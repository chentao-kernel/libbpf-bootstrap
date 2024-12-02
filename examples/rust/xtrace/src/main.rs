use std::mem::MaybeUninit;
use std::str;
use std::time::Duration;
use std::process;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use std::mem;
use anyhow::bail;
use anyhow::Result;
use anyhow::Context as _;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::MapCore as _;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::PerfBufferBuilder;
use libbpf_rs::MapFlags;
use plain::Plain;
use time::OffsetDateTime;
use std::collections::HashMap;

unsafe impl Plain for net_skel::types::conn_data_event_t {}
unsafe impl Plain for net_skel::types::attr_t {}
unsafe impl Plain for net_skel::types::conn_stats_event_t {}
unsafe impl Plain for net_skel::types::conn_ctrl_event_t {}
unsafe impl Plain for net_skel::types::connect_id_t {}

use net_skel::types::*;

mod net_skel {
    include!(concat!(
        env!("OUT_DIR"),
        "/net.skel.rs"
    ));
}

use net_skel::*;
mod proto;
use proto::ProtoParser;

const NumProto: usize = 10;

impl Hash for connect_id_t {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.tgid.hash(state);
        self.fd.hash(state);
        self.start.hash(state);
    }
}
impl PartialEq for connect_id_t {
    fn eq(&self, others: &Self) -> bool {
        self.tgid == others.tgid && self.fd == others.fd && self.start == others.start
    }
}
impl Eq for connect_id_t {}

impl sockaddr_t {
    pub fn get_ip(&self) -> IpAddr {
        unsafe {
            let family = (*self).sa.sa_family;
            match family {
                2 => { // AF_INET
                    let ipv4 = (*self).in4.sin_addr;
                    IpAddr::V4(Ipv4Addr::from(ipv4.s_addr.to_be()))
                },
                10 => { // AF_INET6
                    let ipv6 = (*self).in6.sin6_addr;
                    IpAddr::V6(Ipv6Addr::from(ipv6.in6_u.u6_addr8))
                },
                _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            }
        }
    }
    pub fn get_port(&self) -> u16 {
        unsafe {
            let family = (*self).sa.sa_family;
            match family {
                2 => { // AF_INET
                    (*self).in4.sin_port
                },
                10 => { // AF_INET6
                    (*self).in6.sin6_port
                },
                _ => 0,
            }
        }
    }
}

// cache send/recvfrom data for a whole request and reponse packet
#[derive(Debug, Clone)]
pub struct ConnFlow {
    pub ingress_queue :Vec<conn_data_event_t>,
    pub ingress_package_size :u32,
    pub egress_queue :Vec<conn_data_event_t>,
    pub egress_package_size :u32,
    pub proto: support_proto_e,
}

impl ConnFlow {
    fn new() -> Self {
        ConnFlow {
            ingress_queue: Vec::new(),
            egress_queue: Vec::new(),
            ingress_package_size: 0,
            egress_package_size: 0,
            proto: support_proto_e::ProtoUnknown,
        }
    }

    pub fn enqueue_ingress(&mut self, item: &conn_data_event_t) {
        self.ingress_queue.push(item.clone());
    }

    fn enqueue_egress(&mut self, item: &conn_data_event_t) {
        self.egress_queue.push(item.clone());
    }

    fn ingress_queue_size(&mut self) -> usize {
        self.ingress_queue.len()
    }

    fn egress_queue_size(&mut self) -> usize {
        self.egress_queue.len()
    }

    fn is_new_conn(&mut self, item: &conn_data_event_t) -> bool {
        let role = unsafe { item.attr.role.assume_init() };
        let dir = unsafe { item.attr.direction.assume_init() };
        if role == support_role_e::IsClient {
            if dir == support_direction_e::DirEgress {
                if self.ingress_queue_size() != 0 {
                    return true;
                }
            }
        }
        if role == support_role_e::IsServer {
            if dir == support_direction_e::DirIngress {
                if self.egress_queue_size() != 0 {
                    return true;
                }
            }
        }
        return false;
    }
}

pub struct ConnectionManager {
    pub connects_ctrl: HashMap<connect_id_t, conn_ctrl_event_t>,
    pub connects_data: HashMap<connect_id_t, ConnFlow>,
    pub connects_stat: HashMap<connect_id_t, conn_stats_event_t>,
    pub parser: ProtoParser,
}

impl ConnectionManager {
    fn new() -> Self {
        ConnectionManager {
            connects_ctrl: HashMap::new(),
            connects_data: HashMap::new(),
            connects_stat: HashMap::new(),
            parser: ProtoParser::new(),
        }
    }

    fn get_conn_flow(&mut self, id: &connect_id_t) -> Option<&ConnFlow> {
        self.connects_data.get(id)
    }

    fn del_conn_flow(&mut self, id: &connect_id_t) {
        self.connects_data.remove(id);
    }

    fn add_conn_flow(&mut self, id: &connect_id_t, data: &conn_data_event_t) {
        let flow = self.connects_data.entry(id.clone()).or_insert_with(|| ConnFlow {
            ingress_queue: Vec::new(),
            ingress_package_size :0,
            egress_queue: Vec::new(),
            egress_package_size :0,
            // init proto type
            proto :unsafe { data.attr.protocol.assume_init() },
        });

        let direction = unsafe { data.attr.direction.assume_init() };
        match direction {
            support_direction_e::DirEgress => {
                flow.egress_queue.push(data.clone());
                flow.egress_package_size += data.attr.org_msg_size;
            }
            support_direction_e::DirIngress => {
                flow.ingress_queue.push(data.clone());
                flow.ingress_package_size += data.attr.org_msg_size;
            }
            support_direction_e::DirUnknown => {
                println!{"dirunknown, package info:{:?}", data};
            }
        }
    }
}

/// Trace net syscall and latency
#[derive(Debug, Parser)]
struct Command {
    /// Trace latency higher than this value(ms)
    #[arg(default_value = "1000")]
    latency: u64,
    /// Process PID to trace
    #[arg(default_value = "-1")]
    pid: i32,
    /// Thread TID to trace
    #[arg(default_value = "0")]
    tid: i64,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

//unsafe impl Plain for net::types::event {}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

fn connect_ctrl_handle_event(_cpu: i32, data: &[u8]) {
    let mut data_ = net_skel::types::conn_ctrl_event_t::default();
    plain::copy_from_bytes(&mut data_, data).expect("data event buf was too short");
    println!("conn_ctrl || ts:{}, type:{:?}, {:?}, {:?}, {:?}",
            data_.ts,
            unsafe { data_.r#type.assume_init() },
            data_.conn_id,
            data_.connect,
            data_.close,
            );
}

fn connect_data_handle_event(_cpu: i32, data: &[u8]) {
    let mut conn_data = net_skel::types::conn_data_event_t::default();
    let mut data_ = net_skel::types::attr_t::default();
    plain::copy_from_bytes(&mut data_, data).expect("data event buf was too short");
    conn_data.attr = data_;

    let event = unsafe { &*(data.as_ptr() as *const conn_data_event_t) };
    let raw_comm: String = match String::from_utf8(event.attr.comm.iter().map(|&c| c as u8).collect()) {
        Ok(parsed_comm) => parsed_comm,
        Err(e) => {
            eprintln!("Failed to parse comm: {}", e);
            String::from("unknown")
        }
    };
    let comm: String = raw_comm.chars().filter(|&c| c != '\0').collect();
    println!("conn_data || conn_id:{:?}, proto:{:?}, role:{:?}, type:{:?}, dir:{:?}, syscall:{:?}, comm:{:?}, length_header:{:?}, addr:{:?}, port:{:?}",
            conn_data.attr.conn_id,
            unsafe { conn_data.attr.protocol.assume_init() },
            unsafe { conn_data.attr.role.assume_init() },
            unsafe { conn_data.attr._type.assume_init() },
            unsafe { conn_data.attr.direction.assume_init() },
            unsafe { conn_data.attr.syscall_func.assume_init() },
            comm,
            conn_data.attr.length_header,
            conn_data.attr.addr.get_ip(),
            conn_data.attr.addr.get_port(),
            );

    match String::from_utf8(event.msg.iter().map(|&c| c as u8).collect()) {
        Ok(msg) => println!("Message: {}", msg),
        Err(e) => eprintln!("Failed to decode msg as UTF-8 string,comm:{:?}", comm)
    }
}

fn connect_stats_handle_event(_cpu: i32, data: &[u8]) {
    let mut data_ = net_skel::types::conn_stats_event_t::default();
    plain::copy_from_bytes(&mut data_, data).expect("data event buf was too short");
    println!("conn_stats || {:?}", data_);
}

fn handle_lost_events(cpu: i32, count: u64) {
    eprintln!("Lost {count} events on CPU {cpu}");
}

fn main() -> Result<()> {
    let opts = Command::parse();
    let mut skel_builder = NetSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }
    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    // open
    let open_skel = skel_builder.open(&mut open_object)?;

    // load
    let mut skel = open_skel.load()?;
    // update config map
    let key :u32 = 0;
    let config = net_skel::types::config_info_t {
        port: 0,
        self_pid: process::id() as i32,
        data_sample: 100,
        threhold_ms: 10000,
        pid: opts.pid,
        proto : [1; NumProto],
    };
    let val = unsafe {plain::as_bytes(&config)};
    skel.maps.config_info_map
        .update(&key.to_ne_bytes(), &val, MapFlags::ANY)
        .context("update config info map fail")?;
    // attach
    skel.attach()?;

    let connect_ctrl_perf = PerfBufferBuilder::new(&skel.maps.connect_ctrl_events_map)
        .sample_cb(connect_ctrl_handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    let connect_data_perf = PerfBufferBuilder::new(&skel.maps.connect_data_events_map)
        .sample_cb(connect_data_handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    let connect_stats_perf = PerfBufferBuilder::new(&skel.maps.connect_stats_events_map)
        .sample_cb(connect_stats_handle_event)
        .lost_cb(handle_lost_events)
        .build()?;
    // poll data
    loop {
        connect_ctrl_perf.poll(Duration::from_millis(100))?;
        connect_data_perf.poll(Duration::from_millis(100))?;
        connect_stats_perf.poll(Duration::from_millis(100))?;
    }
}
