use std::mem::MaybeUninit;
use std::str;
use std::time::Duration;
use std::process;

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

unsafe impl Plain for net_skel::types::conn_data_event_t {}
unsafe impl Plain for net_skel::types::attr_t {}
unsafe impl Plain for net_skel::types::conn_stats_event_t {}
unsafe impl Plain for net_skel::types::conn_ctrl_event_t {}

mod net_skel {
    include!(concat!(
        env!("OUT_DIR"),
        "/net.skel.rs"
    ));
}

use net_skel::*;
mod net;

const NumProto: usize = 10;

/*
#[derive(Debug, Copy, Clone, Default, PartialEq, Eq)]
#[repr(u32)]
pub enum support_event_e {
    #[default]
    EventConnect = 0,
    EventClose = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct close_event_t {
    pub wr_bytes: i64,
    pub rd_bytes: i64
}
impl Default for close_event_t {
    fn default() -> Self {
        Self {
            wr_bytes: i64::default(),
            rd_bytes: i64::default(),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct conn_event_t {
    pub addr: net_skel::types::sockaddr_t,
    pub role: std::mem::MaybeUninit<net_skel::types::support_role_e>
}
impl Default for conn_event_t {
    fn default()  -> Self {
        Self {
            addr: net_skel::types::sockaddr_t::default(),
            role: std::mem::MaybeUninit::new(net_skel::types::support_role_e::default()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct conn_ctrl_event_t {
    pub ts: u64,
    //pub pad: u32,
    pub type_ :std::mem::MaybeUninit<support_event_e>,
    pub conn_id :net_skel::types::connect_id_t,
    pub connect :conn_event_t,
    pub close :close_event_t
}
impl Default for conn_ctrl_event_t {
    fn default() -> Self {
        Self {
            ts: u64::default(),
            //pad: u32::default(),
            type_: std::mem::MaybeUninit::new(support_event_e::default()),
            conn_id: net_skel::types::connect_id_t::default(),
            connect: conn_event_t::default(),
            close: close_event_t::default(),
        }
    }
}
*/

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
            unsafe { data_.type_.assume_init() },
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
    println!("conn_data || conn_id:{:?}, proto:{:?}, role:{:?}, type:{:?}, dir:{:?}, syscall:{:?}",
            conn_data.attr.conn_id,
            unsafe { conn_data.attr.protocol.assume_init() },
            unsafe { conn_data.attr.role.assume_init() },
            unsafe { conn_data.attr._type.assume_init() },
            unsafe { conn_data.attr.direction.assume_init() },
            unsafe { conn_data.attr.syscall_func.assume_init() },
            );
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
