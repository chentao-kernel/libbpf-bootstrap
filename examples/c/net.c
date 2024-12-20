#include "netapi.h"
#include "net.h"
#include "net.skel.h"
//#include "trace_helpers.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <string.h>
#include <sys/resource.h>

#define FILE_PATH_SIZE 256

typedef void (*handle_event_func_t)(void *ctx, int cpu, void *data,
		__u32 data_sz);
typedef void (*handle_lost_func_t)(void *ctx, int cpu, __u64 lost_cnt);
typedef void (*callback_func_t)(void *custom_data, void *event);

static int cleanup_dog_init(char *so, int32_t so_size, long uprobe_offset);

int g_poll_callback_count = 0;

struct callback_t {
	callback_func_t func;
	void *custom_data;
};

struct lost_callback_t {
	net_lost_func_t func;
	void *custom_data;
};

struct map_syscall_t net_mapsys[25] = {
  {0, "NULL"},
  {1, "sys_enter_connect"},
  {2, "sys_exit_connect"},
  {3, "sys_enter_accept"},
  {4, "sys_exit_accept"},
  {5, "sys_accept4"},
  {6, "sys_exit_accept4"},
  {7, "sys_enter_close"},
  {8, "sys_exit_close"},
  {9, "sys_enter_mmap"},
  {10, "sock_alloc"},
  {11, "security_socket_sendmsg"},
  {12, "security_socket_recvmsg"},
  {13, "sys_enter_write"},
  {14, "sys_exit_write"},
  {15, "sys_enter_read"},
  {16, "sys_exit_read"},
  {17, "sys_enter_sendto"},
  {18, "sys_exit_sendto"},
  {19, "sys_enter_recvfrom"},
  {20, "sys_exit_recvfrom"},
  {21, "sys_enter_sendmsg"},
  {22, "sys_exit_sendmsg"},
  {23, "sys_enter_recvmsg"},
  {24, "sys_exit_recvmsg"},
};

struct mproto_t net_mproto[MAX_PROTOCOL_NUM] = {
    {0, "dns"},
    {1, "http"},
    {2, "redis"},
    {3, "kafka"},
    {4, "mysql"},
};

static struct net_env_t {
	bool debug;
	char btf_custom_path[FILE_PATH_SIZE];
	int64_t tgid;
	uint32_t protocol;
	uint64_t enable;
	struct config_info_t config;
	struct net_bpf *obj;
	struct perf_buffer * pbs[MAX_HAND];
	struct callback_t callback[MAX_HAND];
	int32_t page_count[MAX_HAND];
	struct lost_callback_t lost_callback;
	net_print_fn_t libbpf_print;
	char version[64];
} env = {
	.debug = false,
	.btf_custom_path = {0},
	.tgid = -1,
	.protocol = -1,
	.enable = 1,
	.config = {
		.port = -1,
		.self_pid = -1,
		.data_sample = DATA_SAMPLE_ALL,
	},
	.obj = NULL,
	.pbs = {},
	.callback = {},
	.page_count = {0},
	.lost_callback = {
		.func = NULL,
		.custom_data = NULL,
	},
	.version = "net v0.1"
};

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur = RLIM_INFINITY,
		.rlim_max = RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int bpf_net_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    int16_t int_level=(int16_t) level;
    env.libbpf_print(int_level,format,args);
}

static void net_log(enum libbpf_print_level level,
		const char *format, ...)
{
	va_list args;

	va_start(args, format);
	(void)bpf_net_print_fn(level, format, args);
	va_end(args);
}

#ifdef NET_TEST
void ebpf_setup_net_test_process_func(net_test_process_func_t func, void * custom_data)
{
	printf("setup test_process:%p\n", func);
	env.callback[TEST_HAND].func = func;
	env.callback[TEST_HAND].custom_data = custom_data;
}
#endif

void ebpf_setup_net_data_process_func(net_data_process_func_t func, void * custom_data)
{
	env.callback[DATA_HAND].func = func;
	env.callback[DATA_HAND].custom_data = custom_data;
}

void ebpf_setup_net_event_process_func(net_ctrl_process_func_t func, void * custom_data)
{
	env.callback[CTRL_HAND].func = func;
	env.callback[CTRL_HAND].custom_data = custom_data;
}

void ebpf_setup_net_statistics_process_func(net_statistics_process_func_t func,
		void * custom_data)
{
	env.callback[STAT_HAND].func = func;
	env.callback[STAT_HAND].custom_data = custom_data;
}

void ebpf_setup_net_lost_func(net_lost_func_t func, void * custom_data)
{
	env.lost_callback.func = func;
	env.lost_callback.custom_data = custom_data;
}

void ebpf_setup_print_func(net_print_fn_t func)
{
	env.libbpf_print = func;
}



#ifdef NET_TEST
static void handle_test_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	++g_poll_callback_count;
	struct test_data *info = (struct test_data*)data;
	void *custom_data = env.callback[TEST_HAND].custom_data;
	env.callback[TEST_HAND].func(custom_data, info);
}

static void handle_lost_test_events(void *ctx, int cpu, __u64 lost_cnt)
{
	++g_poll_callback_count;
	if (env.lost_callback.func == NULL) {
		net_log(0, "Lost %llu test events on CPU #%d!\n", lost_cnt, cpu);
	} else {
		env.lost_callback.func(env.lost_callback.custom_data, TEST_HAND, lost_cnt);
	}
}
#endif

static void handle_ctrl_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	++g_poll_callback_count;
	struct conn_ctrl_event_t *info = (struct conn_ctrl_event_t*)data;
	void *custom_data = env.callback[CTRL_HAND].custom_data;
	env.callback[CTRL_HAND].func(custom_data, info);
}

static void handle_lost_ctrl_event(void *ctx, int cpu, __u64 lost_cnt)
{
	++g_poll_callback_count;
	if (env.lost_callback.func == NULL) {
		net_log(0, "Lost %llu ctrl events on CPU #%d!\n", lost_cnt, cpu);
	} else {
		env.lost_callback.func(env.lost_callback.custom_data, CTRL_HAND, lost_cnt);
	}
}

static void handle_data_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	++g_poll_callback_count;
	struct conn_data_event_t *info = (struct conn_data_event_t*)data;
	void *custom_data = env.callback[DATA_HAND].custom_data;
	env.callback[DATA_HAND].func(custom_data, info);
}

static void handle_lost_data_event(void *ctx, int cpu, __u64 lost_cnt)
{
	++g_poll_callback_count;
	if (env.lost_callback.func == NULL) {
		net_log(0, "Lost %llu data events on CPU #%d!\n", lost_cnt, cpu);
	} else {
		env.lost_callback.func(env.lost_callback.custom_data, DATA_HAND, lost_cnt);
	}
}

static void handle_stat_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	++g_poll_callback_count;
	struct connect_info_t *info = (struct connect_info_t*)data;
	void *custom_data = env.callback[STAT_HAND].custom_data;
	env.callback[STAT_HAND].func(custom_data, info);
}

static void handle_lost_stat_event(void *ctx, int cpu, __u64 lost_cnt)
{
	++g_poll_callback_count;
	if (env.lost_callback.func == NULL) {
		net_log(0, "Lost %llu stat events on CPU #%d!\n", lost_cnt, cpu);
	} else {
		env.lost_callback.func(env.lost_callback.custom_data, STAT_HAND, lost_cnt);
	}
}

static int user_config_tgid(int config_fd)
{
	int ret;
	uint32_t index = TgidIndex;
	ret = bpf_map_update_elem(config_fd, &index, &env.tgid, BPF_ANY);
	if (ret)
		printf("Could not update map for tgid %ld: %s\n", env.tgid, strerror(-ret));
	else
		printf("success to update map for tgid: %ld\n", env.tgid);

	return ret;
}

static int user_config_proto(int config_fd)
{
	int ret;
	uint32_t protocol;
	uint64_t enable = 1;

	if (env.protocol == -1) {
		for (protocol = ProtoHTTP; protocol < NumProto; protocol++) {
			ret = bpf_map_update_elem(config_fd, &protocol, &enable, BPF_ANY);
			if (ret)
				printf("Could not update map for protocol %d, err: %s", env.protocol, strerror(-ret));
			else
				printf("success to update map for protocol: %d\n", env.protocol);
		}
	} else {
		ret = bpf_map_update_elem(config_fd, &env.protocol, &enable, BPF_ANY);
		if (ret)
			printf("Could not update map for protocol %d, err: %s", env.protocol, strerror(-ret));
		else
			printf("success to update map for protocol: %d\n", env.protocol);
	}

	return ret;
}

static int user_config_info(int config_fd)
{
	int ret;
	uint32_t key = 0;

	ret = bpf_map_update_elem(config_fd, &key, &env.config, BPF_ANY);
	if (ret)
		printf("Could not update map for config_info, err: %s", strerror(-ret));
	else
		printf("success to update map for config_info: %d\n", env.protocol);

	return ret;
}

static void get_btf_path(void)
{
	FILE *fp = NULL;
	char version[64] = {};

	fp = popen("uname -r", "r");
	if (!fp) {
		net_log(0, "get kernel version failed, error:%s\n", strerror(errno));
		return;
	}
	fgets(version, sizeof(version), fp);

	//snprintf(env.btf_custom_path, sizeof(env.btf_custom_path), "/usr/lib/vmlinux-%s", version);
	snprintf(env.btf_custom_path, sizeof(env.btf_custom_path), "/boot/vmlinux-%s", version);
	env.btf_custom_path[strlen(env.btf_custom_path) - 1] = '\0';
	//printf("btf_path:%s\n", env.btf_custom_path);
	pclose(fp);
}

void proto_map_init(int fd)
{
	uint64_t enable = 0;
	int i;

	for (i = ProtoHTTP; i < NumProto; i++) {
		bpf_map_update_elem(fd, &i, &enable, BPF_ANY);
	}
}

int32_t ebpf_init(char *btf, int32_t btf_size, char *so, int32_t so_size, long uprobe_offset)
{
	struct net_bpf *obj = NULL;
	int err;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts);

	if (btf == NULL || btf_size == 0 || btf_size > FILE_PATH_SIZE) {
		get_btf_path();
	} else {
		strcpy(env.btf_custom_path, btf);
	}

	if (so == NULL || so_size == 0) {
		return -EINVAL;
	}

	bump_memlock_rlimit();
	libbpf_set_print(bpf_net_print_fn);

	//open_opts.btf_custom_path = env.btf_custom_path;
	open_opts.btf_custom_path = NULL;
	obj = net_bpf__open_opts(&open_opts);
	if (!obj) {
		net_log(0, "failed to open BPF object\n");
		return 1;
	}
	err = net_bpf__load(obj);
	if (err) {
		net_log(0, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	err = net_bpf__attach(obj);
	if (err) {
		net_log(0, "failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}
	env.obj = obj;

	err = cleanup_dog_init(so, so_size, uprobe_offset);
	if (err) {
		net_log(0, "cleanup dog init failed: %s\n", strerror(-err));
		goto cleanup;
	}
	proto_map_init(bpf_map__fd(obj->maps.config_protocol_map));
	return 0;

cleanup:
	net_bpf__destroy(obj);
	return err;
}

static int set_events_cont(int perf_fd, int page_count, handle_event_func_t event_func, handle_lost_func_t lost_func, struct perf_buffer **pbuf)
{
	if (page_count <= 0) {
		page_count = 128;
	}
	struct perf_buffer *pb = NULL;
	int err;

	pb = perf_buffer__new(perf_fd, page_count, event_func, lost_func, NULL, NULL);
	err = libbpf_get_error(pb);
	if (err)
	{
		net_log(0, "failed to open perf buffer: %d\n", err);
		perf_buffer__free(pb);
		return err;
	}
	*pbuf = pb;

	net_log(0, "open perf buffer success, page count: %d\n", page_count);

	return 0;
}

int32_t ebpf_start(void)
{
	struct net_bpf *obj = env.obj;
	int err;
#ifdef NET_TEST
	err = set_events_cont(bpf_map__fd(obj->maps.test_map), env.page_count[TEST_HAND],
			handle_test_event, handle_lost_test_event, &(env.pbs[TEST_HAND]));
	if (err)
		return err;
#endif
	err = set_events_cont(bpf_map__fd(obj->maps.connect_ctrl_events_map), env.page_count[CTRL_HAND],
			handle_ctrl_event, handle_lost_ctrl_event, &(env.pbs[CTRL_HAND]));
	if (err)
		return err;
	err = set_events_cont(bpf_map__fd(obj->maps.connect_data_events_map), env.page_count[DATA_HAND],
			handle_data_event, handle_lost_data_event, &(env.pbs[DATA_HAND]));
	if (err)
		return err;
	err = set_events_cont(bpf_map__fd(obj->maps.connect_stats_events_map), env.page_count[STAT_HAND],
			handle_stat_event, handle_lost_stat_event, &(env.pbs[STAT_HAND]));
	if (err)
		return err;

	return 0;
}

void ebpf_config(int32_t opt1, int32_t opt2, int32_t params_count,
		void ** params, int32_t * params_len)
{
	struct net_bpf *obj = env.obj;
	int32_t *value;

	if (params_len == NULL || params == NULL) {
		net_log(3, "ebpf config failed\n");
		user_config_tgid(bpf_map__fd(obj->maps.config_tgid_map));
		user_config_proto(bpf_map__fd(obj->maps.config_protocol_map));
		user_config_info(bpf_map__fd(obj->maps.config_info_map));
		return;
	}

	switch (opt1) {
		case PROTOCOL_FILTER:
			value = (int32_t *)(params[0]);
			if (value && *value >= -1 && *value < NumProto) {
				env.protocol = *value;
			} else {
				env.protocol = -1;
			}
			user_config_proto(bpf_map__fd(obj->maps.config_protocol_map));
			break;
		case TGID_FILTER:
			value = (int32_t *)(params[0]);
			if (value && *value >= -1) {
				env.tgid = *value;
			}
			user_config_tgid(bpf_map__fd(obj->maps.config_tgid_map));
			break;
		case PORT_FILTER:
			value = (int32_t *)(params[0]);
			if (value && *value >= -1) {
				env.config.port = *value;
			}
			user_config_info(bpf_map__fd(obj->maps.config_info_map));
			break;
		case SELF_FILTER:
			value = (int32_t *)(params[0]);
			if (value && *value >= -1) {
				env.config.self_pid = *value;
			}
			user_config_info(bpf_map__fd(obj->maps.config_info_map));
			break;
		case DATA_SAMPLING:
			value = (int32_t *)(params[0]);
			if (value && *value >= -1 && *value <= DATA_SAMPLE_ALL) {
				env.config.data_sample = *value;
			}
			user_config_info(bpf_map__fd(obj->maps.config_info_map));
			break;
		case PERF_BUFFER_PAGE:
			value = (int32_t *)(params[0]);
			env.page_count[opt2] = *value;
			break;
		defaults:
			user_config_proto(bpf_map__fd(obj->maps.config_protocol_map));
			user_config_tgid(bpf_map__fd(obj->maps.config_tgid_map));
			user_config_info(bpf_map__fd(obj->maps.config_info_map));
			break;
	}
}

int32_t ebpf_poll_events(int32_t max_events, int32_t * stop_flag)
{
	int j;
	/* 100 times one by one ?*/
	g_poll_callback_count = 0;
	for (j = 0; j < MAX_HAND; j++) {
		if (g_poll_callback_count < max_events && !*stop_flag) {
		   int rst = perf_buffer__poll(env.pbs[j], 500);
		   if (rst < 0 && errno != EINTR) {
				net_log(0, "Error polling perf buffer: %d, hand_type:%d\n",
					rst, j);
				return rst;
		   }
		}
	}
	if (*stop_flag) {
		return -100;
	}
	return g_poll_callback_count;
}

int32_t ebpf_stop(void)
{
	int i;
	struct perf_buffer *pb = NULL;

	for (i = 0; i < MAX_HAND; i++) {
		pb = env.pbs[i];
		if (pb) {
			perf_buffer__free(pb);
		}
	}
	if (env.obj) {
		net_bpf__destroy(env.obj);
	}

	return 0;
}

int32_t ebpf_get_fd(void)
{
	return bpf_map__fd(env.obj->maps.connect_info_map);
}

int32_t ebpf_get_proto_fd(int proto)
{
	switch (proto)
	{
	case ProtoHTTP:
		/* code */
		return bpf_map__fd(env.obj->maps.http_map);
	case ProtoDNS:
		return bpf_map__fd(env.obj->maps.dns_map);
	case ProtoMySQL:
		return bpf_map__fd(env.obj->maps.mysql_map);
	case ProtoRedis:
		return bpf_map__fd(env.obj->maps.redis_map);
	default:
		break;
	}
	return 0;
}

int32_t ebpf_get_next_key(int fd, const void *key, void *next_key)
{
	return bpf_map_get_next_key(fd, key, next_key);
}

int32_t ebpf_get_map_value(int fd, const void *key, void *value)
{
	return bpf_map_lookup_elem(fd, key, value);
}

void ebpf_cleanup_dog(void *key, int32_t size)
{
}

static int cleanup_dog_init(char *so, int32_t so_size, long uprobe_offset)
{
	struct net_bpf *obj = env.obj;
	int ret;

	obj->links.cleanup_dog_probe = bpf_program__attach_uprobe(obj->progs.cleanup_dog_probe, false,
			0, so, uprobe_offset); //0 for self
	ret = libbpf_get_error(obj->links.cleanup_dog_probe);
	if (ret != 0) {
		net_log(1, "uprobe attach failed\n");
		return ret;
	}
	return 0;
}

void ebpf_delete_map_value(void *key, int32_t size)
{

	if (key == NULL || size == 0) {
		return;
	}

	ebpf_cleanup_dog(key, size);
}


int main(void)
{
	return 0;
}
