/*
 * Create: Mon Mar 03 17:14:34 2025
 */
#include <stdio.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>


#define PROG_INFO_MAX 100

struct prog_info {
	char prog_name[128];
	__u64 last_run_time_ns;
	__u32 last_run_cnt;
};

static struct env {
	int interval; /* sample interval unit of s */
	struct prog_info prog_infos[PROG_INFO_MAX];
	int prog_info_id;
} env = {
	.interval = 5,
	.prog_infos = {0},
	.prog_info_id = 0,
};

static int get_prog_info()
{
	int ret, fd;
	float delta;
	__u32 cnt, id = 0;
	struct bpf_prog_info info = {0};
	__u32 info_size = sizeof(info);
	bool recored;
	struct tm *timeinfo;
	time_t rawtime;
	char buffer[64];

	time(&rawtime);
	timeinfo = localtime(&rawtime);

	strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", timeinfo);

	while (true) {
		ret = bpf_prog_get_next_id(id, &id);
		if (ret) {
			if (errno == ENOENT) {
				ret = 0;
				break;
			}
		}

		fd = bpf_prog_get_fd_by_id(id);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			fprintf(stderr, "prog get fd failed:%s\n", strerror(errno));

			return fd;
		}

		memset(&info, 0, info_size);
		ret = bpf_obj_get_info_by_fd(fd, &info, &info_size);
		if (ret < 0) {
			fprintf(stderr, "bpf get info failed, ret:%d, %s\n", ret, strerror(errno));
			close(fd);
			return ret;
		}

		recored = false;

		if (info.name[0]) {
			if (env.prog_info_id >= PROG_INFO_MAX) {
				fprintf(stderr, "too many prog infos\n");
				return -EINVAL;
			}

			if (info.run_time_ns == 0)
				continue;

			for (int i = 0; i < env.prog_info_id; i++) {
				if (strcmp(env.prog_infos[i].prog_name, info.name) == 0) {

					delta = info.run_time_ns - env.prog_infos[i].last_run_time_ns;
					cnt = info.run_cnt - env.prog_infos[i].last_run_cnt;
					printf("PROG:%s, AVG_DUR:%f, COUNT:%llu, INTRVAL:%d, TIME:%s\n",
	    					info.name, delta / cnt, cnt, env.interval, buffer);

					env.prog_infos[i].last_run_time_ns = info.run_time_ns;
					env.prog_infos[i].last_run_cnt = info.run_cnt;
					recored = true;

					break;
				}
			}

			if (!recored) {
				strncpy(env.prog_infos[env.prog_info_id].prog_name, info.name, sizeof(info.name));
				env.prog_infos[env.prog_info_id].last_run_time_ns = info.run_time_ns;
				env.prog_infos[env.prog_info_id].last_run_cnt = info.run_cnt;
				env.prog_info_id++;
			}
		}

		close(fd);
	}

	return ret;
}

int main(void)
{
	int ret;

	memset(&env.prog_infos, 0, sizeof(env.prog_infos));

	ret = bpf_enable_stats(0);
	if (ret < 0) {
		fprintf(stderr, "enable stats failed:%s\n", strerror(errno));
	}

	while (true) {
		ret = get_prog_info();
		if (ret < 0)
			return ret;

		sleep(env.interval);
	}
	return 0;
}
