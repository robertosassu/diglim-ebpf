// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * DIGLIM eBPF logging service.
 */

#include <bpf/libbpf.h>
#include <limits.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/signal.h>

#include "common_user.h"

static char *errors_str[LAST__ERR] = {
	[UNKNOWN_DIGEST_ERR] = UNKNOWN_DIGEST_ERR_STR,
	[CALC_DIGEST_ERR] = CALC_DIGEST_ERR_STR,
	[MMAP_WRITERS_ERR] = MMAP_WRITERS_ERR_STR,
	[MPROTECT_ERR] = MPROTECT_ERR_STR,
	[WRITE_MMAPPED_EXEC_ERR] = WRITE_MMAPPED_EXEC_STR,
	[IMA_NOT_READY_ERR] = IMA_NOT_READY_STR,
};

static int stop_loop;

static void stop_server(int sig)
{
	stop_loop = 1;
}

static int process_log(void *ctx, void *data, size_t len)
{
	struct log_entry *e = data;
	char digest_str[512] = { 0 };
	enum hash_algo algo;
	loff_t digest_str_offset = 0;

	switch (e->error) {
	case UNKNOWN_DIGEST_ERR:
		algo = e->digest[0];
		digest_str_offset = snprintf(digest_str, sizeof(digest_str),
					", digest=%s:", hash_algo_name[algo]);

		bin2hex(digest_str + digest_str_offset, e->digest + 1,
			hash_digest_size[algo]);
		break;
	default:
		break;
	}

	syslog(LOG_INFO, "%s[%d]: error=%s%s, filename=%s, sb_magic=0x%lx\n",
	       e->task_name, e->task_pid, errors_str[e->error], digest_str,
	       e->filename, e->magic);
	return 0;
}

int main(int argc, char *argv[])
{
	struct ring_buffer *ringbuf;
	int ret = 0, fd;

	fd = diglim_find_map("ringbuf");
	if (fd < 0) {
		printf("ringbuf map not found, is DIGLIM loaded?\n");
		exit(1);
	}

	ringbuf = ring_buffer__new(fd, process_log, NULL, NULL);
	if (!ringbuf) {
		printf("Cannot use ringbuf map\n");
		exit(1);
	}

	signal(SIGTERM, stop_server);

	while (!stop_loop) {
		ret = ring_buffer__poll(ringbuf, -1);
		if (ret < 0)
			break;
	}

	ring_buffer__free(ringbuf);
	close(fd);
	return ret;
}
