/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Log definitions.
 */

#define UNKNOWN_DIGEST_ERR_STR "unknown digest"
#define CALC_DIGEST_ERR_STR "cannot calculate the digest"
#define MMAP_WRITERS_ERR_STR "mmap() with writers"
#define MPROTECT_ERR_STR "mprotect() with exec perm"
#define WRITE_MMAPPED_EXEC_STR "attempt to write a file mmapped for execution"

#define MAX_DIGEST_SIZE	64
#define TASK_COMM_LEN 16

enum errors { UNKNOWN_DIGEST_ERR, CALC_DIGEST_ERR, MMAP_WRITERS_ERR,
	      MPROTECT_ERR, WRITE_MMAPPED_EXEC, LAST__ERR };

struct log_entry {
	enum errors error;
	u8 digest[1 + MAX_DIGEST_SIZE];
	char filename[NAME_MAX + 1];
	unsigned long magic;
	char task_name[TASK_COMM_LEN + 1];
	u32 task_pid;
};
