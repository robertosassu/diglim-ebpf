/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common definitions.
 */

#ifndef __VMLINUX_H__
#include <limits.h>
#include <linux/types.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#endif

enum lsm_modes { MODE_ENFORCING, MODE_PERMISSIVE };

/* Compact list definitions */
#define MAX_NUM_BLOCKS	10

enum compact_types { COMPACT_PARSER, COMPACT_FILE, COMPACT_METADATA,
		     COMPACT_DIGEST_LIST, COMPACT__LAST };

enum compact_modifiers { COMPACT_MOD_IMMUTABLE, COMPACT_MOD__LAST };

struct compact_list_hdr {
	__u8 version;
	__u8 _reserved;
	__le16 type;
	__le16 modifiers;
	__le16 algo;
	__le32 count;
	__le32 datalen;
} __attribute((packed));

enum ops { DIGEST_LIST_ADD, DIGEST_LIST_DEL, DIGEST_LIST_OP__LAST };

struct data {
	u8 op;
	size_t size;
	u8 val[2 * 1024 * 1024];
};

#define UNKNOWN_DIGEST_ERR_STR "unknown digest"
#define CALC_DIGEST_ERR_STR "cannot calculate the digest"
#define MMAP_WRITERS_ERR_STR "mmap() with writers"
#define MPROTECT_ERR_STR "mprotect() with exec perm"
#define WRITE_MMAPPED_EXEC_STR "attempt to write a file mmapped for execution"
#define IMA_NOT_READY_STR "IMA not yet ready"

#define MAX_DIGEST_SIZE	64
#define TASK_COMM_LEN 16

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

enum errors { UNKNOWN_DIGEST_ERR, CALC_DIGEST_ERR, MMAP_WRITERS_ERR,
	      MPROTECT_ERR, WRITE_MMAPPED_EXEC_ERR, IMA_NOT_READY_ERR,
	      LAST__ERR };

struct log_entry {
	enum errors error;
	u8 digest[1 + MAX_DIGEST_SIZE];
	char filename[NAME_MAX + 1];
	unsigned long magic;
	char task_name[TASK_COMM_LEN + 1];
	u32 task_pid;
};

#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define RMD160_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SHA224_DIGEST_SIZE 28
#define RMD128_DIGEST_SIZE 16
#define RMD256_DIGEST_SIZE 32
#define RMD320_DIGEST_SIZE 40
#define WP256_DIGEST_SIZE 32
#define WP384_DIGEST_SIZE 48
#define WP512_DIGEST_SIZE 64
#define TGR128_DIGEST_SIZE 16
#define TGR160_DIGEST_SIZE 20
#define TGR192_DIGEST_SIZE 24
#define SM3256_DIGEST_SIZE 32
#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64

#define SYSFS_PATH "/sys/"
#define BPFFS_PATH SYSFS_PATH "fs/bpf/"
#define SECURITYFS_PATH SYSFS_PATH "kernel/security/"
#define BPFFS_DIGLIM_PATH BPFFS_PATH "diglim/"
#define DIGEST_LISTS_DEFAULT_PATH "/etc/digest_lists/"
#define DIGEST_LIST_LOADER_PATH "/usr/bin/diglim_user_loader"
#define LOADER_DIGEST_LIST_PATH DIGEST_LISTS_DEFAULT_PATH \
				"/0-file_list-map-diglim_user_loader"
