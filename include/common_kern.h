/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common kernel space definitions.
 */

#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common.h"

#ifdef __BIG_ENDIAN__
#define le16_to_cpu(x) ___bpf_swab16(x)
#define le32_to_cpu(x) ___bpf_swab32(x)
#define be16_to_cpu(x) (x)
#define be32_to_cpu(x) (x)
#else
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define be16_to_cpu(x) ___bpf_swab16(x)
#define be32_to_cpu(x) ___bpf_swab32(x)
#endif

#define MAX_DIGEST_SIZE	64

#define MAX_DIGESTS	1000000

/* From include/linux/mm.h. */
#define VM_EXEC	0x00000004

/* From include/linux/mm.h. */
#define FMODE_WRITE	0x2

/* From include/uapi/asm-generic/fcntl.h. */
#define __O_TMPFILE	020000000
#define O_EXCL		00000200

/* From include/linux/fs.h. */
#define SB_KERNMOUNT	(1<<22) /* this is a kern_mount call */

/* From include/uapi/linux/magic.h. */
#define TMPFS_MAGIC	0x01021994

/* From include/uapi/linux/stat.h. */
#define S_IXUSR 00100
#define S_IXGRP 00010
#define S_IXOTH 00001
#define S_IXUGO            (S_IXUSR|S_IXGRP|S_IXOTH)

#define S_IWUSR 00200
#define S_IWGRP 00020
#define S_IWOTH 00002
#define S_IWUGO            (S_IWUSR|S_IWGRP|S_IWOTH)

#define LIB_FIRMWARE_PATH "/lib/firmware"
#define USR_LIB_FIRMWARE_PATH "/usr/lib/firmware"
#define LIB_MODULES_PATH "/lib/module"
#define USR_LIB_MODULES_PATH "/usr/lib/modules"
#define USR_LIB64_PATH "/usr/lib64"

/* Inode state flags. */
#define INODE_STATE_CHECKED		0x01
#define INODE_STATE_MMAP_EXEC_ALLOWED	0x02
#define INODE_STATE_MMAP_EXEC_DONE	0x04
#define INODE_STATE_OPENED_WRITTEN	0x08

struct digest_info {
	u16 type;
	u16 modifiers;
	u32 count;
};

typedef struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DIGESTS);
	__uint(key_size, 1 + MAX_DIGEST_SIZE);
	__uint(value_size, sizeof(struct digest_info));
} digest_items_t;

extern digest_items_t digest_items SEC(".maps");

typedef struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct data);
} data_input_t;

extern data_input_t data_input SEC(".maps");

struct inode_storage {
	u8 state;
	struct digest_info *info;
};

typedef struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inode_storage);
} inode_storage_map_t;

typedef struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf_t;

struct _path {
	char val[4096];
};

typedef struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1000);
	__type(key, __u32);
	__type(value, struct _path);
} dirnames_map_t;

extern dirnames_map_t dirnames_map SEC(".maps");

extern const int hash_digest_size[HASH_ALGO__LAST];

static inline int update_digest_items(u8 *digest, u16 type, u16 modifiers,
				      enum ops op)
{
	struct digest_info *info, new_info = { type, 0, 0 };

	info = bpf_map_lookup_elem(&digest_items, digest);
	if (!info)
		info = &new_info;

	switch (op) {
	case DIGEST_LIST_ADD:
		if (info->count == (u32)(~0UL))
			break;

		if (info->type != type)
			break;

		info->modifiers |= modifiers;
		info->count++;
		bpf_map_update_elem(&digest_items, digest, info, BPF_ANY);
		break;
	case DIGEST_LIST_DEL:
		if (info == &new_info)
			break;

		info->count--;

		if (info->count == 0)
			bpf_map_delete_elem(&digest_items, digest);
		else
			bpf_map_update_elem(&digest_items, digest, info,
					    BPF_ANY);
		break;
	default:
		break;
	}

	return 0;
}
