// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2005,2006,2007,2008 IBM Corporation
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Authors:
 * Roberto Sassu <roberto.sassu@huawei.com>
 * Reiner Sailer <sailer@watson.ibm.com>
 * Serge Hallyn <serue@us.ibm.com>
 * Kylene Hall <kylene@us.ibm.com>
 * Mimi Zohar <zohar@us.ibm.com>
 *
 * Implement the kernel space side of DIGLIM.
 */

#include "vmlinux.h"
#include <errno.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <linux/mman.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "common_kern.h"
#include "log.h"

#define MAX_DIGESTS	1000000

/* From include/linux/mm.h. */
#define VM_EXEC	0x00000004

/* From include/linux/mm.h. */
#define FMODE_WRITE	0x2

/* From include/uapi/asm-generic/fcntl.h. */
#define __O_TMPFILE	020000000

char _license[] SEC("license") = "GPL";
int lsm_mode;

struct inode_storage {
	u8 state;
	u8 attribs;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_DIGESTS);
	__uint(key_size, 1 + MAX_DIGEST_SIZE);
	__uint(value_size, sizeof(u8));
} digest_items SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_INODE_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inode_storage);
} inode_storage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} ringbuf SEC(".maps");

static void log(enum errors error, u8 *digest, struct file *file)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *file_dentry = BPF_CORE_READ(file, f_path.dentry);
	struct log_entry *e;
	int i;

	e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
	if (!e)
		return;

	memset(e, 0, sizeof(*e));

	e->error = error;
	if (digest)
		memcpy(e->digest, digest, sizeof(e->digest));

	bpf_probe_read_str(e->filename, NAME_MAX,
			   BPF_CORE_READ(file_dentry, d_name.name));
	e->magic = file->f_inode->i_sb->s_magic;
	bpf_core_read_str(e->task_name, sizeof(e->task_name), &task->comm);
	e->task_pid = bpf_get_current_pid_tgid() >> 32;
	bpf_ringbuf_submit(e, 0);
}

static int digest_lookup(struct file *file)
{
	u8 digest[1 + MAX_DIGEST_SIZE] = { 0 };
	struct inode_storage *inode_storage;
	u8 *inode_attribs;
	int ret;

	inode_storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode,
					0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (inode_storage && (inode_storage->state & INODE_STATE_CHECKED))
		return 0;

#ifndef HAVE_KERNEL_PATCHES
	ret = bpf_ima_inode_hash(file->f_inode, digest + 1, sizeof(digest) - 1);
#else
	ret = bpf_ima_file_hash(file, digest + 1, sizeof(digest) - 1);
#endif
	if (ret < 0) {
		log(CALC_DIGEST_ERR, NULL, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	digest[0] = ret;

	inode_attribs = bpf_map_lookup_elem(&digest_items, digest);
	if (!inode_attribs) {
		log(UNKNOWN_DIGEST_ERR, digest, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	if (inode_storage) {
		inode_storage->attribs |= *inode_attribs;
		inode_storage->state |= INODE_STATE_CHECKED;
	}

	return 0;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(exec, struct linux_binprm *bprm)
{
	return digest_lookup(bprm->file);
}

SEC("lsm.s/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	if (!file || !(prot & PROT_EXEC))
		return 0;

	/* From mmap_violation_check() in ima_main.c. */
	if (file->f_mapping->i_mmap_writable.counter > 0) {
		log(MMAP_WRITERS_ERR, NULL, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	return digest_lookup(file);
}

SEC("lsm/file_mprotect")
int BPF_PROG(file_mprotect, struct vm_area_struct *vma, unsigned long prot)
{
	/* From ima_file_mprotect() in ima_main.c. */
	if (!vma->vm_file || !(prot & PROT_EXEC) || (vma->vm_flags & VM_EXEC))
		return 0;

	log(MPROTECT_ERR, NULL, vma->vm_file ?: NULL);
	return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file)
{
	struct inode_storage *inode_storage;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	inode_storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode,
					0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!inode_storage)
		return 0;

#ifndef HAVE_KERNEL_PATCHES
	if (file->f_flags & __O_TMPFILE) {
		inode_storage->state |= INODE_STATE_CHECKED;
		return 0;
	}
#endif

	inode_storage->state &= ~INODE_STATE_CHECKED;
	return 0;
}

#ifdef HAVE_KERNEL_PATCHES
SEC("lsm.s/kernel_read_file")
int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id,
	     bool contents)
{
	if (!contents)
		return 0;

	return digest_lookup(file);
}
#endif
