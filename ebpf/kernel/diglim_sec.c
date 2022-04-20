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
 * DIGLIM eBPF security module.
 */

#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <asm-generic/mman-common.h>

#include "common_kern.h"

char _license[] SEC("license") = "GPL";

int lsm_mode;
bool ima_ready = false;

digest_items_t digest_items SEC(".maps");
ringbuf_t ringbuf SEC(".maps");
data_input_t data_input SEC(".maps");
inode_storage_map_t inode_storage_map SEC(".maps");
dirnames_map_t dirnames_map SEC(".maps");

const int hash_digest_size[HASH_ALGO__LAST] = {
	[HASH_ALGO_MD4]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_MD5]		= MD5_DIGEST_SIZE,
	[HASH_ALGO_SHA1]	= SHA1_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_160]	= RMD160_DIGEST_SIZE,
	[HASH_ALGO_SHA256]	= SHA256_DIGEST_SIZE,
	[HASH_ALGO_SHA384]	= SHA384_DIGEST_SIZE,
	[HASH_ALGO_SHA512]	= SHA512_DIGEST_SIZE,
	[HASH_ALGO_SHA224]	= SHA224_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_128]	= RMD128_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_256]	= RMD256_DIGEST_SIZE,
	[HASH_ALGO_RIPE_MD_320]	= RMD320_DIGEST_SIZE,
	[HASH_ALGO_WP_256]	= WP256_DIGEST_SIZE,
	[HASH_ALGO_WP_384]	= WP384_DIGEST_SIZE,
	[HASH_ALGO_WP_512]	= WP512_DIGEST_SIZE,
	[HASH_ALGO_TGR_128]	= TGR128_DIGEST_SIZE,
	[HASH_ALGO_TGR_160]	= TGR160_DIGEST_SIZE,
	[HASH_ALGO_TGR_192]	= TGR192_DIGEST_SIZE,
	[HASH_ALGO_SM3_256]	= SM3256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_256] = STREEBOG256_DIGEST_SIZE,
	[HASH_ALGO_STREEBOG_512] = STREEBOG512_DIGEST_SIZE,
};

static void log(enum errors error, u8 *digest, struct file *file)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	struct dentry *file_dentry = BPF_CORE_READ(file, f_path.dentry);
	struct log_entry *e;

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
	struct digest_info *info;
	int ret;

	if (!ima_ready) {
		log(IMA_NOT_READY_ERR, NULL, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	inode_storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode,
					0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (inode_storage && (inode_storage->state & INODE_STATE_CHECKED))
		return 0;

	ret = -EPERM;

	ret = bpf_ima_file_hash(file, digest + 1, sizeof(digest) - 1);
	if (ret < 0) {
		log(CALC_DIGEST_ERR, NULL, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	digest[0] = ret;

	info = bpf_map_lookup_elem(&digest_items, digest);
	if (!info) {
		log(UNKNOWN_DIGEST_ERR, digest, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	if (inode_storage) {
		inode_storage->info = info;
		inode_storage->state |= INODE_STATE_CHECKED;
	}

	return 0;
}

static bool mmap_exec_allowed(struct file *file)
{
	struct inode_storage *inode_storage;
	u64 storage_flags = 0;

	if ((file->f_inode->i_sb->s_magic == TMPFS_MAGIC) &&
	     (file->f_inode->i_sb->s_flags & SB_KERNMOUNT))
		storage_flags = BPF_LOCAL_STORAGE_GET_F_CREATE;

	inode_storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode,
					      0, storage_flags);
	if (!inode_storage)
		return false;

	if (storage_flags &
	    !(inode_storage->state & INODE_STATE_OPENED_WRITTEN))
		inode_storage->state |= INODE_STATE_MMAP_EXEC_ALLOWED;

	if (!(inode_storage->state & INODE_STATE_MMAP_EXEC_ALLOWED))
		return false;

	inode_storage->state |= INODE_STATE_MMAP_EXEC_DONE;
	return true;
}

SEC("lsm.s/bprm_creds_for_exec")
int BPF_PROG(exec, struct linux_binprm *bprm)
{
	if (!bprm->file)
		return 0;

	return digest_lookup(bprm->file);
}

SEC("lsm.s/mmap_file")
int BPF_PROG(mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags)
{
	if (!file || !(prot & PROT_EXEC))
		return 0;

	if (mmap_exec_allowed(file))
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

	if (mmap_exec_allowed(vma->vm_file))
		return 0;

	log(MPROTECT_ERR, NULL, vma->vm_file);
	return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(file_open, struct file *file)
{
	struct inode_storage *inode_storage;
	u64 storage_flags = 0;

	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	if ((file->f_flags & __O_TMPFILE) ||
	    ((file->f_inode->i_sb->s_magic == TMPFS_MAGIC) &&
	     (file->f_inode->i_sb->s_flags & SB_KERNMOUNT)))
		storage_flags = BPF_LOCAL_STORAGE_GET_F_CREATE;

	inode_storage = bpf_inode_storage_get(&inode_storage_map, file->f_inode,
					      0, storage_flags);
	if (!inode_storage)
		return 0;

	if (inode_storage->state & INODE_STATE_MMAP_EXEC_DONE) {
		log(WRITE_MMAPPED_EXEC_ERR, NULL, file);
		return (lsm_mode == MODE_ENFORCING) ? -EPERM : 0;
	}

	if (inode_storage->state & INODE_STATE_OPENED_WRITTEN) {
		inode_storage->state &= ~INODE_STATE_MMAP_EXEC_ALLOWED;
	} else {
		if (file->f_flags & __O_TMPFILE)
			inode_storage->state |= INODE_STATE_MMAP_EXEC_ALLOWED;
	}

	inode_storage->state &= ~INODE_STATE_CHECKED;
	inode_storage->state |= INODE_STATE_OPENED_WRITTEN;
	return 0;
}

SEC("lsm.s/kernel_read_file")
int BPF_PROG(kernel_read_file, struct file *file, enum kernel_read_file_id id,
	     bool contents)
{
	if (!contents)
		return 0;

	/* Signature is verified. */
	if (id == READING_DIGLIM_CONF)
		return 0;

	return digest_lookup(file);
}

SEC("lsm.s/bpf")
int BPF_PROG(bpf_deny_map_write, int cmd, union bpf_attr *attr,
	     unsigned int size)
{
	if (cmd != BPF_MAP_UPDATE_ELEM && cmd != BPF_MAP_DELETE_ELEM)
		return 0;

	if (bpf_map_same((struct bpf_map *)&digest_items, attr->map_fd) ||
	    bpf_map_same((struct bpf_map *)&dirnames_map, attr->map_fd))
		return -EPERM;

	return 0;
}
