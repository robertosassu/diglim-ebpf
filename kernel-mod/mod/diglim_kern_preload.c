// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Kernel module for loading DIGLIM eBPF.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/init.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/kernel_read_file.h>
#include <linux/vmalloc.h>

#include "../../ebpf/kernel/diglim_kern.lskel.h"
#include "../../include/common.h"

#define ptr_to_u64(ptr)    ((__u64)(unsigned long)(ptr))

static struct bpf_link *exec_link;
static struct bpf_link *mmap_file_link;
static struct bpf_link *file_mprotect_link;
static struct bpf_link *file_open_link;
static struct bpf_link *kernel_read_file_link;
static struct bpf_link *bpf_compact_link;
static struct bpf_link *bpf_rpm_link;
static struct bpf_link *bpf_map_link;
static struct bpf_map *digest_items_map;
static struct bpf_map *inode_storage_map_map;
static struct bpf_map *ringbuf_map;
static struct bpf_map *data_input_map;
static struct diglim_kern *skel;

extern long bpf_mod_verify_sig(const void *mod, size_t modlen);

static bool active;
static bool ima_ready;
static int lsm_mode;

static void free_objs_and_skel(void)
{
	if (!IS_ERR_OR_NULL(exec_link))
		bpf_link_put(exec_link);
	if (!IS_ERR_OR_NULL(mmap_file_link))
		bpf_link_put(mmap_file_link);
	if (!IS_ERR_OR_NULL(file_mprotect_link))
		bpf_link_put(file_mprotect_link);
	if (!IS_ERR_OR_NULL(file_open_link))
		bpf_link_put(file_open_link);
	if (!IS_ERR_OR_NULL(kernel_read_file_link))
		bpf_link_put(kernel_read_file_link);
	if (!IS_ERR_OR_NULL(bpf_compact_link))
		bpf_link_put(bpf_compact_link);
	if (!IS_ERR_OR_NULL(bpf_rpm_link))
		bpf_link_put(bpf_rpm_link);
	if (!IS_ERR_OR_NULL(bpf_map_link))
		bpf_link_put(bpf_map_link);
	if (!IS_ERR_OR_NULL(digest_items_map))
		bpf_map_put(digest_items_map);
	if (!IS_ERR_OR_NULL(inode_storage_map_map))
		bpf_map_put(inode_storage_map_map);
	if (!IS_ERR_OR_NULL(ringbuf_map))
		bpf_map_put(ringbuf_map);
	if (!IS_ERR_OR_NULL(data_input_map))
		bpf_map_put(data_input_map);

	diglim_kern__destroy(skel);
}

static int load_skel(void)
{
	int err = -ENOMEM;

	skel = diglim_kern__open();
	if (!skel)
		goto out;

	err = diglim_kern__load(skel);
	if (err)
		goto out;

	err = diglim_kern__attach(skel);
	if (err)
		goto out;

	exec_link = bpf_link_get_from_fd(skel->links.exec_fd);
	if (IS_ERR(exec_link)) {
		err = PTR_ERR(exec_link);
		goto out;
	}

	mmap_file_link = bpf_link_get_from_fd(skel->links.mmap_file_fd);
	if (IS_ERR(mmap_file_link)) {
		err = PTR_ERR(mmap_file_link);
		goto out;
	}

	file_mprotect_link = bpf_link_get_from_fd(skel->links.file_mprotect_fd);
	if (IS_ERR(file_mprotect_link)) {
		err = PTR_ERR(file_mprotect_link);
		goto out;
	}

	file_open_link = bpf_link_get_from_fd(skel->links.file_open_fd);
	if (IS_ERR(file_open_link)) {
		err = PTR_ERR(file_open_link);
		goto out;
	}

	kernel_read_file_link =
		bpf_link_get_from_fd(skel->links.kernel_read_file_fd);
	if (IS_ERR(kernel_read_file_link)) {
		err = PTR_ERR(kernel_read_file_link);
		goto out;
	}

	bpf_compact_link = bpf_link_get_from_fd(skel->links.bpf_compact_fd);
	if (IS_ERR(bpf_compact_link)) {
		err = PTR_ERR(bpf_compact_link);
		goto out;
	}

	bpf_rpm_link = bpf_link_get_from_fd(skel->links.bpf_rpm_fd);
	if (IS_ERR(bpf_rpm_link)) {
		err = PTR_ERR(bpf_rpm_link);
		goto out;
	}

	bpf_map_link = bpf_link_get_from_fd(skel->links.bpf_map_fd);
	if (IS_ERR(bpf_map_link)) {
		err = PTR_ERR(bpf_map_link);
		goto out;
	}

	digest_items_map = bpf_map_get(skel->maps.digest_items.map_fd);
	if (IS_ERR(digest_items_map)) {
		err = PTR_ERR(digest_items_map);
		goto out;
	}

	inode_storage_map_map = bpf_map_get(skel->maps.inode_storage_map.map_fd);
	if (IS_ERR(inode_storage_map_map)) {
		err = PTR_ERR(inode_storage_map_map);
		goto out;
	}

	ringbuf_map = bpf_map_get(skel->maps.ringbuf.map_fd);
	if (IS_ERR(ringbuf_map)) {
		err = PTR_ERR(ringbuf_map);
		goto out;
	}

	data_input_map = bpf_map_get(skel->maps.data_input.map_fd);
	if (IS_ERR(data_input_map)) {
		err = PTR_ERR(data_input_map);
		goto out;
	}

	/* Avoid taking over stdin/stdout/stderr of init process. Zeroing out
	 * makes skel_closenz() a no-op later in iterators_bpf__destroy().
	 */
	close_fd(skel->links.exec_fd);
	skel->links.exec_fd = 0;
	close_fd(skel->links.mmap_file_fd);
	skel->links.mmap_file_fd = 0;
	close_fd(skel->links.file_mprotect_fd);
	skel->links.file_mprotect_fd = 0;
	close_fd(skel->links.file_open_fd);
	skel->links.file_open_fd = 0;
	close_fd(skel->links.kernel_read_file_fd);
	skel->links.kernel_read_file_fd = 0;
	close_fd(skel->links.bpf_compact_fd);
	skel->links.bpf_compact_fd = 0;
	close_fd(skel->links.bpf_rpm_fd);
	skel->links.bpf_rpm_fd = 0;
	close_fd(skel->links.bpf_map_fd);
	skel->links.bpf_map_fd = 0;
	close(skel->maps.digest_items.map_fd);
	skel->maps.digest_items.map_fd = 0;
	close(skel->maps.inode_storage_map.map_fd);
	skel->maps.inode_storage_map.map_fd = 0;
	close(skel->maps.ringbuf.map_fd);
	skel->maps.ringbuf.map_fd = 0;
	close(skel->maps.data_input.map_fd);
	skel->maps.data_input.map_fd = 0;

	active = true;

	return 0;
out:
	free_objs_and_skel();
	return err;
}

static void diglim_exec_loader(void)
{
	char *argv[6] = {NULL}, *envp[1] = {NULL};

	argv[0] = DIGEST_LIST_LOADER_PATH;
	argv[1] = "-o";
	argv[2] = "add";
	argv[3] = "-d";
	argv[4] = DIGEST_LISTS_DEFAULT_PATH;

	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

int diglim_read_loader_digest(void)
{
	void *buf = NULL;
	size_t file_size;
	u8 digest_type = COMPACT_FILE;
	int ret;

	ret = kernel_read_file_from_path(LOADER_DIGEST_LIST_PATH, 0, &buf,
					 INT_MAX, &file_size,
					 READING_DIGLIM_CONF);
	if (ret < 0)
		return ret;

	ret = bpf_mod_verify_sig(buf, file_size);
	if (ret < 0)
		goto out;

	if (ret != 1 + MAX_DIGEST_SIZE)
		return -EINVAL;

	ret = digest_items_map->ops->map_update_elem(digest_items_map, buf,
						     &digest_type, BPF_ANY);
	if (!ret)
		diglim_exec_loader();
out:
	vfree(buf);
	return ret;
}

int ima_status_change(struct notifier_block *nb, unsigned long event,
		      void *lsm_data)
{
	int ret;

	if (event != IMA_READY)
		return NOTIFY_DONE;

	skel->bss->ima_ready = true;

	ret = diglim_read_loader_digest();
	if (ret < 0)
		pr_err("Failed to initialize DIGLIM eBPF, ret: %d\n", ret);

	return NOTIFY_OK;
}

static struct notifier_block diglim_notifier = {
	.notifier_call = ima_status_change,
};

int __init init_diglim(void)
{
	int ret;

	ret = load_skel();
	if (ret < 0) {
		pr_err("Failed to load DIGLIM eBPF, ret: %d\n", ret);
		return 0;
	}

	if (lsm_mode)
		skel->bss->lsm_mode = lsm_mode;

	if (ima_ready) {
		skel->bss->ima_ready = true;

		ret = diglim_read_loader_digest();
		if (ret < 0)
			pr_err("Failed to initialize DIGLIM eBPF, ret: %d\n",
			       ret);

		return ret;
	}

	return register_blocking_lsm_notifier(&diglim_notifier);
}

void __exit fini_diglim(void)
{
	if (!active)
		return;

	free_objs_and_skel();
}

module_init(init_diglim);
module_exit(fini_diglim);
MODULE_LICENSE("GPL");

module_param(ima_ready, bool, 0644);
module_param(lsm_mode, int, 0644);
