// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * DIGLIM eBPF user space initialization program.
 */

#include <unistd.h>
#include <bpf/bpf.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include "common_user.h"
#include "../kernel/diglim_kern.skel.h"

#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME)

struct data tmp;

static int mount_fs(bool *mounted)
{
	struct stat st;
	int ret;

	if (!stat("/sys/kernel", &st))
		return false;

	ret = mount(SYSFS_PATH, SYSFS_PATH, "sysfs", MOUNT_FLAGS, NULL);
	if (ret == -1) {
		_log("Failed to mount sysfs\n");
		return -errno;
	}

	ret = mount(SECURITYFS_PATH, SECURITYFS_PATH, "securityfs", MOUNT_FLAGS,
		    NULL);
	if (ret == -1) {
		_log("Failed to mount securityfs\n");
		umount(SYSFS_PATH);
		return -errno;
	}

	*mounted = true;
	return 0;
}

static void umount_fs(bool mounted)
{
	if (!mounted)
		return;

	umount(SECURITYFS_PATH);
	umount(SYSFS_PATH);
}

static void usage(char *progname)
{
	_log("Usage: %s <options>\n", progname);
	_log("Options:\n");
	_log("\t-p: set DIGLIM eBPF in permissive mode\n"
	     "\t-d <path>: path of the digest list or the directory containing the digest lists\n"
	     "\t-m <map name>: the name of the eBPF map digest lists are written to\n"
	     "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	struct diglim_kern *skel = NULL;
	char path[PATH_MAX];
	unsigned char *loader_digest = NULL;
	size_t loader_digest_len = 0;
	char *map_name = "data_input";
	char *digest_list_path = NULL;
	bool permissive_mode = false;
	bool fs_mounted = false;
	struct stat st;
	int zero = 0;
	char c;
	int ret, i, fd, status;

	is_init = (getpid() == 1);
	if (is_init)
		digest_list_path = DIGEST_LISTS_DEFAULT_PATH;

	while ((c = getopt(argc, argv, "d:pm:h")) != -1) {
		switch (c) {
		case 'd':
			digest_list_path = optarg;
			break;
		case 'p':
			permissive_mode = true;
			break;
		case 'm':
			map_name = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			_log("Invalid option %c\n", c);
			exit(1);
		}
	}

	ret = mount_fs(&fs_mounted);
	if (ret < 0)
		return ret;

	skel = diglim_kern__open_and_load();
	if (!skel) {
		_log("diglim_kern__open_and_load() failed\n");
		ret = -EINVAL;
		goto out;
	}

	ret = diglim_kern__attach(skel);
	if (ret < 0) {
		_log("diglim_kern__attach() failed\n");
		goto out;
	}

	skel->bss->ima_ready = true;

	if (permissive_mode)
		skel->bss->lsm_mode = MODE_PERMISSIVE;

	ret = diglim_read_file(LOADER_DIGEST_LIST_PATH, &loader_digest_len,
			       &loader_digest);
	if (ret < 0) {
		_log("Error: %s not found, loader will not execute in enforcing mode\n",
		     LOADER_DIGEST_LIST_PATH);
		goto out;
	}

	fd = diglim_find_map(map_name);
	if (fd < 0) {
		_log("Unable to find the map %s\n", map_name);
		ret = -ENOENT;
		goto out_munmap;
	}

	tmp.op = DIGEST_LIST_ADD;
	tmp.size = loader_digest_len;
	memcpy(tmp.val, loader_digest, loader_digest_len);

	bpf_map_update_elem(fd, &zero, &tmp, BPF_ANY);
	memset(&tmp, 0, sizeof(tmp));
	bpf_map_update_elem(fd, &zero, &tmp, BPF_ANY);

	close(fd);

	if (digest_list_path) {
		if (fork() == 0)
			return execlp(DIGEST_LIST_LOADER_PATH,
				DIGEST_LIST_LOADER_PATH, "-o", "add",
				"-d", digest_list_path, NULL);

		wait(&status);

		if (WEXITSTATUS(status)) {
			_log("Error: %s returned %d\n", DIGEST_LIST_LOADER_PATH,
			     WEXITSTATUS(status));
			goto out_munmap;
		}
	}

	if (is_init) {
		if (fork() == 0) {
			/* Wait for /sys/fs/bpf mount. */
			while (stat(BPFFS_PATH, &st) == -1 || st.st_ino != 1)
				sleep(0.1);

			if (stat(BPFFS_DIGLIM_PATH, &st) == -1)
				mkdir(BPFFS_DIGLIM_PATH, 0755);

			ret = 0;

			for (i = 0; i < skel->skeleton->prog_cnt; i++) {
				snprintf(path, sizeof(path), "%s%s",
					 BPFFS_DIGLIM_PATH,
					 skel->skeleton->progs[i].name);

				bpf_link__pin(*skel->skeleton->progs[i].link,
					      path);
			}

			munmap(loader_digest, loader_digest_len);
			diglim_kern__destroy(skel);
			exit(0);
		}
	} else {
		pause();
	}
out_munmap:
	munmap(loader_digest, loader_digest_len);
out:
	umount_fs(fs_mounted);
	diglim_kern__destroy(skel);
	if (ret < 0)
		return ret;

	return (is_init) ? execlp("/sbin/init", "/sbin/init", NULL) : 0;
}
