// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the user space side of DIGLIM.
 */

#include <fcntl.h>
#include <getopt.h>
#include <unistd.h>
#include <fts.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <syslog.h>

#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/signal.h>

#include "diglim_kern.skel.h"
#include "common.h"
#include "log.h"

#define MOUNT_FLAGS (MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME)

static char *errors_str[LAST__ERR] = {
	[UNKNOWN_DIGEST_ERR] = UNKNOWN_DIGEST_ERR_STR,
	[CALC_DIGEST_ERR] = CALC_DIGEST_ERR_STR,
	[MMAP_WRITERS_ERR] = MMAP_WRITERS_ERR_STR,
	[MPROTECT_ERR] = MPROTECT_ERR_STR,
	[WRITE_MMAPPED_EXEC] = WRITE_MMAPPED_EXEC_STR,
};

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

#ifndef HAVE_KERNEL_PATCHES
static int write_ima_policy(void)
{
	struct stat st_ima, st_pol;
	size_t to_write, read_len = 0, write_len = 0;
	u8 buf[128], *buf_ptr = buf;
	int ret, fd_ima, fd_pol;

	if (stat(IMA_POLICY_PATH, &st_ima) == -1 ||
	    stat(DIGLIM_IMA_POLICY_PATH, &st_pol) == -1)
		return 0;

	to_write = st_pol.st_size;

	fd_ima = open(IMA_POLICY_PATH, O_WRONLY);
	if (fd_ima == -1)
		return -errno;

	fd_pol = open(DIGLIM_IMA_POLICY_PATH, O_RDONLY);
	if (fd_pol == -1) {
		close(fd_ima);
		return -errno;
	}

	while (to_write) {
		read_len = read(fd_pol, buf_ptr, buf + sizeof(buf) - buf_ptr);
		if (read_len == -1) {
			_log("Unable to read the IMA policy\n");
			ret = -errno;
			goto out;
		}

		buf_ptr += read_len;

		write_len = write(fd_ima, buf, buf_ptr - buf);
		if (write_len == -1) {
			_log("Unable to write the IMA policy\n");
			ret = -errno;
			goto out;
		}

		to_write -= write_len;
		memmove(buf, buf + write_len, buf_ptr - buf - write_len);
		buf_ptr -= write_len;
	}

	ret = 0;
out:
	close(fd_pol);
	close(fd_ima);
	return ret;
}
#endif

static int add_digests_from_dir(int map_fd, char *dir_path, bool only_immutable)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { dir_path, NULL };
	int ret = 0;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		_log("Unable to open %s\n", dir_path);
		return -EACCES;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = diglim_parse_digest_list(map_fd, CMD_ADD,
						       ftsent->fts_path,
						       only_immutable);
			if (ret < 0)
				_log("Cannot parse %s\n", ftsent->fts_path);
			break;
		default:
			break;
		}
	}

	fts_close(fts);
	return ret;
}

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

	ret = mount(DEBUGFS_PATH, DEBUGFS_PATH, "debugfs", MOUNT_FLAGS, NULL);
	if (ret == -1) {
		_log("Failed to mount debugfs\n");
		umount(SYSFS_PATH);
		return -errno;
	}

	ret = mount(SECURITYFS_PATH, SECURITYFS_PATH, "securityfs", MOUNT_FLAGS,
		    NULL);
	if (ret == -1) {
		_log("Failed to mount securityfs\n");
		umount(DEBUGFS_PATH);
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
	umount(DEBUGFS_PATH);
	umount(SYSFS_PATH);
}

static bool diglim_initialized(void)
{
	struct stat st;

	return (!stat(DIGEST_ITEMS_MAP_PATH, &st));
}

static int diglim_init(char *digest_lists_dir, bool only_immutable,
		       enum lsm_modes lsm_mode, struct diglim_kern **skel,
		       struct bpf_map **map, int *map_fd,
		       struct bpf_map **ringbuf_map,
		       struct ring_buffer **ringbuf)
{
	struct diglim_kern *_skel;
	struct bpf_map *_map, *_ringbuf_map;
	struct ring_buffer *_ringbuf;
	bool fs_mounted = false;
	int ret, ringbuf_fd;

	ret = diglim_init_parsers();
	if (ret < 0) {
		_log("Failed to init parsers\n");
		return ret;
	}

	if (diglim_initialized()) {
		*map_fd = bpf_obj_get(DIGEST_ITEMS_MAP_PATH);
		if (*map_fd < 0) {
			ret = -EACCES;
			goto out;
		}

		ringbuf_fd = bpf_obj_get(RINGBUF_PATH);
		if (ringbuf_fd < 0) {
			close(*map_fd);
			ret = -EACCES;
			goto out;
		}

		_ringbuf = ring_buffer__new(ringbuf_fd, process_log, NULL,
					    NULL);
		if (!_ringbuf) {
			close(*map_fd);
			close(ringbuf_fd);
			ret = -ENOMEM;
			goto out;
		}

		*ringbuf = _ringbuf;
		close(ringbuf_fd);
		ret = 0;
		goto out;
	}

	ret = mount_fs(&fs_mounted);
	if (ret < 0)
		goto out;

#ifndef HAVE_KERNEL_PATCHES
	ret = write_ima_policy();
	if (ret < 0)
		goto out;
#endif

	_skel = diglim_kern__open_and_load();
	if (!_skel) {
		_log("Failed to open and load\n");
		ret = -EINVAL;
		goto out_umount;
	}

	ret = diglim_kern__attach(_skel);
	if (ret < 0) {
		_log("Failed to attach\n");
		goto out_destroy;
	}

	_skel->bss->lsm_mode = lsm_mode;

	_map = bpf_object__find_map_by_name(_skel->obj, DIGEST_ITEMS_MAP_NAME);
	if (!_map) {
		_log("Failed to find map\n");
		ret = -EINVAL;
		goto out_detach;
	}

	_ringbuf_map = bpf_object__find_map_by_name(_skel->obj, RINGBUF_NAME);
	if (!_ringbuf_map) {
		_log("Failed to find ring buffer\n");
		ret = -EINVAL;
		goto out_detach;
	}

	_ringbuf = ring_buffer__new(bpf_map__fd(_skel->maps.ringbuf),
				    process_log, NULL, NULL);
	if (!_ringbuf) {
		_log("Failed to get the ring buffer\n");
		ret = -EINVAL;
		goto out_detach;
	}

	ret = add_digests_from_dir(bpf_map__fd(_map), digest_lists_dir,
				   only_immutable);
	if (ret < 0) {
		_log("Failed to add digests from %s\n", digest_lists_dir);
		goto out_ringbuf_free;
	}

	*skel = _skel;
	*map = _map;
	*map_fd = bpf_map__fd(*map);
	*ringbuf_map = _ringbuf_map;
	*ringbuf = _ringbuf;
out_ringbuf_free:
	if (ret < 0)
		ring_buffer__free(_ringbuf);
out_detach:
	if (ret < 0)
		diglim_kern__detach(_skel);
out_destroy:
	if (ret < 0)
		diglim_kern__destroy(_skel);
out_umount:
	umount_fs(fs_mounted);
out:
	if (ret < 0)
		diglim_fini_parsers();

	return ret;
}

static void diglim_fini(struct diglim_kern *skel, struct bpf_map *map,
			struct ring_buffer *ringbuf)
{
	if (diglim_initialized())
		return;

	ring_buffer__free(ringbuf);
	diglim_kern__detach(skel);
	diglim_kern__destroy(skel);
	diglim_fini_parsers();
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <digest list directory>: directory digest lists are read from\n"
	       "\t-a: add to the allow list all the files, not only the immutable ones\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	bool only_immutable = true;
	struct diglim_kern *skel = NULL;
	struct bpf_map *map = NULL, *ringbuf_map = NULL;
	struct ring_buffer *ringbuf = NULL;
	char *digest_list_dir = DIGEST_LISTS_DEFAULT_PATH;
	char path[PATH_MAX] = DIGLIM_BPFFS_PATH;
	struct stat st;
	char c;
	enum lsm_modes lsm_mode = MODE_ENFORCING;
	int ret, i, map_fd, path_len = strlen(path);

	while ((c = getopt(argc, argv, "d:aph")) != -1) {
		switch (c) {
		case 'd':
			digest_list_dir = optarg;
			break;
		case 'a':
			only_immutable = false;
			break;
		case 'p':
			lsm_mode = MODE_PERMISSIVE;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			printf("Invalid option %c\n", c);
			exit(1);
		}
	}

	is_init = (getpid() == 1);

	ret = diglim_init(digest_list_dir, only_immutable, lsm_mode, &skel,
			  &map, &map_fd, &ringbuf_map, &ringbuf);
	if (ret < 0)
		return ret;

	if (!is_init || !fork()) {
		if (is_init) {
			/* Wait for /sys/fs/bpf mount. */
			while (stat(BPFFS_PATH, &st) == -1 || st.st_ino != 1)
				sleep(0.1);

			if (stat(path, &st) == -1)
				mkdir(path, 0600);

			for (i = 0; i < skel->skeleton->prog_cnt; i++) {
				snprintf(path + path_len,
					 sizeof(path) - path_len, "%s",
					 skel->skeleton->progs[i].name);
				bpf_link__pin(*skel->skeleton->progs[i].link,
					      path);
			}

			ret = bpf_map__pin(map, DIGEST_ITEMS_MAP_PATH);
			if (ret < 0) {
				_log("Failed to pin map\n");
				diglim_fini(skel, map, ringbuf);
				exit(1);
			}

			ret = bpf_map__pin(ringbuf_map, RINGBUF_PATH);
			if (ret < 0) {
				_log("Failed to pin ring buffer\n");
				diglim_fini(skel, map, ringbuf);
				exit(1);
			}

			/* Wait for /run mount. */
			while (stat("/run", &st) == -1 || st.st_ino != 1)
				sleep(0.1);
		}

		ret = diglim_main_loop(map_fd, only_immutable, ringbuf);
		close(map_fd);
		diglim_fini(skel, map, ringbuf);
		exit(!ret ? ret : 1);
	}

	close(map_fd);
	diglim_fini(skel, map, ringbuf);

	return execlp("/sbin/init", "/sbin/init", NULL);
}
