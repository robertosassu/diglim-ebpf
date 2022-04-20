// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common functions.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bpf/bpf.h>

#include "common_user.h"

int diglim_read_file(const char *path, size_t *len, unsigned char **data)
{
	struct stat st;
	int rc = 0, fd;

	if (stat(path, &st) == -1)
		return -ENOENT;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -EACCES;

	*len = st.st_size;

	*data = mmap(NULL, *len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (*data == MAP_FAILED)
		rc = -ENOMEM;

	close(fd);
	return rc;
}

int diglim_find_map(const char *map_name)
{
	struct bpf_map_info info = {};
	uint32_t info_len = sizeof(info);
	u32 id = 0;
	int ret, fd;

	while (true) {
		ret = bpf_map_get_next_id(id, &id);
		if (ret)
			break;

		fd = bpf_map_get_fd_by_id(id);
		if (fd < 0)
			continue;

		ret = bpf_obj_get_info_by_fd(fd, &info, &info_len);
		if (ret) {
			close(fd);
			continue;
		}

		if (!strcmp(info.name, map_name))
			break;

		close(fd);
	}

	if (ret)
		return -ENOENT;

	return fd;
}
