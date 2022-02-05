// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the parser framework.
 */

#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include "common.h"

struct parser *head;

int diglim_init_parsers(void)
{
	DIR *parser_dir;
	struct dirent *ent;
	struct parser *new;
	char path[PATH_MAX];
	char func_name[512];
	char *dot_ptr;
	int ret, d_name_len;

	parser_dir = opendir(PARSER_DIR);
	if (!parser_dir)
		return -errno;

	snprintf(path, sizeof(path), "%s", PARSER_DIR);

	while ((ent = readdir(parser_dir))) {
		if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "."))
			continue;

		if (ent->d_type != DT_REG && ent->d_type != DT_UNKNOWN)
			continue;

		d_name_len = strlen(ent->d_name);

		if (d_name_len < 3 ||
		    strncmp(ent->d_name + d_name_len - 3, ".so", 3))
			continue;

		new = calloc(1, sizeof(*new));
		if (!new) {
			ret = -ENOMEM;
			goto out;
		}

		dot_ptr = strchr(ent->d_name, '.');
		if (!dot_ptr)
			dot_ptr = ent->d_name + strlen(ent->d_name);

		strncpy(new->name, ent->d_name, dot_ptr - ent->d_name);

		snprintf(path + sizeof(PARSER_DIR) - 1,
			 sizeof(path) - sizeof(PARSER_DIR) + 1, "%s",
			 ent->d_name);

		new->handle = dlopen(path, RTLD_LAZY);
		if (!new->handle) {
			free(new);
			ret = -EACCES;
			goto out;
		}

		snprintf(func_name, sizeof(func_name), "%s_init", new->name);
		new->init_func = dlsym(new->handle, func_name);
		if (!new->init_func) {
			dlclose(new->handle);
			free(new);
			ret = -ENOENT;
			goto out;
		}

		snprintf(func_name, sizeof(func_name), "%s_fini", new->name);
		new->fini_func = dlsym(new->handle, func_name);
		if (!new->fini_func) {
			dlclose(new->handle);
			free(new);
			ret = -ENOENT;
			goto out;
		}

		snprintf(func_name, sizeof(func_name), "%s_parse", new->name);
		new->parse_func = dlsym(new->handle, func_name);
		if (!new->parse_func) {
			dlclose(new->handle);
			free(new);
			ret = -ENOENT;
			goto out;
		}

		new->next = head;
		head = new;
	}

	ret = 0;
out:
	closedir(parser_dir);
	return ret;
}

void diglim_fini_parsers(void)
{
	struct parser *tmp;

	while (head) {
		tmp = head->next;

		head->fini_func();
		dlclose(head->handle);
		free(head);
		head = tmp;
	}
}

int diglim_parse_digest_list(int map_fd, unsigned char cmd, char *path,
			     bool only_immutable)
{
	struct parser *cur = head;
	char *filename = strrchr(path, '/');
	char *type_start, *format_start, *format_end;
	struct stat st;

	if (stat(path, &st) == -1)
		return -errno;

	if (!st.st_size)
		return 0;

	if (!filename)
		return 0;

	type_start = strchr(++filename, '-');
	if (!type_start)
		return 0;

	format_start = strchr(++type_start, '-');
	if (!format_start)
		return 0;

	format_end = strchr(++format_start, '-');
	if (!format_end)
		return 0;

	while (cur) {
		if (!strncmp(cur->name, format_start,
			     format_end - format_start))
			break;

		cur = cur->next;
	}

	if (!cur)
		return -ENOENT;

	return cur->parse_func(map_fd, cmd, path, only_immutable);
}
