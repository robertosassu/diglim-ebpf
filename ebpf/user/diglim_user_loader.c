// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Digest list loader.
 */

#include <fts.h>
#include <sys/mman.h>

#include "libbpf.h"
#include "common_user.h"

struct data tmp;

static char *ops_str[DIGEST_LIST_OP__LAST] = {
	[DIGEST_LIST_ADD] = "add",
	[DIGEST_LIST_DEL] = "del",
};

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-o <op>: digest list operation\n"
	       "\t-d <path>: path of the digest list or the directory containing the digest lists\n"
	       "\t-m <map name>: the name of the eBPF map digest lists are written to\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	unsigned char *data;
	size_t len;
	int zero = 0;
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { DIGEST_LISTS_DEFAULT_PATH, NULL };
	enum ops op = DIGEST_LIST_OP__LAST;
	char *map_name = "data_input";
	char c;
	int ret, i, fd;

	while ((c = getopt(argc, argv, "o:d:m:h")) != -1) {
		switch (c) {
		case 'o':
			for (i = 0; i < DIGEST_LIST_OP__LAST; i++) {
				if (!strcmp(optarg, ops_str[i])) {
					op = i;
					break;
				}
			}
			break;
		case 'd':
			paths[0] = optarg;
			break;
		case 'm':
			map_name = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			printf("Invalid option %c\n", c);
			exit(1);
		}
	}

	if (op == DIGEST_LIST_OP__LAST) {
		printf("Digest list operation not specified\n");
		exit(1);
	}

	fd = diglim_find_map(map_name);
	if (fd < 0) {
		printf("data_input map not found, is DIGLIM loaded?\n");
		exit(1);
	}

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		ret = -EACCES;
		goto out;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			ret = diglim_read_file(ftsent->fts_path, &len, &data);
			if (ret < 0)
				goto out;

			if (len > sizeof(tmp.val)) {
				munmap(data, len);
				continue;
			}

			tmp.op = op;
			tmp.size = len;
			memcpy(tmp.val, data, len);

			bpf_map_update_elem(fd, &zero, &tmp, BPF_ANY);
			memset(&tmp, 0, sizeof(tmp));
			bpf_map_update_elem(fd, &zero, &tmp, BPF_ANY);

			munmap(data, len);
			break;
		default:
			break;
		}
	}

	ret = 0;
out:
	close(fd);
	return ret;
}
