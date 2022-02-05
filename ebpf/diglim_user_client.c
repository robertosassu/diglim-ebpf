// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the client of the user space side of DIGLIM.
 */

#include <stdlib.h>
#include <getopt.h>

#include "common.h"

static char *digest_list_ops_str[CMD__LAST] = {
	[CMD_ADD] = "add",
	[CMD_DEL] = "del",
};

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-o <op>: digest list operation\n"
	       "\t-p <path>: path of the digest list or the directory containing the digest lists\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	enum digest_list_ops op = CMD__LAST;
	char *path = NULL;
	char c;
	int ret, i, server_ret = -1;

	while ((c = getopt(argc, argv, "o:p:h")) != -1) {
		switch (c) {
		case 'o':
			for (i = 0; i < CMD__LAST; i++) {
				if (!strcmp(optarg, digest_list_ops_str[i])) {
					op = i;
					break;
				}
			}
			break;
		case 'p':
			path = optarg;
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			printf("Invalid option %c\n", c);
			exit(1);
		}
	}

	if (op == CMD__LAST) {
		printf("Digest list operation not specified\n");
		exit(1);
	}

	if (!path) {
		printf("Digest list path not specified\n");
		exit(1);
	}

	ret = diglim_exec_op(path, op, &server_ret);
	if (!ret && !server_ret) {
		printf("Digest list command successful\n");
		return 0;
	}

	printf("Send result: %d, diglim_user result: %d\n", ret, server_ret);
	return ret;
}
