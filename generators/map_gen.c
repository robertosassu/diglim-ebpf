// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generator of map digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <fts.h>
#include <string.h>
#include <getopt.h>

#include "common_user.h"

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <output directory>: directory digest lists are written to\n"
	       "\t-i <path>: file/directory the digest list is generated from\n"
	       "\t-a <algo>: digest algorithm\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	u8 digest[1 + MAX_DIGEST_SIZE] = { 0 };
	char path[PATH_MAX];
	char filename[NAME_MAX + 1];
	char *output_dir = NULL, *input = NULL;
	enum compact_types type = COMPACT_FILE;
	enum hash_algo algo = HASH_ALGO_SHA256;
	char *input_ptr;
	struct stat st;
	int c;
	int ret, fd = -1;

	while ((c = getopt(argc, argv, "d:i:a:h")) != -1) {
		switch (c) {
		case 'd':
			output_dir = optarg;
			break;
		case 'i':
			input = optarg;
			break;
		case 'a':
			for (algo = 0; algo < HASH_ALGO__LAST; algo++)
				if (!strcmp(hash_algo_name[algo], optarg))
					break;
			if (algo == HASH_ALGO__LAST) {
				printf("Invalid algo %s\n", optarg);
				exit(1);
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(0);
		default:
			printf("Invalid option %c\n", c);
			exit(1);
		}
	}

	if (!output_dir) {
		printf("Output directory not specified\n");
		exit(1);
	}

	if (!input) {
		printf("Input file not specified\n");
		exit(1);
	}

	if (stat(input, &st) == -1) {
		printf("Input file not found or not accessible\n");
		exit(1);
	}

	if (!S_ISREG(st.st_mode)) {
		printf("%s is not a regular file\n", input);
		exit(1);
	}

	if (stat(output_dir, &st) == -1)
		mkdir(output_dir, 0755);

	gen_filename_prefix(filename, sizeof(filename), 0, "map", type);

	input_ptr = strrchr(input, '/');
	if (input_ptr)
		input_ptr++;
	else
		input_ptr = input;

	snprintf(path, sizeof(path), "%s/%s%s", output_dir, filename,
		 input_ptr);

	digest[0] = algo;
	ret = diglim_calc_file_digest(digest + 1, input, algo);
	if (ret < 0) {
		printf("Unable to calculate digest of %s\n", input);
		exit(1);
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		printf("Unable to create %s\n", path);
		exit(1);
	}

	ret = write(fd, digest, sizeof(digest));
	if (ret != sizeof(digest)) {
		printf("Unable to write the digest to %s\n", path);
		goto out;
	}
out:
	if (fd >= 0)
		close(fd);

	if (ret < 0)
		unlink(path);

	return ret;
}
