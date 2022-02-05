// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2021 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate compact digest lists.
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

#include "common.h"

char *compact_types_str[COMPACT__LAST] = {
	[COMPACT_PARSER] = "parser",
	[COMPACT_FILE] = "file",
	[COMPACT_METADATA] = "metadata",
	[COMPACT_DIGEST_LIST] = "digest_list",
};

static int gen_filename_prefix(char *filename, int filename_len, int pos,
			       const char *format, enum compact_types type)
{
	return snprintf(filename, filename_len, "%d-%s_list-%s-",
			(pos >= 0) ? pos : 0, compact_types_str[type], format);
}

static int calc_digest(u8 *digest, void *data, u64 len, enum hash_algo algo)
{
	EVP_MD_CTX *mdctx;
	const EVP_MD *md;
	int ret = -EINVAL;

	OpenSSL_add_all_algorithms();

	md = EVP_get_digestbyname(hash_algo_name[algo]);
	if (!md)
		goto out;

	mdctx = EVP_MD_CTX_create();
	if (!mdctx)
		goto out;

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
		goto out_mdctx;

	if (EVP_DigestUpdate(mdctx, data, len) != 1)
		goto out_mdctx;

	if (EVP_DigestFinal_ex(mdctx, digest, NULL) != 1)
		goto out_mdctx;

	ret = 0;
out_mdctx:
	EVP_MD_CTX_destroy(mdctx);
out:
	EVP_cleanup();
	return ret;
}

static int calc_file_digest(u8 *digest, char *path, enum hash_algo algo)
{
	void *data = MAP_FAILED;
	struct stat st;
	int fd, ret = 0;

	if (stat(path, &st) == -1)
		return -EACCES;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -EACCES;

	if (st.st_size) {
		data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if (data == MAP_FAILED) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = calc_digest(digest, data, st.st_size, algo);
out:
	if (data != MAP_FAILED)
		munmap(data, st.st_size);

	close(fd);
	return ret;
}

static u8 *new_digest_list(enum hash_algo algo, enum compact_types type,
			   u16 modifiers)
{
	u8 *digest_list;
	struct compact_list_hdr *hdr;

	digest_list = mmap(NULL, COMPACT_LIST_SIZE_MAX, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (digest_list == MAP_FAILED) {
		printf("Cannot allocate buffer\n");
		return NULL;
	}

	hdr = (struct compact_list_hdr *)digest_list;
	memset(hdr, 0, sizeof(*hdr));

	hdr->version = 1;
	hdr->type = __cpu_to_le16(type);
	hdr->modifiers = __cpu_to_le16(modifiers);
	hdr->algo = __cpu_to_le16(algo);
	return digest_list;
}

static int write_digest_list(int fd, u8 *digest_list)
{
	struct compact_list_hdr *hdr;
	u32 datalen;
	ssize_t ret;

	hdr = (struct compact_list_hdr *)digest_list;
	if (!hdr->count)
		return 0;

	datalen = hdr->datalen;
	hdr->count = __cpu_to_le32(hdr->count);
	hdr->datalen = __cpu_to_le32(hdr->datalen);

	ret = write(fd, digest_list, sizeof(*hdr) + datalen);
	if (ret != sizeof(*hdr) + datalen)
		return -EIO;

	return ret;
}

static int gen_compact_digest_list(char *input, enum hash_algo algo,
				   u8 *digest_list, u8 *digest_list_immutable)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fts_flags = (FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR | FTS_XDEV);
	char *paths[2] = { input, NULL };
	u8 *digest_list_ptr = digest_list;
	struct compact_list_hdr *cur_hdr;
	char *filename;
	int ret;

	if (!digest_list)
		digest_list_ptr = digest_list_immutable;

	fts = fts_open(paths, fts_flags, NULL);
	if (!fts) {
		printf("Unable to open %s\n", input);
		return -EACCES;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_F:
			if (((ftsent->fts_statp->st_mode & 0111) ||
			    !(ftsent->fts_statp->st_mode & 0222)) &&
			    ftsent->fts_statp->st_size)
				digest_list_ptr = digest_list_immutable;

			filename = strrchr(ftsent->fts_path, '/');

			if ((strstr(ftsent->fts_path, "/lib/modules") &&
			    (!filename || strncmp(filename, "modules.", 8))) ||
			    strstr(ftsent->fts_path, "/lib/firmware"))
				digest_list_ptr = digest_list_immutable;

			cur_hdr = (struct compact_list_hdr *)digest_list_ptr;

			ret = calc_file_digest(digest_list_ptr +
					sizeof(*cur_hdr) + cur_hdr->datalen,
					ftsent->fts_path, algo);
			if (ret < 0) {
				printf("Cannot calculate digest of %s\n",
				       ftsent->fts_path);
				continue;
			}

			cur_hdr->count++;
			cur_hdr->datalen += hash_digest_size[algo];
			break;
		default:
			break;
		}
	}

	return 0;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <output directory>: directory digest lists are written to\n"
	       "\t-i <path>: file/directory the digest list is generated from\n"
	       "\t-t <type>: type of compact list to generate\n"
	       "\t-a <algo>: digest algorithm\n"
	       "\t-f: force the digest list to be immutable\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	char path[PATH_MAX];
	char filename[NAME_MAX + 1];
	char *output_dir = NULL, *input = NULL;
	enum compact_types type = COMPACT_FILE;
	enum hash_algo algo = HASH_ALGO_SHA256;
	u8 *digest_list = NULL, *digest_list_immutable = NULL;
	char *input_ptr;
	struct stat st;
	int c;
	int ret, fd = -1, force_immutable = 0;

	while ((c = getopt(argc, argv, "d:i:t:a:fh")) != -1) {
		switch (c) {
		case 'd':
			output_dir = optarg;
			break;
		case 'i':
			input = optarg;
			break;
		case 't':
			for (type = 0; type < COMPACT__LAST; type++)
				if (!strcmp(compact_types_str[type], optarg))
					break;
			if (type == COMPACT__LAST) {
				printf("Invalid type %s\n", optarg);
				exit(1);
			}
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
		case 'f':
			force_immutable = 1;
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
		printf("Input file/directory not specified\n");
		exit(1);
	}

	if (stat(input, &st) == -1) {
		printf("Input file/directory not found or not accessible\n");
		exit(1);
	}

	if (stat(output_dir, &st) == -1)
		mkdir(output_dir, 0755);

	gen_filename_prefix(filename, sizeof(filename), 0, "compact", type);

	input_ptr = strrchr(input, '/');
	if (input_ptr)
		input_ptr++;
	else
		input_ptr = input;

	snprintf(path, sizeof(path), "%s/%s%s", output_dir, filename,
		 input_ptr);

	if (!force_immutable) {
		digest_list = new_digest_list(algo, type, 0);
		if (!digest_list) {
			ret = -ENOMEM;
			goto out;
		}
	}

	digest_list_immutable = new_digest_list(algo, type,
						(1 << COMPACT_MOD_IMMUTABLE));
	if (!digest_list_immutable) {
		ret = -ENOMEM;
		goto out;
	}

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		printf("Unable to create %s\n", path);
		ret = -errno;
		goto out;
	}

	ret = gen_compact_digest_list(input, algo, digest_list,
				      digest_list_immutable);
	if (ret < 0) {
		printf("Unable to generate the digest list from %s\n", input);
		goto out;
	}

	if (!force_immutable) {
		ret = write_digest_list(fd, digest_list);
		if (ret < 0) {
			printf("Unable to write the digest list to %s\n", path);
			goto out;
		}
	}

	ret = write_digest_list(fd, digest_list_immutable);
	if (ret < 0)
		printf("Unable to write the digest list to %s\n", path);
out:
	if (digest_list)
		munmap(digest_list, COMPACT_LIST_SIZE_MAX);
	if (digest_list_immutable)
		munmap(digest_list_immutable, COMPACT_LIST_SIZE_MAX);

	if (fd >= 0)
		close(fd);

	if (ret < 0)
		unlink(path);

	return ret;
}
