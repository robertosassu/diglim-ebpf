// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common functions used in digest list generators.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <bpf/bpf.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#include "common_user.h"

int diglim_calc_digest(u8 *digest, void *data, u64 len, enum hash_algo algo)
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

int diglim_calc_file_digest(u8 *digest, char *path, enum hash_algo algo)
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

	ret = diglim_calc_digest(digest, data, st.st_size, algo);
out:
	if (data != MAP_FAILED)
		munmap(data, st.st_size);

	close(fd);
	return ret;
}

char *compact_types_str[COMPACT__LAST] = {
	[COMPACT_PARSER] = "parser",
	[COMPACT_FILE] = "file",
	[COMPACT_METADATA] = "metadata",
	[COMPACT_DIGEST_LIST] = "digest_list",
};

int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type)
{
	return snprintf(filename, filename_len, "%d-%s_list-%s-",
			(pos >= 0) ? pos : 0, compact_types_str[type], format);
}
