// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the rpm parser.
 */

#include <errno.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <linux/hash_info.h>

#include "common.h"

enum hash_algo pgp_algo_mapping[PGPHASHALGO_SHA224 + 1] = {
	[PGPHASHALGO_MD5] = HASH_ALGO_MD5,
	[PGPHASHALGO_SHA1] = HASH_ALGO_SHA1,
	[PGPHASHALGO_SHA224] = HASH_ALGO_SHA224,
	[PGPHASHALGO_SHA256] = HASH_ALGO_SHA256,
	[PGPHASHALGO_SHA384] = HASH_ALGO_SHA384,
	[PGPHASHALGO_SHA512] = HASH_ALGO_SHA512,
};

rpmts ts;

int rpm_init(void)
{
	rpmVSFlags vsflags = 0;

	ts = rpmtsCreate();
	if (!ts) {
		_log("rpmtsCreate() error..\n");
		return -EACCES;
	}

	vsflags |= _RPMVSF_NODIGESTS;
	vsflags |= _RPMVSF_NOSIGNATURES;
	rpmtsSetVSFlags(ts, vsflags);
	return 0;
}

void rpm_fini(void)
{
	rpmtsFree(ts);
}

int rpm_parse(int map_fd, unsigned char cmd, char *path, bool only_immutable)
{
	const char *dirname, *filename;
	const unsigned char *rpm_digest;
	unsigned char digest[1 + MAX_DIGEST_SIZE] = { 0 };
	unsigned char digest_value = 0;
	Header hdr;
	FD_t fd;
	rpmRC rpm_ret;
	rpmfi fi;
	uint32_t size;
	uint16_t mode;
	int ret, algo, diglen;

	fd = Fopen(path, "r.ufdio");
	if ((!fd) || Ferror(fd)) {
		_log("Failed to open package file %s, %s\n", path,
		     Ferror(fd) ? Fstrerror(fd) : "");
		return -EACCES;
	}

	rpm_ret = rpmReadHeader(ts, fd, &hdr, NULL);
	if (rpm_ret != RPMRC_OK) {
		_log("Could not read package file %s\n", path);
		ret = -EINVAL;
		goto out_fd;
	}

	fi = rpmfiNew(NULL, hdr, RPMTAG_BASENAMES, RPMFI_FLAGS_QUERY);
	if (!fi) {
		_log("Unable to parse header\n");
		ret = -ENOMEM;
		goto out_hdr;
	}

	if (rpmfiFC(fi) == 0) {
		ret = 0;
		goto out_fi;
	}

	algo = rpmfiDigestAlgo(fi);
	diglen = rpmDigestLength(algo);

	if (diglen > MAX_DIGEST_SIZE) {
		ret = -EINVAL;
		goto out_fi;
	}

	while (rpmfiNext(fi) >= 0) {
		size = rpmfiFSize(fi);
		mode = rpmfiFMode(fi);
		dirname = rpmfiDN(fi);
		filename = rpmfiFN(fi);

		if (!S_ISREG(mode))
			continue;

		if (((mode & 0111) || !(mode & 0222)) && size)
			digest_value = INODE_ATTRIB_IMMUTABLE;

		if (!(digest_value & INODE_ATTRIB_IMMUTABLE) &&
		    ((strstr(dirname, "/lib/modules/") &&
		      strncmp(filename, "modules.", 8)) ||
		     strstr(dirname, "/lib/firmware") ||
		     strstr(dirname, "/usr/libexec/") ||
		     strstr(dirname, "/usr/lib64/") ||
		     strstr(dirname, "/lib64/")))
			digest_value = INODE_ATTRIB_IMMUTABLE;

		if (only_immutable && !(digest_value & INODE_ATTRIB_IMMUTABLE))
			continue;

		rpm_digest = rpmfiFDigest(fi, NULL, NULL);

		digest[0] = pgp_algo_mapping[algo];
		memcpy(digest + 1, rpm_digest, diglen);

		switch (cmd) {
		case CMD_ADD:
			ret = bpf_map_update_elem(map_fd, digest, &digest_value,
						  BPF_ANY);
			break;
		case CMD_DEL:
			ret = bpf_map_delete_elem(map_fd, digest);
			break;
		default:
			_log("Unknown command %d\n", cmd);
			ret = -EINVAL;
			break;
		}
	}

	ret = 0;
out_fi:
	rpmfiFree(fi);
out_hdr:
	headerFree(hdr);
out_fd:
	Fclose(fd);
	return ret;
}
