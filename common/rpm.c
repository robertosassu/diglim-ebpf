// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generate RPM digest lists.
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#include <limits.h>
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmtag.h>

#include "common.h"

void diglim_gen_filename(Header rpm, char *filename, int filename_len)
{
	rpmtd name = rpmtdNew(), version = rpmtdNew();
	rpmtd release = rpmtdNew(), arch = rpmtdNew();

	headerGet(rpm, RPMTAG_NAME, name, 0);
	headerGet(rpm, RPMTAG_VERSION, version, 0);
	headerGet(rpm, RPMTAG_RELEASE, release, 0);
	headerGet(rpm, RPMTAG_ARCH, arch, 0);

	snprintf(filename, filename_len, "0-file_list-rpm-%s-%s-%s.%s",
		 rpmtdGetString(name), rpmtdGetString(version),
		 rpmtdGetString(release), rpmtdGetString(arch));

	rpmtdFree(name);
	rpmtdFree(version);
	rpmtdFree(release);
	rpmtdFree(arch);
}

static int write_rpm_header(Header rpm, int dirfd, char *filename)
{
	rpmtd immutable;
	ssize_t ret;
	int fd;

	fd = openat(dirfd, filename, O_WRONLY | O_CREAT | O_TRUNC | O_SYNC, 0644);
	if (fd < 0)
		return -EACCES;

	ret = write(fd, rpm_header_magic, sizeof(rpm_header_magic));
	if (ret != sizeof(rpm_header_magic)) {
		ret = -EIO;
		goto out;
	}

	immutable = rpmtdNew();
	headerGet(rpm, RPMTAG_HEADERIMMUTABLE, immutable, 0);
	ret = write(fd, immutable->data, immutable->count);
	if (ret != immutable->count) {
		ret = -EIO;
		goto out;
	}

	rpmtdFree(immutable);
out:
	close(fd);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}

static int write_rpm_header_signature(Header rpm, int dirfd, char *filename)
{
	struct module_signature modsig = { 0 };
	rpmtd signature = rpmtdNew();
	int ret, fd;

	headerGet(rpm, RPMTAG_RSAHEADER, signature, 0);
	fd = openat(dirfd, filename, O_WRONLY | O_APPEND);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	modsig.id_type = PKEY_ID_PGP;
	modsig.sig_len = signature->count;
	modsig.sig_len = __cpu_to_be32(modsig.sig_len);

	ret = write(fd, signature->data, signature->count);
	if (ret != signature->count) {
		ret = -EIO;
		goto out_fd;
	}

	ret = write(fd, &modsig, sizeof(modsig));
	if (ret != sizeof(modsig)) {
		ret = -EIO;
		goto out_fd;
	}

	ret = write(fd, MODULE_SIG_STRING, sizeof(MODULE_SIG_STRING) - 1);
	if (ret != sizeof(MODULE_SIG_STRING) - 1) {
		ret = -EIO;
		goto out;
	}

	ret = 0;
out_fd:
	close(fd);
out:
	rpmtdFree(signature);

	if (ret < 0)
		unlinkat(dirfd, filename, 0);

	return ret;
}

int diglim_gen_rpm_digest_list(Header rpm, int dirfd, char *filename)
{
	int ret;

	ret = write_rpm_header(rpm, dirfd, filename);
	if (ret < 0) {
		printf("Cannot generate %s digest list\n", filename);
		return ret;
	}

	ret = write_rpm_header_signature(rpm, dirfd, filename);
	if (ret < 0)
		printf("Cannot add signature to %s digest list\n",
		       filename);

	return ret;
}
