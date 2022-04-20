// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Generator of rpm digest lists.
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

#include "common_user.h"
#include "rpm-common.h"

static int find_package(Header rpm, char *package)
{
	rpmtd name = rpmtdNew();
	int found = 0;

	headerGet(rpm, RPMTAG_NAME, name, 0);
	if (!strncmp(rpmtdGetString(name), package, strlen(package)))
		found = 1;

	rpmtdFree(name);
	return found;
}

static void usage(char *progname)
{
	printf("Usage: %s <options>\n", progname);
	printf("Options:\n");
	printf("\t-d <output directory>: directory digest lists are written to\n"
	       "\t-r <RPM path>: RPM package the digest list is generated from (all RPM packages in DB if not specified)\n"
	       "\t-p <package>: selected RPM package in RPM DB\n"
	       "\t-h: display help\n");
}

int main(int argc, char *argv[])
{
	char filename[NAME_MAX + 1];
	rpmts ts = NULL;
	Header hdr;
	FD_t fd;
	rpmdbMatchIterator mi;
	rpmVSFlags vsflags = 0;
	char *input_package = NULL, *selected_package = NULL;
	char *output_dir = NULL;
	struct stat st;
	int c;
	int ret, dirfd;

	while ((c = getopt(argc, argv, "d:r:p:h")) != -1) {
		switch (c) {
		case 'd':
			output_dir = optarg;
			break;
		case 'r':
			input_package = optarg;
			break;
		case 'p':
			selected_package = optarg;
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

	if (stat(output_dir, &st) == -1)
		mkdir(output_dir, 0755);

	dirfd = open(output_dir, O_RDONLY | O_DIRECTORY);
	if (dirfd < 0) {
		printf("Unable to open %s, ret: %d\n", output_dir, -errno);
		ret = -errno;
		goto out;
	}

	ts = rpmtsCreate();
	if (!ts) {
		rpmlog(RPMLOG_NOTICE, "rpmtsCreate() error..\n");
		ret = -EACCES;
		goto out;
	}

	ret = rpmReadConfigFiles(NULL, NULL);
	if (ret != RPMRC_OK) {
		rpmlog(RPMLOG_NOTICE, "Unable to read RPM configuration.\n");
		ret = -EACCES;
		goto out;
	}

	if (input_package) {
		vsflags |= _RPMVSF_NODIGESTS;
		vsflags |= _RPMVSF_NOSIGNATURES;
		rpmtsSetVSFlags(ts, vsflags);

		fd = Fopen(input_package, "r.ufdio");
		if ((!fd) || Ferror(fd)) {
			rpmlog(RPMLOG_NOTICE,
			       "Failed to open package file %s, %s\n",
			       input_package, Fstrerror(fd));
			ret = -EACCES;
			goto out_rpm;
		}

		ret = rpmReadPackageFile(ts, fd, "rpm", &hdr);
		Fclose(fd);

		if (ret != RPMRC_OK) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not read package file %s\n",
			       input_package);
			goto out_rpm;
		}

		ret = diglim_gen_filename(hdr, filename, sizeof(filename));
		if (ret < 0) {
			rpmlog(RPMLOG_NOTICE,
			       "Could not generate digest list file name\n");
			goto out_rpm;
		}

		ret = diglim_gen_rpm_digest_list(hdr, dirfd, filename);
		headerFree(hdr);
		goto out_rpm;
	}

	mi = rpmtsInitIterator(ts, RPMDBI_PACKAGES, NULL, 0);
	while ((hdr = rpmdbNextIterator(mi)) != NULL) {
		diglim_gen_filename(hdr, filename, sizeof(filename));

		if (strstr(filename, "gpg-pubkey") != NULL)
			continue;

		if (selected_package && !find_package(hdr, selected_package))
			continue;

		ret = diglim_gen_rpm_digest_list(hdr, dirfd, filename);
		if (ret < 0)
			break;
	}

	rpmdbFreeIterator(mi);
out_rpm:
	rpmFreeRpmrc();
	rpmtsFree(ts);
out:
	close(dirfd);
	return ret;
}
