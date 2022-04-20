// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Plugin to update digests loaded by DIGLIM.
 */

#include <errno.h>
#include <limits.h>
#include <sys/wait.h>
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include <rpm/header.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmfileutil.h>

#include "rpmplugin.h"
#include "common_user.h"
#include "rpm-common.h"

static int process_digest_list(rpmte te, enum ops op)
{
	static char rpm_digest_list_path[PATH_MAX] = DIGEST_LISTS_DEFAULT_PATH;
	struct stat st;
	int ret, fd, status;

	ret = diglim_gen_filename(rpmteHeader(te),
		rpm_digest_list_path + sizeof(DIGEST_LISTS_DEFAULT_PATH) - 1,
		sizeof(rpm_digest_list_path) -
		sizeof(DIGEST_LISTS_DEFAULT_PATH) + 1);
	if (ret < 0) {
		rpmlog(RPMLOG_DEBUG,
		       "Could not generate digest list file name\n");
		return RPMRC_OK;
	}

	/* The rpm digest list has been already processed. */
	if ((op == DIGEST_LIST_ADD && !stat(rpm_digest_list_path, &st)) ||
	    (op == DIGEST_LIST_DEL && stat(rpm_digest_list_path, &st) == -1))
		return RPMRC_OK;

	if (op == DIGEST_LIST_DEL)
		goto do_op;

	ret = diglim_gen_rpm_digest_list(rpmteHeader(te), -1,
					 rpm_digest_list_path);
	if (ret)
		goto out;
do_op:
	fd = diglim_find_map("data_input");
	if (fd < 0)
		return RPMRC_OK;

	if (fork() == 0)
		return execlp(DIGEST_LIST_LOADER_PATH, DIGEST_LIST_LOADER_PATH,
			      "-o", op == DIGEST_LIST_ADD ? "add" : "del", "-d",
			      rpm_digest_list_path, NULL);
	wait(&status);

	rpmlog(RPMLOG_DEBUG, "%s returned: %d\n", DIGEST_LIST_LOADER_PATH,
	       WEXITSTATUS(status));
out:
	if (ret < 0 || op == DIGEST_LIST_DEL)
		unlink(rpm_digest_list_path);

	return RPMRC_OK;
}

static rpmRC digest_list_psm_pre(rpmPlugin plugin, rpmte te)
{
	if (rpmteType(te) != TR_ADDED)
		return RPMRC_OK;

	return process_digest_list(te, DIGEST_LIST_ADD);
}

static rpmRC digest_list_psm_post(rpmPlugin plugin, rpmte te, int res)
{
	if (rpmteType(te) != TR_REMOVED)
		return RPMRC_OK;

	return process_digest_list(te, DIGEST_LIST_DEL);
}

struct rpmPluginHooks_s diglim_hooks = {
	.psm_pre = digest_list_psm_pre,
	.psm_post = digest_list_psm_post,
};
