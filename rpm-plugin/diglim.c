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
#include <rpm/rpmlog.h>
#include <rpm/rpmts.h>
#include <rpm/header.h>
#include <rpm/rpmpgp.h>
#include <rpm/rpmfileutil.h>
#include <rpm/rpmplugin.h>

#include "common.h"
#include "rpm-common.h"

static int process_digest_list(rpmte te, enum digest_list_ops op)
{
	static char rpm_digest_list_path[PATH_MAX] = DIGEST_LISTS_DEFAULT_PATH;
	struct stat st;
	int ret, server_ret;

	diglim_gen_filename(rpmteHeader(te),
		rpm_digest_list_path + sizeof(DIGEST_LISTS_DEFAULT_PATH) - 1,
		sizeof(rpm_digest_list_path) -
		sizeof(DIGEST_LISTS_DEFAULT_PATH) + 1);

	/* The rpm digest list has been already processed. */
	if ((op == CMD_ADD && !stat(rpm_digest_list_path, &st)) ||
	    (op == CMD_DEL && stat(rpm_digest_list_path, &st) == -1))
		return RPMRC_OK;

	if (op == CMD_DEL)
		goto do_op;

	ret = diglim_gen_rpm_digest_list(rpmteHeader(te), -1,
					 rpm_digest_list_path);
	if (ret)
		goto out;
do_op:
	ret = diglim_exec_op(rpm_digest_list_path, op, &server_ret);
	if (!ret)
		rpmlog(RPMLOG_DEBUG, "diglim_user returned: %d\n", server_ret);
out:
	if (ret < 0 || op == CMD_DEL)
		unlink(rpm_digest_list_path);

	return RPMRC_OK;
}

static rpmRC digest_list_psm_pre(rpmPlugin plugin, rpmte te)
{
	if (rpmteType(te) != TR_ADDED)
		return RPMRC_OK;

	return process_digest_list(te, CMD_ADD);
}

static rpmRC digest_list_psm_post(rpmPlugin plugin, rpmte te, int res)
{
	if (rpmteType(te) != TR_REMOVED)
		return RPMRC_OK;

	return process_digest_list(te, CMD_DEL);
}

struct rpmPluginHooks_s diglim_hooks = {
	.psm_pre = digest_list_psm_pre,
	.psm_post = digest_list_psm_post,
};
