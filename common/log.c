// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the logging function.
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "common_user.h"

bool is_init;

void _log(char *fmt, ...)
{
	char msg_buf[1024] = "diglim_user: ";
	int msg_buf_len = strlen(msg_buf);
	int ret, len, fd_log;
	struct stat st;
	va_list ap;

	va_start(ap, fmt);

	if (!is_init) {
		vprintf(fmt, ap);
		return;
	}

	if (stat("/.kmsg", &st) == -1) {
		ret = mknod("/.kmsg", S_IFCHR | 0600, makedev(1, 11));
		if (ret == -1)
			return;
	}

	fd_log = open("/.kmsg", O_WRONLY);
	if (fd_log == -1)
		return;

	len = vsnprintf(msg_buf + msg_buf_len, sizeof(msg_buf) - msg_buf_len,
			fmt, ap);
	if (len < 0)
		goto out;

	len = write(fd_log, msg_buf, msg_buf_len + len + 1);
out:
	close(fd_log);
}
