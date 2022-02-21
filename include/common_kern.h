/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common kernel definitions.
 */

#define MAX_DIGEST_SIZE	64

/* Inode state flags. */
#define INODE_STATE_CHECKED		0x01
#define INODE_STATE_MMAP_EXEC_ALLOWED	0x02

/* Inode attrib flags. */
#define INODE_ATTRIB_IMMUTABLE		0x01

enum lsm_modes { MODE_ENFORCING, MODE_PERMISSIVE };
