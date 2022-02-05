/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common kernel definitions.
 */

#define MAX_DIGEST_SIZE	64
#define INODE_FLAG_CHECKED	0x01
#define INODE_FLAG_IMMUTABLE	0x02

enum lsm_modes { MODE_ENFORCING, MODE_PERMISSIVE };
