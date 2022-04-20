/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Header of libbpf.c.
 */
#ifndef __LIBBPF_LIBBPF_H
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <syscall.h>

#define ptr_to_u64(ptr)    ((__u64)(unsigned long)(ptr))

int bpf_map_get_next_id(__u32 start_id, __u32 *next_id);
int bpf_map_get_fd_by_id(__u32 id);
int bpf_obj_get_info_by_fd(int bpf_fd, void *info, __u32 *info_len);
int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags);
#endif /*__LIBBPF_LIBBPF_H*/
