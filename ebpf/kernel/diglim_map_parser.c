// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parser of the map digest list.
 */

#include "common_kern.h"

char _license[] SEC("license") = "GPL";

SEC("lsm.s/bpf")
int BPF_PROG(bpf_map, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct data *tmp;
	u32 zero = 0;
	int ret;

	if (cmd != BPF_MAP_UPDATE_ELEM)
		return 0;

	if (!bpf_map_same((struct bpf_map *)&data_input, attr->map_fd))
		return 0;

	tmp = bpf_map_lookup_elem((struct bpf_map *)&data_input, &zero);
	if (!tmp)
		return 0;

	if (tmp->size > sizeof(tmp->val))
		return 0;

	ret = bpf_mod_verify_sig(tmp->val, tmp->size);
	if (ret < 0)
		return 0;

	if (ret != 1 + MAX_DIGEST_SIZE)
		return 0;

	update_digest_items(tmp->val, COMPACT_FILE,
			    (1 << COMPACT_MOD_IMMUTABLE), tmp->op);
	return 0;
}
