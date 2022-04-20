// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parser of the compact digest list.
 */

#include "common_kern.h"

char _license[] SEC("license") = "GPL";

struct callback_ctx {
	u8 *buf;
	u32 digest_len;
	struct compact_list_hdr *hdr;
	enum ops op;
};

static int callback(__u32 index, void *data)
{
	u8 digest[1 + MAX_DIGEST_SIZE] = { 0 };
	struct callback_ctx *ctx = data;
	int i;

	digest[0] = ctx->hdr->algo;
	for (i = 0; i < MAX_DIGEST_SIZE && i < ctx->digest_len; i++)
		digest[i + 1] = ctx->buf[i];

	update_digest_items(digest, ctx->hdr->type, ctx->hdr->modifiers,
			    ctx->op);

	ctx->buf += ctx->digest_len;
	return 0;
}

static int digest_list_parse(u32 size, u8 *buf, enum ops op)
{
	struct compact_list_hdr hdr;
	u32 digest_len;
	struct callback_ctx ctx;

	if (size < sizeof(hdr))
		return 0;

	bpf_probe_read(&hdr, sizeof(hdr), buf);

	hdr.type = le16_to_cpu(hdr.type);
	hdr.modifiers = le16_to_cpu(hdr.modifiers);
	hdr.algo = le16_to_cpu(hdr.algo);
	hdr.count = le32_to_cpu(hdr.count);
	hdr.datalen = le32_to_cpu(hdr.datalen);

	size -= sizeof(hdr);
	buf += sizeof(hdr);

	if (hdr.algo >= HASH_ALGO__LAST)
		return -EINVAL;

	digest_len = hash_digest_size[hdr.algo];

	if (size < hdr.count * digest_len)
		return 0;

	ctx.buf = buf;
	ctx.digest_len = digest_len;
	ctx.hdr = &hdr;
	ctx.op = op;

	bpf_loop(hdr.count, callback, &ctx, 0);
	size -= hdr.count * digest_len;
	return size;
}

struct callback_block_ctx {
	u8 *buf;
	u32 size;
	enum ops op;
};

static int callback_block(__u32 index, void *data)
{
	struct callback_block_ctx *ctx = data;
	int ret;

	ret = digest_list_parse(ctx->size, ctx->buf, ctx->op);
	if (ret <= 0)
		return 1;

	ctx->size -= ret;
	ctx->buf += ret;
	return 0;
}

SEC("lsm.s/bpf")
int BPF_PROG(bpf_compact, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct callback_block_ctx _ctx;
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

	_ctx.buf = tmp->val;
	_ctx.size = ret;
	_ctx.op = tmp->op;

	bpf_loop(MAX_NUM_BLOCKS, callback_block, &_ctx, 0);
	return 0;
}
