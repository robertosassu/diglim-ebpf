// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Parser of the rpm digest list.
 */

#include "common_kern.h"
#include <string.h>
#include <errno.h>

char _license[] SEC("license") = "GPL";

typedef enum pgpHashAlgo_e {
	PGPHASHALGO_MD5             =  1,   /*!< MD5 */
	PGPHASHALGO_SHA1            =  2,   /*!< SHA1 */
	PGPHASHALGO_RIPEMD160       =  3,   /*!< RIPEMD160 */
	PGPHASHALGO_MD2             =  5,   /*!< MD2 */
	PGPHASHALGO_TIGER192        =  6,   /*!< TIGER192 */
	PGPHASHALGO_HAVAL_5_160     =  7,   /*!< HAVAL-5-160 */
	PGPHASHALGO_SHA256          =  8,   /*!< SHA256 */
	PGPHASHALGO_SHA384          =  9,   /*!< SHA384 */
	PGPHASHALGO_SHA512          = 10,   /*!< SHA512 */
	PGPHASHALGO_SHA224          = 11,   /*!< SHA224 */
} pgpHashAlgo;

unsigned char pgp_algo_mapping[PGPHASHALGO_SHA224 + 1] = {
	[PGPHASHALGO_MD5] = HASH_ALGO_MD5,
	[PGPHASHALGO_SHA1] = HASH_ALGO_SHA1,
	[PGPHASHALGO_RIPEMD160] = HASH_ALGO_RIPE_MD_160,
	[PGPHASHALGO_MD2] = HASH_ALGO__LAST,
	[PGPHASHALGO_TIGER192] = HASH_ALGO_TGR_192,
	[PGPHASHALGO_HAVAL_5_160] = HASH_ALGO__LAST,
	[PGPHASHALGO_SHA256] = HASH_ALGO_SHA256,
	[PGPHASHALGO_SHA384] = HASH_ALGO_SHA384,
	[PGPHASHALGO_SHA512] = HASH_ALGO_SHA512,
	[PGPHASHALGO_SHA224] = HASH_ALGO_SHA224,
};

typedef enum rpmTag_e {
	RPMTAG_FILESIZES		= 1028,	/* i[] */
	RPMTAG_FILEMODES		= 1030,	/* h[] */
	RPMTAG_FILEDIGESTS		= 1035,	/* s[] */
	RPMTAG_FILEDIGESTALGO		= 5011, /* i file digest algorithm */
	RPMTAG_DIRNAMES			= 1118,	/* s[] */
	RPMTAG_DIRINDEXES		= 1116,	/* i[] */
	RPMTAG_BASENAMES		= 1117,	/* s[] */
} rpmTag;

struct rpm_hdr {
	u32 magic;
	u32 reserved;
	u32 tags;
	u32 datasize;
} __attribute__((packed));

struct rpm_entryinfo {
	int32_t tag;
	u32 type;
	int32_t offset;
	u32 count;
} __attribute__((packed));

struct callback_ctx {
	/* in */
	enum ops op;
	struct rpm_entryinfo *cur_entry;
	u8 *datap;
	u8 *endp;
	/* out */
	u32 sizes_offset;
	u32 sizes_count;
	u32 modes_offset;
	u32 modes_count;
	u32 digests_offset;
	u32 digests_count;
	u32 algo_offset;
	u32 algo_count;
	u32 dirnames_offset;
	u32 dirnames_count;
	u32 dirnames_current;
	u32 dirindexes_offset;
	u32 dirindexes_count;
	u8 algo;
};

static __u64
clear_elem(struct bpf_map *map, __u32 *key, struct _path *path,
	   struct callback_ctx *data)
{
	path->val[0] = '\0';
	return 0;
}

static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

static int hex2bin(unsigned char *dst, const char *src, int count)
{
	while (count-- > 0) {
		int hi = hex_to_bin(*src++);
		int lo = hex_to_bin(*src++);

		if ((hi < 0) || (lo < 0))
			return -EINVAL;

		*dst++ = (hi << 4) | lo;
	}

	return 0;
}

static int process_algo(void *data)
{
	struct callback_ctx *ctx = data;
	u32 pgp_algo;

	if (ctx->algo_count == 0)
		return 0;

	if (ctx->datap + ctx->algo_offset + sizeof(u32) > ctx->endp)
		return 0;

	bpf_probe_read(&pgp_algo, sizeof(pgp_algo),
		       ctx->datap + ctx->algo_offset);

	pgp_algo = be32_to_cpu(pgp_algo);
	if (pgp_algo > PGPHASHALGO_SHA224 ||
	    pgp_algo_mapping[pgp_algo] >= HASH_ALGO__LAST)
		return 0;

	ctx->algo = pgp_algo_mapping[pgp_algo];
	return 0;
}

static int process_digest(struct callback_ctx *ctx, u8 *digest)
{
	char digest_str[MAX_DIGEST_SIZE * 2 + 1] = { 0 };
	u32 digest_len;
	int ret;

	if (ctx->digests_count == 0)
		return -ENOENT;

	if (ctx->datap + ctx->digests_offset + 2 > ctx->endp)
		return -EINVAL;

	ret = bpf_probe_read_str(digest_str, 2,
				 ctx->datap + ctx->digests_offset);
	if (ret < 0)
		return ret;

	if (digest_str[0] == '\0') {
		ctx->digests_offset++;
		return 1;
	}

	if (ctx->algo >= HASH_ALGO__LAST)
		return -EINVAL;

	digest_len = hash_digest_size[ctx->algo];
	if (digest_len > MAX_DIGEST_SIZE)
		return -EINVAL;

	if (ctx->datap + ctx->digests_offset + digest_len * 2 + 1 > ctx->endp)
		return -EINVAL;

	ret = bpf_probe_read_str(digest_str + 1, sizeof(digest_str) - 1,
				 ctx->datap + ctx->digests_offset + 1);
	if (ret < 0)
		return -EINVAL;

	digest[0] = ctx->algo;
	ret = hex2bin(digest + 1, digest_str, digest_len);
	ctx->digests_offset += digest_len * 2 + 1;
	return ret;
}

static int process_mode(struct callback_ctx *ctx, u16 *mode)
{
	if (ctx->datap + ctx->modes_offset + sizeof(*mode) > ctx->endp)
		return -EINVAL;

	bpf_probe_read(mode, sizeof(*mode), ctx->datap + ctx->modes_offset);
	*mode = be16_to_cpu(*mode);
	ctx->modes_offset += sizeof(*mode);
	return 0;
}

static int process_size(struct callback_ctx *ctx, u32 *size)
{
	if (ctx->datap + ctx->sizes_offset + sizeof(*size) > ctx->endp)
		return -EINVAL;

	bpf_probe_read(size, sizeof(*size), ctx->datap + ctx->sizes_offset);
	*size = be32_to_cpu(*size);
	ctx->sizes_offset += sizeof(*size);
	return 0;
}

static int process_dirindex(struct callback_ctx *ctx, u32 *dirindex)
{
	if (ctx->datap + ctx->dirindexes_offset + sizeof(*dirindex) > ctx->endp)
		return -EINVAL;

	bpf_probe_read(dirindex, sizeof(*dirindex),
		       ctx->datap + ctx->dirindexes_offset);

	*dirindex = be32_to_cpu(*dirindex);
	ctx->dirindexes_offset += sizeof(*dirindex);
	return 0;
}

static int process_file(u32 index, void *data)
{
	u8 digest[1 + MAX_DIGEST_SIZE] = { 0 };
	struct callback_ctx *ctx = data;
	u16 mode = 0;
	u32 size = 0;
	u32 dirindex = 0;
	struct _path *path;
	bool skip = false;
	int ret;

	ret = process_digest(ctx, digest);
	if (ret < 0)
		return 1;
	else if (ret == 1)
		skip = true;

	ret = process_mode(ctx, &mode);
	if (ret < 0)
		return 1;

	ret = process_size(ctx, &size);
	if (ret < 0)
		return 1;

	ret = process_dirindex(ctx, &dirindex);
	if (ret < 0)
		return 1;

	if (skip)
		return 0;

	if (!((mode & S_IXUGO) || !(mode & S_IWUGO)) || !size) {
		path = bpf_map_lookup_elem(&dirnames_map, &dirindex);
		if (!path || path->val[0] == '\0')
			return 0;
	}

	update_digest_items(digest, COMPACT_FILE, (1 << COMPACT_MOD_IMMUTABLE),
			    ctx->op);
	return 0;
}

static int process_dirnames(__u32 index, void *data)
{
	struct callback_ctx *ctx = data;
	struct _path *path;
	int ret;

	if (ctx->dirnames_count == 0)
		return 1;

	path = bpf_map_lookup_elem(&dirnames_map, &ctx->dirnames_current);
	if (!path)
		return 1;

	ret = bpf_probe_read_str(path->val, sizeof(path->val),
				 ctx->datap + ctx->dirnames_offset);
	if (ret < 0)
		return 1;

	if (bpf_strncmp(path->val, sizeof(LIB_FIRMWARE_PATH) - 1,
			LIB_FIRMWARE_PATH) &&
	    bpf_strncmp(path->val, sizeof(USR_LIB_FIRMWARE_PATH) - 1,
			USR_LIB_FIRMWARE_PATH) &&
	    bpf_strncmp(path->val, sizeof(LIB_MODULES_PATH) - 1,
			LIB_MODULES_PATH) &&
	    bpf_strncmp(path->val, sizeof(USR_LIB_MODULES_PATH) - 1,
			USR_LIB_MODULES_PATH) &&
	    bpf_strncmp(path->val, sizeof(USR_LIB64_PATH) - 1,
			USR_LIB64_PATH))
		path->val[0] = '\0';

	ctx->dirnames_offset += ret;
	ctx->dirnames_current++;
	return 0;
}

static int parse_rpm_header(__u32 index, void *data)
{
	struct callback_ctx *ctx = data;
	u32 count = be32_to_cpu(ctx->cur_entry->count);
	u32 offset = be32_to_cpu(ctx->cur_entry->offset);
	u32 tag = be32_to_cpu(ctx->cur_entry->tag);

	switch (tag) {
	case RPMTAG_FILESIZES:
		ctx->sizes_offset = offset;
		ctx->sizes_count = count;
		break;
	case RPMTAG_FILEMODES:
		ctx->modes_offset = offset;
		ctx->modes_count = count;
		break;
	case RPMTAG_FILEDIGESTS:
		ctx->digests_offset = offset;
		ctx->digests_count = count;
		break;
	case RPMTAG_FILEDIGESTALGO:
		ctx->algo_offset = offset;
		ctx->algo_count = 1;
		break;
	case RPMTAG_DIRNAMES:
		ctx->dirnames_offset = offset;
		ctx->dirnames_count = count;
		ctx->dirnames_current = 0;
		break;
	case RPMTAG_DIRINDEXES:
		ctx->dirindexes_offset = offset;
		ctx->dirindexes_count = count;
		break;
	default:
		break;
	}

	ctx->cur_entry++;
	return 0;
}

SEC("lsm.s/bpf")
int BPF_PROG(bpf_rpm, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct callback_ctx _ctx;
	struct rpm_hdr *hdr;
	u32 num_tags;
	struct data *tmp;
	u32 zero = 0;
	u32 entry_len;
	size_t tmp_size;
	int ret, i;

	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};

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

	tmp_size = ret;

	if (tmp_size < sizeof(*hdr))
		return 0;

	hdr = (struct rpm_hdr *)tmp->val;

	for (i = 0; i < sizeof(rpm_header_magic); i++)
		if (((u8 *)(hdr))[i] != rpm_header_magic[i])
			return 0;

	num_tags = be32_to_cpu(hdr->tags);
	entry_len = num_tags * sizeof(struct rpm_entryinfo);

	if (tmp_size < sizeof(*hdr) + entry_len)
		return 0;

	memset(&_ctx, 0, sizeof(_ctx));
	_ctx.cur_entry = (struct rpm_entryinfo *)((void *)hdr + sizeof(*hdr));
	_ctx.datap = (u8 *)_ctx.cur_entry + entry_len;
	_ctx.endp = tmp->val + tmp_size;
	_ctx.op = tmp->op;

	bpf_loop(num_tags, parse_rpm_header, &_ctx, 0);

	_ctx.algo = HASH_ALGO_MD5;
	process_algo(&_ctx);

	bpf_loop(_ctx.dirnames_count, process_dirnames, &_ctx, 0);
	bpf_loop(_ctx.digests_count, process_file, &_ctx, 0);

	bpf_for_each_map_elem(&dirnames_map, clear_elem, NULL, 0);
	return 0;
}
