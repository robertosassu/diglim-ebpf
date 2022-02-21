// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Implement the compact parser.
 */

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "common.h"

static int digest_list_validate(loff_t size, unsigned char *buf)
{
	unsigned char *bufp = buf, *bufendp = buf + size;
	struct compact_list_hdr *hdr;
	size_t digest_len;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			_log("Insufficient data\n");
			return -EINVAL;
		}

		hdr = (struct compact_list_hdr *)bufp;

		if (hdr->version != 1) {
			_log("Unsupported version\n");
			return -EINVAL;
		}

		if (hdr->_reserved != 0) {
			_log("Unexpected value for _reserved field\n");
			return -EINVAL;
		}

		hdr->type = le16_to_cpu(hdr->type);
		hdr->modifiers = le16_to_cpu(hdr->modifiers);
		hdr->algo = le16_to_cpu(hdr->algo);
		hdr->count = le32_to_cpu(hdr->count);
		hdr->datalen = le32_to_cpu(hdr->datalen);

		if (hdr->algo >= HASH_ALGO__LAST) {
			_log("Invalid hash algorithm\n");
			return -EINVAL;
		}

		digest_len = hash_digest_size[hdr->algo];

		if (hdr->type >= COMPACT__LAST ||
		    hdr->type == COMPACT_DIGEST_LIST) {
			_log("Invalid type %d\n", hdr->type);
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		if (hdr->datalen != hdr->count * digest_len ||
		    bufp + hdr->datalen > bufendp) {
			_log("Invalid data\n");
			return -EINVAL;
		}

		bufp += hdr->count * digest_len;
	}

	return 0;
}


int compact_init(void)
{
	return 0;
}

void compact_fini(void)
{
}

int compact_parse(int map_fd, unsigned char cmd, char *path,
		  bool only_immutable)
{
	struct compact_list_hdr *hdr;
	size_t digest_len;
	unsigned char digest[1 + MAX_DIGEST_SIZE];
	unsigned char digest_value;
	unsigned char *buf, *bufp, *bufendp;
	struct stat st;
	int ret, i, fd;

	if (stat(path, &st) == -1)
		return -errno;

	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	buf = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd,
		   0);
	if (buf == MAP_FAILED) {
		ret = -ENOMEM;
		goto out;
	}

	ret = digest_list_validate(st.st_size, buf);
	if (ret < 0) {
		_log("Invalid digest list %s\n", path);
		goto out_munmap;
	}

	bufp = buf;
	bufendp = buf + st.st_size;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp)
			break;

		hdr = (struct compact_list_hdr *)bufp;
		bufp += sizeof(*hdr);

		digest_len = hash_digest_size[hdr->algo];
		digest_value = (hdr->modifiers & (1 << COMPACT_MOD_IMMUTABLE)) ?
			       INODE_ATTRIB_IMMUTABLE : 0;

		for (i = 0; i < hdr->count && bufp + digest_len <= bufendp;
		     i++, bufp += digest_len) {
			memset(digest, 0, sizeof(digest));

			digest[0] = hdr->algo;
			memcpy(digest + 1, bufp, digest_len);

			switch (cmd) {
			case CMD_ADD:
				ret = bpf_map_update_elem(map_fd, digest,
							  &digest_value,
							  BPF_ANY);
				break;
			case CMD_DEL:
				ret = bpf_map_delete_elem(map_fd, digest);
				break;
			default:
				_log("Unknown command %d\n", cmd);
				ret = -EINVAL;
				break;
			}
		}
	}

out_munmap:
	munmap(buf, st.st_size);
out:
	close(fd);
	return ret;
}
