/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common functions and definitions.
 */

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#ifdef __BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif
#include <asm/bitsperlong.h>
#include <linux/hash_info.h>

#include "common_kern.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
#ifndef bool
typedef int bool;
#endif

#define be32_to_cpu __be32_to_cpu
#define be16_to_cpu __be16_to_cpu
#define cpu_to_be32 __cpu_to_be32
#define cpu_to_be16 __cpu_to_be16
#define le16_to_cpu __le16_to_cpu
#define le32_to_cpu __le32_to_cpu
#define le64_to_cpu __le64_to_cpu
#define cpu_to_le16 __cpu_to_le16
#define cpu_to_le32 __cpu_to_le32
#define cpu_to_le64 __cpu_to_le64

#define DIGEST_LISTS_DEFAULT_PATH "/etc/digest_lists/"
#define PARSER_DIR LIBDIR "/diglim-parsers/"

#define SYSFS_PATH "/sys/"
#define BPFFS_PATH SYSFS_PATH "fs/bpf/"
#define SECURITYFS_PATH SYSFS_PATH "kernel/security/"
#define DIGLIM_BPFFS_PATH BPFFS_PATH "diglim/"
#define DEBUGFS_PATH SYSFS_PATH "kernel/debug/"
#define DIGEST_ITEMS_MAP_NAME "digest_items"
#define DIGEST_ITEMS_MAP_PATH (DIGLIM_BPFFS_PATH DIGEST_ITEMS_MAP_NAME)
#define RINGBUF_NAME "ringbuf"
#define RINGBUF_PATH (DIGLIM_BPFFS_PATH RINGBUF_NAME)
#define DIGLIM_IMA_POLICY_PATH "/usr/share/diglim-ebpf/ima-policy"
#define IMA_POLICY_PATH SECURITYFS_PATH "ima/policy"

/* parsers.c */
typedef int (*init_parser)(void);
typedef void (*fini_parser)(void);
typedef int (*parse_digest_list)(int map_fd, unsigned char cmd,
				 char *path, bool only_immutable);

struct parser {
	char name[256];
	init_parser init_func;
	fini_parser fini_func;
	parse_digest_list parse_func;
	void *handle;
	struct parser *next;
};

enum digest_list_ops { CMD_ADD, CMD_DEL, CMD__LAST };

int diglim_init_parsers(void);
void diglim_fini_parsers(void);
int diglim_parse_digest_list(int map_fd, unsigned char cmd, char *path,
			     bool only_immutable);

/* clientserver.c */
int diglim_main_loop(int map_fd, bool only_immutable,
		     struct ring_buffer *ringbuf);
int diglim_exec_op(char *path, enum digest_list_ops op, int *server_ret);

/* Compact list definitions */
#define COMPACT_LIST_SIZE_MAX (64 * 1024 * 1024 - 1)

enum compact_types { COMPACT_PARSER, COMPACT_FILE, COMPACT_METADATA,
		     COMPACT_DIGEST_LIST, COMPACT__LAST };

enum compact_modifiers { COMPACT_MOD_IMMUTABLE, COMPACT_MOD__LAST };

struct compact_list_hdr {
	__u8 version;
	__u8 _reserved;
	__le16 type;
	__le16 modifiers;
	__le16 algo;
	__le32 count;
	__le32 datalen;
} __attribute((packed));

/* hexdump.c */
int hex2bin(unsigned char *dst, const char *src, size_t count);
char *bin2hex(char *dst, const void *src, size_t count);

/* log.c */
extern bool is_init;

void _log(char *fmt, ...);

/* hash_info.c */
#define MD5_DIGEST_SIZE 16
#define SHA1_DIGEST_SIZE 20
#define RMD160_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32
#define SHA384_DIGEST_SIZE 48
#define SHA512_DIGEST_SIZE 64
#define SHA224_DIGEST_SIZE 28
#define RMD128_DIGEST_SIZE 16
#define RMD256_DIGEST_SIZE 32
#define RMD320_DIGEST_SIZE 40
#define WP256_DIGEST_SIZE 32
#define WP384_DIGEST_SIZE 48
#define WP512_DIGEST_SIZE 64
#define TGR128_DIGEST_SIZE 16
#define TGR160_DIGEST_SIZE 20
#define TGR192_DIGEST_SIZE 24
#define SM3256_DIGEST_SIZE 32
#define STREEBOG256_DIGEST_SIZE 32
#define STREEBOG512_DIGEST_SIZE 64

extern const char *const hash_algo_name[HASH_ALGO__LAST];
extern const int hash_digest_size[HASH_ALGO__LAST];

/* module_signature.h (from Linux kernel) */

/* In stripped ARM and x86-64 modules, ~ is surprisingly rare. */
#define MODULE_SIG_STRING "~Module signature appended~\n"

enum pkey_id_type {
	PKEY_ID_PGP,		/* OpenPGP generated key ID */
	PKEY_ID_X509,		/* X.509 arbitrary subjectKeyIdentifier */
	PKEY_ID_PKCS7,		/* Signature in PKCS#7 message */
};

/*
 * Module signature information block.
 *
 * The constituents of the signature section are, in order:
 *
 *	- Signer's name
 *	- Key identifier
 *	- Signature data
 *	- Information block
 */
struct module_signature {
	u8	algo;		/* Public-key crypto algorithm [0] */
	u8	hash;		/* Digest algorithm [0] */
	u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
	u8	signer_len;	/* Length of signer's name [0] */
	u8	key_id_len;	/* Length of key identifier [0] */
	u8	__pad[3];
	__be32	sig_len;	/* Length of signature data */
};
