/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * Common user space definitions.
 */

#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>
#ifdef __BIG_ENDIAN__
#include <linux/byteorder/big_endian.h>
#else
#include <linux/byteorder/little_endian.h>
#endif
#include <asm/bitsperlong.h>
#include <linux/hash_info.h>

#include "common.h"

/* hash_info.c */
extern const char *const hash_algo_name[HASH_ALGO__LAST];
extern const int hash_digest_size[HASH_ALGO__LAST];

/* hexdump.c */
int hex2bin(unsigned char *dst, const char *src, size_t count);
char *bin2hex(char *dst, const void *src, size_t count);

/* lib.c */
int diglim_read_file(const char *path, size_t *len, unsigned char **data);
int diglim_find_map(const char *map_name);

/* compact.c */
int diglim_calc_digest(u8 *digest, void *data, u64 len, enum hash_algo algo);
int diglim_calc_file_digest(u8 *digest, char *path, enum hash_algo algo);
extern char *compact_types_str[COMPACT__LAST];
int gen_filename_prefix(char *filename, int filename_len, int pos,
			const char *format, enum compact_types type);

/* log.c */
extern bool is_init;
void _log(char *fmt, ...);

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
