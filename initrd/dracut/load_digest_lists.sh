#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# Load remaining digest lists from the new root.

if [ ! -S /run/diglim/diglim_sock ]; then
	exit 0
fi

a=$(mktemp)
b=$(mktemp)

ls /etc/digest_lists | sort | uniq > $a
ls $NEWROOT/etc/digest_lists | sort | uniq > $b

for f in $(diff -up $a $b | awk '$1 ~ /^\+[0-9].*/'); do
	diglim_user_client -o add -p $NEWROOT/etc/digest_lists/${f#+}
done

rm -f $a $b
