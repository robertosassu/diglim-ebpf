#!/usr/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# dracut script.

check() {
    return 255
}

depends() {
    return 0
}

install() {
    if [ ! -e /etc/digest_lists ]; then
        return 0
    fi

    if [ "$(find /etc/digest_lists)" = "/etc/digest_lists" ]; then
        return 0
    fi

    inst_dir /etc/digest_lists
    inst_multiple /etc/digest_lists/*
    inst_binary diglim_user_loader
    inst_binary diglim_user
    inst_binary diglim_log
    inst_binary sort
    inst_binary uniq
    inst_binary awk
    inst_binary mktemp
    inst_binary ls
    inst_binary diff
    inst_binary rm
    inst_hook pre-pivot 50 "$moddir/load_digest_lists.sh"
}
