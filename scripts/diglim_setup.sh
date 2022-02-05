#! /bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# Configure DIGLIM eBPF.

ask=1

function usage()
{
	echo "Syntax: $0 install/uninstall [--default]"
	exit 1
}

function question()
{
	answer="$2"
	choice="[y/n]"
	echo -n "$1 ${choice/$2/${2^^}} "
	if [ $ask -eq 1 ]; then
		read _answer
		if [ -n "$_answer" ]; then
			answer=$_answer
		fi
	else
		echo
	fi
}

function install()
{
	question "Use DIGLIM as init for the boot?" "y"
	if [ $answer = "y" ]; then
		grubby --update-kernel=/boot/vmlinuz-$(uname -r) \
		        --args="rdinit=/sbin/diglim_user"
	fi

	question "Automatically add diglim module to the initial ram disk?" "y"
	if [ $answer = "y" ]; then
		echo "add_dracutmodules+=\" diglim \"" > \
			/etc/dracut.conf.d/diglim_add_module.conf
	fi

	question "Generate digest lists?" "y"
	if [ $answer = "y" ]; then
		rpm_gen -d /etc/digest_lists
		zero_page_file=$(mktemp)
		dd if=/dev/zero of=$zero_page_file bs=4096 count=1 &> /dev/null
		compact_gen -d /etc/digest_lists -i $zero_page_file
		rm $zero_page_file
	fi

	question "Generate digest list for built kernel modules?" "n"
	if [ $answer = "y" ]; then
		compact_gen -d /etc/digest_lists -i /lib/modules/`uname -r`
	fi

	question "Generate digest lists for built DIGLIM eBPF?" "n"
	if [ $answer = "y" ]; then
		compact_gen -d /etc/digest_lists/ -i /usr/lib64/diglim-parsers
		compact_gen -d /etc/digest_lists/ -i /usr/sbin/diglim_user
		compact_gen -d /etc/digest_lists/ -i /usr/bin/diglim_user_client
		compact_gen -d /etc/digest_lists/ -i /usr/bin/compact_gen
		compact_gen -d /etc/digest_lists/ -i /usr/bin/rpm_gen
		compact_gen -d /etc/digest_lists/ -i /usr/lib64/libdiglimrpm.so
		compact_gen -d /etc/digest_lists/ -i /usr/lib64/libdiglim.so
		compact_gen -d /etc/digest_lists/ \
			    -i /usr/lib64/rpm-plugins/diglim.so
		compact_gen -d /etc/digest_lists/ -i /usr/bin/diglim_setup.sh
	fi

	question "Enable diglim rpm plugin?" "y"
	if [ $answer = "y" ]; then
		echo "%__transaction_diglim %{__plugindir}/diglim.so" > \
			/usr/lib/rpm/macros.d/macros.diglim
	fi

	question "Enable diglim_user systemd service at boot?" "y"
	if [ $answer = "y" ]; then
		systemctl enable diglim_user.service
	fi

	question "Regenerate the initial ram disk?" "y"
	if [ $answer = "y" ]; then
		dracut -f
	fi
}

function uninstall()
{
	question "Use default init at boot?" "y"
	if [ $answer = "y" ]; then
		grubby --update-kernel=/boot/vmlinuz-$(uname -r) \
		       --remove-args="rdinit=/sbin/diglim_user"
	fi

	question "Stop adding the diglim module to the initial ram disk?" "y"
	if [ $answer = "y" ]; then
		rm -f /etc/dracut.conf.d/diglim_add_module.conf
	fi

	question "Remove ALL generated digest lists?" "y"
	if [ $answer = "y" ]; then
		rm -Rf /etc/digest_lists
	fi

	question "Disable diglim rpm plugin?" "y"
	if [ $answer = "y" ]; then
		rm /usr/lib/rpm/macros.d/macros.diglim
	fi

	question "Disable diglim_user systemd service at boot?" "y"
	if [ $answer = "y" ]; then
		systemctl disable diglim_user.service
	fi

	question "Regenerate the initial ram disk?" "y"
	if [ $answer = "y" ]; then
		dracut -f
	fi
}

if [ $# -lt 1 ]; then
	usage
fi

if [ "$1" != "install" ] && [ "$1" != "uninstall" ]; then
	usage
fi

if [ "$2" = "--default" ]; then
	ask=0
fi

$1
