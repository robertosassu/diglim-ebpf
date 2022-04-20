#! /bin/bash
# SPDX-License-Identifier: GPL-2.0-only
#
# Copyright (C) 2022 Huawei Technologies Duesseldorf GmbH
#
# Author: Roberto Sassu <roberto.sassu@huawei.com>
#
# Script to configure DIGLIM eBPF.

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
	fi

	question "Generate digest list for built kernel modules?" "n"
	if [ $answer = "y" ]; then
		compact_gen -d /etc/digest_lists -i /lib/modules/`uname -r`
	fi

	question "Generate digest list for diglim_user_loader?" "n"
	if [ $answer = "y" ]; then
		map_gen -d /etc/digest_lists/ -i /usr/bin/diglim_user_loader
	fi

	question "Generate digest lists for built DIGLIM eBPF?" "n"
	if [ $answer = "y" ]; then
		compact_gen -d /etc/digest_lists/ -i /usr/sbin/diglim_user
		compact_gen -d /etc/digest_lists/ -i /usr/bin/diglim_log
		compact_gen -d /etc/digest_lists/ -i /usr/bin/compact_gen
		compact_gen -d /etc/digest_lists/ -i /usr/bin/rpm_gen
		compact_gen -d /etc/digest_lists/ -i /usr/bin/map_gen
		compact_gen -d /etc/digest_lists/ -i /usr/lib64/libdiglimrpm.so
		compact_gen -d /etc/digest_lists/ -i /usr/lib64/libdiglim.so
		compact_gen -d /etc/digest_lists/ \
			    -i /usr/lib64/rpm-plugins/diglim.so
		compact_gen -d /etc/digest_lists/ -i /usr/bin/diglim_setup.sh
	fi

	question "Sign generated digest lists?" "n"
	if [ $answer = "y" ]; then
		default_dir=$(readlink /lib/modules/`uname -r`/build)
		echo -n "Enter kernel source directory: [$default_dir]"
		read kernel_source_dir

		if [ -z "$kernel_source_dir" ]; then
			kernel_source_dir=$default_dir
		fi

		if [ ! -d "$kernel_source_dir" ]; then
			echo "Invalid directory"
		else
			for f in $(find /etc/digest_lists/ -name \
						"0-file_list-compact-*"); do
				$kernel_source_dir/scripts/sign-file sha256 \
				  $kernel_source_dir/certs/signing_key.pem \
				  $kernel_source_dir/certs/signing_key.pem $f
			done

			for f in $(find /etc/digest_lists/ -name \
						"0-file_list-map-*"); do
				$kernel_source_dir/scripts/sign-file sha256 \
				  $kernel_source_dir/certs/signing_key.pem \
				  $kernel_source_dir/certs/signing_key.pem $f
			done
		fi
	fi

	question "Enable diglim rpm plugin?" "y"
	if [ $answer = "y" ]; then
		echo "%__transaction_diglim %{__plugindir}/diglim.so" > \
			/usr/lib/rpm/macros.d/macros.diglim
	fi

	question "Enable diglim_log systemd service at boot?" "y"
	if [ $answer = "y" ]; then
		systemctl enable diglim_log.service
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

	question "Disable diglim_log systemd service at boot?" "y"
	if [ $answer = "y" ]; then
		systemctl disable diglim_log.service
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
