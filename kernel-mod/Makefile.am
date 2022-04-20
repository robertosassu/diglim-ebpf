BUILT_SOURCES = diglim_kern_preload.ko

CFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)/ebpf/kernel

diglim_kern_preload.ko: mod/diglim_kern_preload.c
	make -C /lib/modules/`uname -r`/build M=$(shell pwd)/mod
