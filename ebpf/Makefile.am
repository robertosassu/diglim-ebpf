sbin_PROGRAMS=diglim_user
bin_PROGRAMS=diglim_user_client

BUILT_SOURCES = diglim_kern.skel.h vmlinux.h

vmlinux.h: /sys/kernel/btf/vmlinux
	/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > \
		vmlinux.h

if HAVE_KERNEL_PATCHES
DIGLIM_CFLAGS=-DHAVE_KERNEL_PATCHES
endif

diglim_kern.o: vmlinux.h diglim_kern.c
	clang -g -Wall -Werror -O2 -I$(top_srcdir)/include -target bpf \
	      -c diglim_kern.c -mcpu=probe $(DIGLIM_CFLAGS) -o diglim_kern.o

diglim_kern.skel.h: diglim_kern.o
	/usr/sbin/bpftool gen skeleton diglim_kern.o > diglim_kern.skel.h

diglim_user_CFLAGS=-I$(top_srcdir)/include $(DIGLIM_CFLAGS)
diglim_user_LDFLAGS=$(top_srcdir)/common/libdiglim.la
diglim_user_SOURCES=diglim_user.c

diglim_user_client_CFLAGS=-I$(top_srcdir)/include
diglim_user_client_LDFLAGS=$(top_srcdir)/common/libdiglim.la
diglim_user_client_SOURCES=diglim_user_client.c

dist_pkgdata_DATA = ima-policy
