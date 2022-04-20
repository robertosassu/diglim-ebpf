sbin_PROGRAMS=diglim_user
bin_PROGRAMS=diglim_user_loader diglim_log

diglim_user_CFLAGS=-I$(top_srcdir)/include -I$(top_srcdir)/ebpf/kernel
diglim_user_LDFLAGS=$(top_srcdir)/common/libdiglim.la
diglim_user_SOURCES=diglim_user.c
diglim_user_DEPENDENCIES=$(top_srcdir)/ebpf/kernel/diglim_kern.skel.h

diglim_user_loader_CFLAGS=-I$(top_srcdir)/include
diglim_user_loader_LDFLAGS=-all-static
diglim_user_loader_SOURCES=diglim_user_loader.c ../../common/libbpf.c \
			   ../../common/lib.c

diglim_log_CFLAGS=-I$(top_srcdir)/include
diglim_log_LDFLAGS=$(top_srcdir)/common/libdiglim.la
diglim_log_SOURCES=diglim_log.c
