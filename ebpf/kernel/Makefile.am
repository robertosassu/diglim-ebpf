noinst_HEADERS = diglim_kern.skel.h diglim_kern.lskel.h

CLEANFILES = $(noinst_HEADERS) *.o vmlinux.h

DIGLIM_CFLAGS = -g -Wall -Werror -O2 -I$(top_srcdir)/include -I. -target bpf \
		-mcpu=probe

vmlinux.h: /sys/kernel/btf/vmlinux
	/usr/sbin/bpftool btf dump file /sys/kernel/btf/vmlinux format c > \
		vmlinux.h

diglim_sec.o: diglim_sec.c vmlinux.h
	clang $(DIGLIM_CFLAGS) -c $< -o $@

diglim_compact_parser.o: diglim_compact_parser.c vmlinux.h
	clang $(DIGLIM_CFLAGS) -c $< -o $@

diglim_rpm_parser.o: diglim_rpm_parser.c vmlinux.h
	clang $(DIGLIM_CFLAGS) -c $< -o $@

diglim_map_parser.o: diglim_map_parser.c vmlinux.h
	clang $(DIGLIM_CFLAGS) -c $< -o $@

diglim_kern.o: diglim_sec.o diglim_compact_parser.o diglim_rpm_parser.o diglim_map_parser.o
	/usr/sbin/bpftool gen object $@ diglim_sec.o diglim_compact_parser.o \
					diglim_rpm_parser.o diglim_map_parser.o

diglim_kern.skel.h: diglim_kern.o
	/usr/sbin/bpftool gen skeleton $< > $@

diglim_kern.lskel.h: diglim_kern.o
	/usr/sbin/bpftool gen skeleton -L $< > $@
