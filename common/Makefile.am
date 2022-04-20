lib_LTLIBRARIES=libdiglim.la libdiglimrpm.la

libdiglim_la_LDFLAGS=-no-undefined -avoid-version
libdiglim_la_LIBADD=-ldl -lbpf -lelf -lcrypto
libdiglim_la_SOURCES=hexdump.c hash_info.c lib.c compact.c log.c
libdiglim_la_CFLAGS=-I$(top_srcdir)/include -Werror -DLIBDIR='"$(libdir)"'

libdiglimrpm_la_LDFLAGS=-no-undefined -avoid-version -lrpm -lrpmio
libdiglimrpm_la_SOURCES=rpm.c
libdiglimrpm_la_CFLAGS=-I$(top_srcdir)/include -Werror -DLIBDIR='"$(libdir)"'
