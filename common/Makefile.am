lib_LTLIBRARIES=libdiglim.la libdiglimrpm.la

libdiglim_la_LDFLAGS=-no-undefined -avoid-version
libdiglim_la_LIBADD=-ldl -lbpf -lelf
libdiglim_la_SOURCES=hash_info.c hexdump.c log.c clientserver.c parsers.c
libdiglim_la_CFLAGS=-I$(top_srcdir)/include -Werror -DLIBDIR='"$(libdir)"'

libdiglimrpm_la_LDFLAGS=-no-undefined -avoid-version -lrpm -lrpmio
libdiglimrpm_la_SOURCES=rpm.c
libdiglimrpm_la_CFLAGS=-I$(top_srcdir)/include -Werror -DLIBDIR='"$(libdir)"'
