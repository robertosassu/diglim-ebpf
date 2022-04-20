bin_PROGRAMS=compact_gen rpm_gen map_gen

compact_gen_CFLAGS=-I$(top_srcdir)/include
compact_gen_LDFLAGS=$(top_srcdir)/common/libdiglim.la -lcrypto
compact_gen_SOURCES=compact_gen.c

rpm_gen_CFLAGS=-I$(top_srcdir)/include
rpm_gen_LDFLAGS=$(top_srcdir)/common/libdiglim.la \
		$(top_srcdir)/common/libdiglimrpm.la -lrpm -lrpmio
rpm_gen_SOURCES=rpm_gen.c

map_gen_CFLAGS=-I$(top_srcdir)/include
map_gen_LDFLAGS=$(top_srcdir)/common/libdiglim.la -lcrypto
map_gen_SOURCES=map_gen.c
