diglim_parsersdir=$(libdir)/diglim-parsers

diglim_parsers_LTLIBRARIES=compact.la rpm.la

compact_la_LDFLAGS=-no-undefined -avoid-version -L$(top_srcdir)/common/.libs \
		   -module
compact_la_LIBADD=$(top_srcdir)/common/libdiglim.la
compact_la_CFLAGS=-I$(top_srcdir)/include
compact_la_SOURCES=compact.c

rpm_la_LDFLAGS=-no-undefined -avoid-version -L$(top_srcdir)/common/.libs -module
rpm_la_LIBADD=$(top_srcdir)/common/libdiglim.la -lrpm -lrpmio
rpm_la_CFLAGS=-I$(top_srcdir)/include
rpm_la_SOURCES=rpm.c
