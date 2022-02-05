pluginsdir = $(libdir)/rpm-plugins

plugins_LTLIBRARIES = diglim.la

diglim_la_LDFLAGS=-no-undefined -avoid-version -module
diglim_la_LIBADD = $(top_srcdir)/common/libdiglim.la \
		   $(top_srcdir)/common/libdiglimrpm.la -lrpm -lrpmio
diglim_la_CFLAGS=-I$(top_srcdir)/include
diglim_la_SOURCES = diglim.c
