## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	-DPACKAGE_LOCALE_DIR=\""$(localedir)"\" \
	-DPACKAGE_SRC_DIR=\""$(srcdir)"\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	$(LIBCDEL_CFLAGS)

AM_CFLAGS =\
	 -Wall\
	 -O3

lib_LTLIBRARIES = libcdel.la


libcdel_la_SOURCES = \
	lib.c

libcdel_la_LDFLAGS = 

libcdel_la_LIBADD = $(libcrypto_LIBS)

include_HEADERS = \
	libcdel.h

