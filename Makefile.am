## Process this file with automake to produce Makefile.in
## Created by Anjuta

SUBDIRS = src 

libcdeldocdir = ${prefix}/doc/libcdel
libcdeldoc_DATA = \
	README\
	COPYING\
	AUTHORS\
	ChangeLog\
	INSTALL\
	NEWS


EXTRA_DIST = $(libcdeldoc_DATA)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libcdel.pc

# Remove doc directory on uninstall
uninstall-local:
	-rm -r $(libcdeldocdir)
