dnl Process this file with autoconf to produce a configure script.
dnl Created by Anjuta application wizard.

AC_INIT(libcdel, 0.1)

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([1.11])

AC_PROG_CC
AC_PROG_CC_C99
AC_HEADER_STDC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET
AC_CONFIG_MACRO_DIR([m4])

LT_INIT

PKG_CHECK_MODULES(libcrypto, [libcrypto >= 1.0.1])

AC_OUTPUT([
Makefile
libcdel.pc
src/Makefile
])
