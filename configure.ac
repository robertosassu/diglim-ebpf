#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([diglim-ebpf], [0.1.2], [roberto.sassu@huawei.com])
AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])

# Enable debug.
AC_ARG_ENABLE([debug], [  --enable-debug    Turn on debugging],
	      [debug=${enableval}], [debug=no])

if test -z "$CFLAGS"; then
  if test "$debug" == yes; then
    CFLAGS="-O0 -g"
  else
    CFLAGS="-O2"
  fi
fi

if test "$debug" == yes; then
  CFLAGS="$CFLAGS -DDEBUG"
fi

big_endian=false
AC_C_BIGENDIAN ([big_endian=true], [big_endian=false])
if test "$big_endian" == true; then
  CFLAGS="$CFLAGS -D__BIG_ENDIAN__"
fi

# Checks for programs.
AM_PROG_AR
AC_PROG_CC
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL

# Checks for libraries.
AC_SEARCH_LIBS([SHA256_Init], [crypto], [],
	       AC_MSG_ERROR([Unable to find the OpenSSL library]))
AC_SEARCH_LIBS([headerGet], [rpm], [],
	       AC_MSG_ERROR([Unable to find the rpm library]))
AC_SEARCH_LIBS([elf32_checksum], [elf], [],
	       AC_MSG_ERROR([Unable to find the ELF library]))
AC_SEARCH_LIBS([bpf_map__pin], [bpf], [],
	       AC_MSG_ERROR([Unable to find the libbpf library]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h stdlib.h string.h unistd.h], [],
		 AC_MSG_ERROR([Unable to find the glibc headers]))
AC_CHECK_HEADERS([openssl/evp.h], [],
		 AC_MSG_ERROR([Unable to find the OpenSSL headers]))
AC_CHECK_HEADERS([rpm/rpmlib.h], [],
		 AC_MSG_ERROR([Unable to find the rpm headers]))
AC_CHECK_HEADERS([libelf.h], [],
		 AC_MSG_ERROR([Unable to find the ELF headers]))
AC_CHECK_HEADERS([bpf/bpf.h], [],
		 AC_MSG_ERROR([Unable to find the libbpf headers]))

AC_ARG_WITH(kernel-patches,
	AC_HELP_STRING([--with-kernel-patches],
	[Use features from non-upstream kernels [default is off]]),
	[kernel_patches="yes"
	AC_MSG_RESULT([*** Enabling features from non-upstream kernels ***])],)

AM_CONDITIONAL([HAVE_KERNEL_PATCHES], [test "$kernel_patches" = yes])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_CHECK_SIZEOF(long)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([ftruncate memset munmap strstr])

# Check availability of initrd tools
DRACUT_SUBDIR=
AC_CHECK_FILE(/usr/bin/dracut, [DRACUT_SUBDIR=dracut], [])
AC_SUBST([DRACUT_SUBDIR])

CFLAGS="$CFLAGS -Wall -Werror"

AC_SUBST(CFLAGS)

AC_CONFIG_FILES([Makefile
		 common/Makefile
		 docs/Makefile
		 ebpf/Makefile
		 generators/Makefile
		 include/Makefile
		 initrd/dracut/Makefile
		 initrd/Makefile
		 parsers/Makefile
		 rpm-plugin/Makefile
		 scripts/Makefile
		 systemd/Makefile])
AC_OUTPUT
cat <<EOF

CFLAGS:				${CFLAGS}

EOF
