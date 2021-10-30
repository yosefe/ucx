#
# Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

#
# Use binutils-devel package for detailed backtrace print
#
AC_ARG_WITH([bfd],
            [AS_HELP_STRING([--with-bfd=(DIR)],
            [Enable using BFD support for detailed backtrace (default is guess).])],
            [], [with_bfd=guess])
AS_IF([test "x$with_bfd" != xno],
      [
       # Do not define BFD_CFLAGS, BFD_LIBS, etc to make sure automake will not
       # try to use them when bfd_happy=no
       BFD_CHECK_CFLAGS=""
       BFD_CHECK_LIBS="-lbfd -ldl -lz"
       AS_IF([test "x$with_bfd" = "xguess" -o "x$with_bfd" = "xyes"],
             [BFD_CHECK_CPPFLAGS=""
              BFD_CHECK_LDFLAGS=""],
             [BFD_CHECK_CPPFLAGS="-I${with_bfd}/include"
              BFD_CHECK_LDFLAGS="-L${with_bfd}/lib -L${with_bfd}/lib64"])

       save_CFLAGS="$CFLAGS"
       save_CPPFLAGS="$CPPFLAGS"
       save_LDFLAGS="$LDFLAGS"
       save_LIBS="$LIBS"

       # Check BFD properties with all flags pointing to the custom location
       CFLAGS="$BFD_CHECK_CFLAGS $CFLAGS "
       CPPFLAGS="$BFD_CHECK_CPPFLAGS $CPPFLAGS"
       LDFLAGS="$BFD_CHECK_LDFLAGS $LDFLAGS"
       LIBS="$BFD_CHECK_LIBS $LIBS"

       bfd_happy="yes"
       AC_CHECK_LIB(bfd, bfd_openr, [],
                    [
                     # If cannot link with bfd, try adding known dependency libs
                     # unset the cached check result to force re-check
                     unset ac_cv_lib_bfd_bfd_openr
                     BFD_CHECK_DEPLIBS="-liberty -lz -ldl"
                     AC_CHECK_LIB(bfd, bfd_openr,
                                  [BFD_CHECK_LIBS="$BFD_CHECK_LIBS $BFD_CHECK_DEPLIBS"
                                   LIBS="$LIBS $BFD_CHECK_DEPLIBS"],
                                  [bfd_happy="no"],
                                  [$BFD_CHECK_DEPLIBS])
                    ])
       AC_CHECK_HEADER([bfd.h], [], [bfd_happy="no"])
       AC_CHECK_TYPES([struct dl_phdr_info], [], [bfd_happy=no],
                      [[#define _GNU_SOURCE 1
                        #include <link.h>]])

       AS_IF([test "x$bfd_happy" = "xyes"],
             [
              # Check optional BFD functions
              AC_CHECK_DECLS([bfd_get_section_flags, bfd_section_flags,
                              bfd_get_section_vma, bfd_section_vma],
                             [], [], [#include <bfd.h>])

              # Check bfd_section_size() function type
              AC_MSG_CHECKING([bfd_section_size API version])
              AC_LANG_PUSH([C])
              AC_COMPILE_IFELSE([
                  AC_LANG_SOURCE([[
                      #include <bfd.h>
                      int main(int argc, char** argv) {
                          asection sec;
                          bfd_section_size(&sec);
                          return 0;
                      }
                  ]])],
                  [AC_MSG_RESULT([1-arg API])
                   AC_DEFINE([HAVE_1_ARG_BFD_SECTION_SIZE], [1], [bfd_section_size 1-arg])],
                  [AC_MSG_RESULT([2-args API])
                   AC_DEFINE([HAVE_1_ARG_BFD_SECTION_SIZE], [0], [bfd_section_size 2-args])
              ])
              AC_LANG_POP([C])

              case ${host} in
                  aarch64*) BFD_CHECK_CFLAGS="$BFD_CHECK_CFLAGS -funwind-tables" ;;
              esac

              # Define macros and variable substitutions for BFD support
              AC_DEFINE([HAVE_DETAILED_BACKTRACE], 1, [Enable detailed backtrace])
              AC_SUBST([BFD_CFLAGS], [$BFD_CHECK_CFLAGS])
              AC_SUBST([BFD_CPPFLAGS], [$BFD_CHECK_CPPFLAGS])
              AC_SUBST([BFD_LIBS], [$BFD_CHECK_LIBS])
              AC_SUBST([BFD_LDFLAGS], [$BFD_CHECK_LDFLAGS])
             ],
             [
               AS_IF([test "x$with_bfd" != "xyes" -a "x$with_bfd" != "xguess"],
                     [AC_MSG_ERROR([BFD support requested but could not be found])])
             ])

       LIBS="$save_LIBS"
       LDFLAGS="$save_LDFLAGS"
       CPPFLAGS="$save_CPPFLAGS"
       CFLAGS="$save_CFLAGS"
      ],
      [bfd_happy="no"
       AC_MSG_WARN([BFD support was explicitly disabled])]
)

AM_CONDITIONAL([HAVE_BFD], [test "x$bfd_happy" = xyes])
AC_CONFIG_FILES([src/ucs/debug/backtrace/bfd/Makefile])

AS_IF([test "x$bfd_happy" = "xyes"], [ucs_modules="${ucs_modules}:bfd"])
