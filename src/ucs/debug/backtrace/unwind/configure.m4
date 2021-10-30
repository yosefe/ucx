#
# Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

AC_ARG_WITH([libunwind],
            [AS_HELP_STRING([--with-libunwind=(DIR)],
            [Enable the use of libunwind for backtrace (default is guess).])],
            [], [with_libunwind=guess])

AS_IF([test "x$with_libunwind" != xno],
      [
       AS_IF([test "x$with_libunwind" = "xguess" -o "x$with_libunwind" = "xyes"],
             [UNWIND_CHECK_CFLAGS=$(pkg-config --cflags libunwind)
              UNWIND_CHECK_LDFLAGS=$(pkg-config --libs libunwind)],
             [UNWIND_CHECK_CFLAGS="-I${with_libunwind}/include"
              UNWIND_CHECK_LDFLAGS="-L${with_libunwind}/lib -L${with_libunwind}/lib64"])

       save_CFLAGS="$CFLAGS"
       save_LDFLAGS="$LDFLAGS"

       CFLAGS="$UNWIND_CHECK_CFLAGS $CPPFLAGS"
       LDFLAGS="$UNWIND_CHECK_LDFLAGS $LDFLAGS"

       unwind_happy="yes"
       AC_CHECK_DECLS([unw_getcontext, unw_init_local, unw_step, unw_get_proc_name],
                      [], [unwind_happy="no"],
                      [[#include <libunwind.h>]])

       # Try to link a simple program using unw_getcontext()
       AC_MSG_CHECKING([unw_getcontext])
       AC_LINK_IFELSE([AC_LANG_SOURCE([[
                #include <libunwind.h>
                int main(int argc, char** argv) {
                    unw_context_t context;
                    unw_getcontext(&context);
                    return 0;
                } ]])],
                [AC_MSG_RESULT([yes])],
                [AC_MSG_RESULT([no])
                 unwind_happy="no"])

       AS_IF([test "x$unwind_happy" = "xyes"],
             [AC_SUBST([UNWIND_CFLAGS], [${UNWIND_CHECK_CFLAGS}])
              AC_SUBST([UNWIND_LDFLAGS], [${UNWIND_CHECK_LDFLAGS}])],
             [AS_IF([test "x$with_libunwind" != "xguess"],
                    [AC_MSG_ERROR([libunwind requested but could not be found])])])

       CFLAGS="$save_CFLAGS"
       LDFLAGS="$save_LDFLAGS"
    ],
    [AC_MSG_WARN([libunwind was explicitly disabled])]
)

AM_CONDITIONAL([HAVE_UNWIND], [test "x$unwind_happy" = xyes])
AC_CONFIG_FILES([src/ucs/debug/backtrace/unwind/Makefile])

AS_IF([test "x$unwind_happy" = "xyes"], [ucs_modules="${ucs_modules}:unwind"])