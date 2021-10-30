#
# Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_UNWIND

module_LTLIBRARIES        = libucs_unwind.la
libucs_unwind_la_CPPFLAGS = $(BASE_CPPFLAGS)
libucs_unwind_la_CFLAGS   = $(UNWIND_CFLAGS) $(BASE_CFLAGS)
libucs_unwind_la_LIBADD   = $(top_builddir)/src/ucs/libucs.la
libucs_unwind_la_LDFLAGS  = $(UNWIND_LDFLAGS) -version-info $(SOVERSION)
libucs_unwind_la_SOURCES    = backtrace_unwind.c
include $(top_srcdir)/config/module.am

endif
