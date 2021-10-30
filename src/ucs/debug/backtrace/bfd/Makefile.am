#
# Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
#
# See file LICENSE for terms.
#

if HAVE_BFD

module_LTLIBRARIES     = libucs_bfd.la
libucs_bfd_la_CPPFLAGS = $(BFD_CPPFLAGS) $(BASE_CPPFLAGS)
libucs_bfd_la_CFLAGS   = $(BFD_CFLAGS) $(BASE_CFLAGS)
libucs_bfd_la_LIBADD   = $(BFD_LIBS) \
                         $(top_builddir)/src/ucs/libucs.la
libucs_bfd_la_LDFLAGS  = $(BFD_LDFLAGS) -version-info $(SOVERSION)
libucs_bfd_la_SOURCES  = backtrace_bfd.c
include $(top_srcdir)/config/module.am

endif
