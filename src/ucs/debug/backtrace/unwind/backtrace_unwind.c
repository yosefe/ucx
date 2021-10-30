/**
 * Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define UNW_LOCAL_ONLY

#include <ucs/debug/backtrace/base/backtrace.h>
#include <libunwind.h>


static ucs_status_t
ucs_debug_unwind_get_backtrace(ucs_debug_backtrace_frame_cb_t frame_cb, void *arg)
{
    char symbol[UCS_DEBUG_BACKTRACE_MAX_SYMBOL_LEN];
    unw_cursor_t cursor;
    unw_context_t context;
    ucs_status_t status;
    unw_word_t ip, off;

    unw_getcontext(&context);
    unw_init_local(&cursor, &context);

    while (unw_step(&cursor)) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (!unw_get_proc_name(&cursor, symbol, sizeof(symbol), &off)) {
            status = frame_cb(arg, (const void*)ip, symbol, off, NULL, 0);
        } else {
            status = frame_cb(arg, (const void*)ip, NULL, 0, NULL, 0);
        }
        if (status != UCS_OK) {
            return status;
        }
    }

    return UCS_OK;
}

static ucs_debug_backtrace_provider_t ucs_debug_bfd_backtrace_provider = {
    .name            = "unwind",
    .get_symbol_name = ucs_debug_get_symbol_name_default,
    .get_backtrace   = ucs_debug_unwind_get_backtrace
};

UCS_STATIC_INIT {
    ucs_list_add_tail(&ucs_debug_backtrace_providers,
                      &ucs_debug_bfd_backtrace_provider.list);
}

UCS_STATIC_CLEANUP {
    ucs_list_del(&ucs_debug_bfd_backtrace_provider.list);
}