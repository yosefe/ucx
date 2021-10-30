/**
 * Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "backtrace.h"

#include <ucs/datastruct/khash.h>
#include <ucs/debug/assert.h>
#include <ucs/debug/memtrack_int.h>
#include <ucs/config/global_opts.h>
#include <ucs/sys/string.h>
#include <ucs/sys/sys.h>
#include <execinfo.h>
#include <dlfcn.h>


typedef struct {
    FILE     *stream;
    unsigned strip;
    unsigned flags;
    unsigned frame_num;
} ucs_debug_print_backtrace_ctx_t;

typedef struct {
    ucs_debug_backtrace_frame_cb_t user_frame_cb;
    void                           *user_arg;
    unsigned                       frame;
} ucs_debug_backtrace_filter_ctx_t;

KHASH_MAP_INIT_INT64(ucs_debug_symbol, char*);

static const void *ucs_debug_signal_restorer = &ucs_debug_signal_restorer;
static khash_t(ucs_debug_symbol) ucs_debug_symbols_cache;
static pthread_mutex_t ucs_debug_symbols_lock = PTHREAD_MUTEX_INITIALIZER;

/* Global list of backtrace providers */
UCS_LIST_HEAD(ucs_debug_backtrace_providers);


ucs_debug_backtrace_provider_t *
ucs_debug_backtrace_find_provider(const char *name)
{
    ucs_debug_backtrace_provider_t *provider;

    ucs_list_for_each(provider, &ucs_debug_backtrace_providers, list) {
        if (!strcmp(name, provider->name)) {
            return provider;
        }
    }

    return NULL;
}

static ucs_debug_backtrace_provider_t *ucs_debug_backtrace_get_provider()
{
    ucs_debug_backtrace_provider_t *provider = NULL;
    unsigned i;

    for (i = 0;
         (i < ucs_global_opts.backtrace_methods.count) && (provider == NULL);
         ++i) {
        provider = ucs_debug_backtrace_find_provider(
                ucs_global_opts.backtrace_methods.names[i]);
    }

    return provider;
}

static char *ucs_debug_default_demangle(const char *mangled_name, char *buffer,
                                        size_t *length, int *status)
{
    *status = 0;
    free(buffer);
    return strdup(mangled_name);
}

static char *ucs_debug_cplus_demangle(const char *symbol_name)
{
    static char *(*cxa_demangle)(const char*, char*, size_t*, int*) = NULL;
    char *demangled_name;
    int status;

    if (cxa_demangle == NULL) {
        cxa_demangle = dlsym(RTLD_DEFAULT, "__cxa_demangle");
    }
    if (cxa_demangle == NULL) {
        cxa_demangle = ucs_debug_default_demangle;
    }

    demangled_name = cxa_demangle(symbol_name, NULL, NULL, &status);
    if (status != 0) {
        free(demangled_name);
        return strdup(symbol_name);
    }

    return demangled_name;
}

static void ucs_debug_print_source_file(FILE *stream, const char *source_file,
                                        unsigned source_line,
                                        const char *function_name)
{
    static const int context = 3;
    char source_text[256];
    unsigned n;
    FILE *file;

    file = fopen(source_file, "r");
    if (file == NULL) {
        return;
    }

    n = 1;
    fprintf(stream, "\n");
    fprintf(stream, "%s:", source_file);
    if (function_name != NULL) {
        fprintf(stream, " [ %s ]", function_name);
    }
    fprintf(stream, "\n");

    if (source_line > context) {
        fprintf(stream, "      ...\n");
    }

    while (fgets(source_text, sizeof(source_text), file) != NULL) {
        if (abs((int)source_line - (int)n) <= context) {
            fprintf(stream, "%s %5u %s", (n == source_line) ? "==>" : "   ", n,
                    source_text);
        }
        ++n;
    }
    fprintf(stream, "\n");

    fclose(file);
}

static ucs_status_t
ucs_debug_print_backtrace_callback(void *arg, const void *address,
                                   const char *function_name, ptrdiff_t offset,
                                   const char *source_file,
                                   unsigned source_line)
{
    ucs_debug_print_backtrace_ctx_t *ctx = arg;
    char *demangled_name                 = NULL;

    if (ctx->frame_num < ctx->strip) {
        return UCS_OK;
    }

    if (function_name != NULL) {
        demangled_name = ucs_debug_cplus_demangle(function_name);
    }

    if ((ctx->frame_num == ctx->strip) &&
        (ctx->flags & UCS_DEBUG_BACKTRACE_PRINT_FLAG_SHOW_SOURCE) &&
        (source_file != NULL) && (source_line != 0)) {
        ucs_debug_print_source_file(ctx->stream, source_file, source_line,
                                    demangled_name);
    }

    fprintf(ctx->stream, "%2d 0x%016lx", ctx->frame_num, (uintptr_t)address);
    if (function_name != NULL) {
        fprintf(ctx->stream, " %s", demangled_name);
        if (strchr(demangled_name, '(') == NULL) {
            fprintf(ctx->stream, "()");
        }
        if (offset != 0) {
            fprintf(ctx->stream, "+%ld", offset);
        }
    }
    if (source_file != NULL) {
        fprintf(ctx->stream, "  %s", source_file);
        if (source_line != 0) {
            fprintf(ctx->stream, ":%d", source_line);
        }
    }
    fprintf(ctx->stream, "\n");

    free(demangled_name);

    ++ctx->frame_num;
    return UCS_OK;
}

static int
ucs_debug_backtrace_is_excluded(const void *address, const char *symbol)
{
    if (address == ucs_debug_signal_restorer) {
        return 1;
    }

    if (symbol == NULL) {
        return 0;
    }

    return !strcmp(symbol, "ucs_handle_error") ||
           !strcmp(symbol, "ucs_fatal_error_format") ||
           !strcmp(symbol, "ucs_fatal_error_message") ||
           !strcmp(symbol, "ucs_error_freeze") ||
           !strcmp(symbol, "ucs_error_signal_handler") ||
           !strcmp(symbol, "ucs_debug_handle_error_signal") ||
           !strcmp(symbol, "ucs_debug_get_backtrace") ||
           !strcmp(symbol, "ucs_debug_print_backtrace") ||
           !strcmp(symbol, "ucs_log_default_handler") ||
           !strcmp(symbol, "ucs_log_dispatch") ||
           !strcmp(symbol, "ucs_debug_send_mail") ||
           (strstr(symbol, "_L_unlock_") == symbol);
}

static ucs_status_t
ucs_debug_backtrace_filter_callback(void *arg, const void *address,
                                    const char *function_name, ptrdiff_t offset,
                                    const char *source_file,
                                    unsigned source_line)
{
    ucs_debug_backtrace_filter_ctx_t *ctx = arg;

    if (ucs_debug_backtrace_is_excluded(address, function_name)) {
        return UCS_OK;
    }

    /* Call user callback and increment frame counter */
    return ctx->user_frame_cb(ctx->user_arg, address, function_name, offset,
                              source_file, source_line);
}

static ucs_status_t
ucs_debug_get_backtrace(ucs_debug_backtrace_frame_cb_t frame_cb, void *arg)
{
    ucs_debug_backtrace_filter_ctx_t ctx = {
        .user_frame_cb = frame_cb,
        .user_arg      = arg,
        .frame         = 0
    };
    ucs_debug_backtrace_provider_t *provider;

    provider = ucs_debug_backtrace_get_provider();
    if (provider == NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    return provider->get_backtrace(ucs_debug_backtrace_filter_callback, &ctx);
}

void ucs_debug_print_backtrace(FILE *stream, unsigned strip, unsigned flags)
{
    ucs_debug_print_backtrace_ctx_t ctx = {
        .stream    = stream,
        .strip     = strip,
        .flags     = flags,
        .frame_num = 0
    };

    fprintf(stream, "==== backtrace (tid:%7d) ====\n", ucs_get_tid());
    ucs_debug_get_backtrace(ucs_debug_print_backtrace_callback, &ctx);
    fprintf(stream, "=================================\n");
}

const char *ucs_debug_get_symbol_name(const void *address)
{
    char symbol_name[UCS_DEBUG_BACKTRACE_MAX_SYMBOL_LEN];
    ucs_debug_backtrace_provider_t *provider;
    int hash_extra_status;
    char *cached_symbol;
    khiter_t hash_it;
    int found;

    provider = ucs_debug_backtrace_get_provider();
    if (provider == NULL) {
        return UCS_DEBUG_UNKNOWN_SYMBOL;
    }

    pthread_mutex_lock(&ucs_debug_symbols_lock);
    hash_it = kh_put(ucs_debug_symbol, &ucs_debug_symbols_cache,
                     (uintptr_t)address, &hash_extra_status);
    if (hash_extra_status == UCS_KH_PUT_KEY_PRESENT) {
        cached_symbol = kh_value(&ucs_debug_symbols_cache, hash_it);
    } else if (hash_extra_status == UCS_KH_PUT_FAILED) {
        cached_symbol = NULL;
    } else {
        ucs_assert(hash_it != kh_end(&ucs_debug_symbols_cache));
        found = provider->get_symbol_name(address, symbol_name,
                                          sizeof(symbol_name));
        if (found) {
            cached_symbol = ucs_debug_cplus_demangle(symbol_name);
        } else {
            cached_symbol = NULL;
        }
        kh_value(&ucs_debug_symbols_cache, hash_it) = cached_symbol;
    }

    pthread_mutex_unlock(&ucs_debug_symbols_lock);
    return cached_symbol ? cached_symbol : UCS_DEBUG_UNKNOWN_SYMBOL;
}

static char *ucs_debug_backtrace_default_process_symbol(char *symbol)
{
    char *saveptr;

    if (symbol == NULL) {
        return NULL;
    }

    return strtok_r(symbol, "\n[]", &saveptr);
}

static ucs_status_t
ucs_debug_get_backtrace_default(ucs_debug_backtrace_frame_cb_t frame_cb,
                                void *arg)
{
    void *addresses[UCS_DEBUG_BACKTRACE_MAX_FRAMES];
    char symbol_buffer[256];
    int frame, num_frames;
    FILE *backtrace_file;
    ucs_status_t status;
    int pipefd[2];
    char *symbol;
    int i, ret;

    /* Create a pipe for reading backtrace symbols and open the read side of the
       pipe as FILE handle */
    ret = pipe(pipefd);
    if (ret == 0) {
        backtrace_file = fdopen(pipefd[0], "r");
    } else {
        backtrace_file = NULL;
        pipefd[0] = pipefd[1] = -1;
    }

    num_frames = backtrace(addresses, ucs_static_array_size(addresses));
    backtrace_symbols_fd(addresses, num_frames, pipefd[1]);

    for (frame = 0; frame < num_frames; ++frame) {
        /* Read symbol from the pipe */
        if (backtrace_file != NULL) {
            symbol = fgets(symbol_buffer, sizeof(symbol_buffer),
                           backtrace_file);
            symbol = ucs_debug_backtrace_default_process_symbol(symbol);
        } else {
            symbol = NULL;
        }

        /* Pass frame information to the user-defined callback */
        status = frame_cb(arg, addresses[frame], NULL, 0, symbol, 0);
        if (status != UCS_OK) {
            return status;
        }
    }

    if (backtrace_file != NULL) {
        fclose(backtrace_file);
    }
    for (i = 0; i < 2; ++i) {
        if (pipefd[i] >= 0) {
            close(pipefd[i]);
        }
    }

    return UCS_OK;
}

int ucs_debug_get_symbol_name_default(const void *address, char *buffer,
                                      size_t max)
{
    Dl_info dl_info;
    int ret;

    ret = dladdr(address, &dl_info);
    if ((ret == 0) || (dl_info.dli_sname == NULL)) {
        return 0;
    }

    ucs_strncpy_safe(buffer, dl_info.dli_sname, max);
    return 1;
}

static ucs_debug_backtrace_provider_t ucs_debug_backtrace_default_provider = {
    .name            = "default",
    .get_symbol_name = ucs_debug_get_symbol_name_default,
    .get_backtrace   = ucs_debug_get_backtrace_default
};

void ucs_debug_set_sa_restorer(const void *sa_restorer)
{
    ucs_debug_signal_restorer = sa_restorer;
}

void ucs_debug_backtrace_init()
{
    kh_init_inplace(ucs_debug_symbol, &ucs_debug_symbols_cache);
    ucs_list_add_tail(&ucs_debug_backtrace_providers,
                      &ucs_debug_backtrace_default_provider.list);
}

void ucs_debug_backtrace_cleanup()
{
    char *symbol;

    kh_foreach_value(&ucs_debug_symbols_cache, symbol, ucs_free(symbol));
    kh_destroy_inplace(ucs_debug_symbol, &ucs_debug_symbols_cache);
}