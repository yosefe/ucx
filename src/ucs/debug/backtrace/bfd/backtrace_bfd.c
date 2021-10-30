/**
 * Copyright (C) 2021 NVIDIA CORPORATION & AFFILIATES. ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <ucs/debug/backtrace/base/backtrace.h>
#include <ucs/sys/string.h>
#include <ucs/sys/sys.h>
#include <execinfo.h>
#include <link.h>
#include <bfd.h>


#if HAVE_DECL_BFD_GET_SECTION_FLAGS
#  define ucs_debug_bfd_section_flags(_abfd, _section) \
    bfd_get_section_flags(_abfd, _section)
#elif HAVE_DECL_BFD_SECTION_FLAGS
#  define ucs_debug_bfd_section_flags(_abfd, _section) \
    bfd_section_flags(_section)
#else
#  error "Unsupported BFD API"
#endif

#if HAVE_DECL_BFD_GET_SECTION_VMA
#  define ucs_debug_bfd_section_vma(_abfd, _section) \
    bfd_get_section_vma(_abfd, _section)
#elif HAVE_DECL_BFD_SECTION_VMA
#  define ucs_debug_bfd_section_vma(_abfd, _section) \
    bfd_section_vma(_section)
#else
#  error "Unsupported BFD API"
#endif

#if HAVE_1_ARG_BFD_SECTION_SIZE
#  define ucs_debug_bfd_section_size(_abfd, _section) \
    bfd_section_size(_section)
#else
#  define ucs_debug_bfd_section_size(_abfd, _section) \
    bfd_section_size(_abfd, _section)
#endif

/* Frame search context */
typedef struct {
    /* Symbol address  to search */
    const void                     *address;

    /* Set to 1 to search call address instead of return address */
    unsigned                       backoff;

    /* Status of last call to frame callback */
    ucs_status_t                   status;

    /* User-defined frame callback */
    ucs_debug_backtrace_frame_cb_t frame_cb;

    /* User-defined argument for the frame callback */
    void                           *arg;
} ucs_debug_bfd_backtrace_frame_ctx_t;

/* File search context */
typedef struct {
    ucs_debug_bfd_backtrace_frame_ctx_t *frame_ctx;

    /* Base address of the object containing the symbol */
    unsigned long                       dl_base;

    /* Loaded symbols */
    asymbol                             **symbols;

    /* Set to nonzero if the symbol was found */
    int                                 found;

} ucs_debug_bfd_backtrace_file_ctx_t;

/* Symbol name search context */
typedef struct {
    char   *buffer;
    size_t max;
    int    found;
} ucs_debug_bfd_get_symbol_ctx_t;


/* @return Whether to continue unwinding frames */
static int ucs_debug_bfd_frame(ucs_debug_bfd_backtrace_frame_ctx_t *ctx,
                               const char *symbol_name, const char *source_file,
                               unsigned source_line)
{
    if (!strcmp(symbol_name, "ucs_debug_bfd_get_backtrace")) {
        /* Ignore internal BFD function */
        return 1;
    }

    ctx->status = ctx->frame_cb(ctx->arg, ctx->address, symbol_name, 0,
                                source_file, source_line);
    return ctx->status == UCS_OK;
}

static void
ucs_debug_bfd_process_section(bfd *abfd, asection *section, void *data)
{
    ucs_debug_bfd_backtrace_file_ctx_t *ctx        = data;
    ucs_debug_bfd_backtrace_frame_ctx_t *frame_ctx = ctx->frame_ctx;
    const char *source_file, *symbol_name;
    size_t dl_offset, section_offset;
    unsigned source_line;
    bfd_vma vma;
    int found;

    if (ctx->found ||
        !(ucs_debug_bfd_section_flags(abfd, section) & SEC_CODE)) {
        /* Skip irrelevant sections */
        return;
    }

    dl_offset = UCS_PTR_BYTE_DIFF(ctx->dl_base, ctx->frame_ctx->address);

    vma = ucs_debug_bfd_section_vma(abfd, section);
    if (dl_offset < vma) {
        return;
    }

    section_offset = dl_offset - vma;
    if (section_offset >= ucs_debug_bfd_section_size(abfd, section)) {
        return;
    }

    found = bfd_find_nearest_line(abfd, section, ctx->symbols,
                                  section_offset - ctx->frame_ctx->backoff,
                                  &source_file, &symbol_name, &source_line);
    if (!found) {
        return;
    }

    ctx->found = 1;
    if (!ucs_debug_bfd_frame(frame_ctx, symbol_name, source_file,
                             source_line)) {
        return;
    }

    /* To get the inliner info, search again at the original address */
    found = bfd_find_nearest_line(abfd, section, ctx->symbols, section_offset,
                                  &source_file, &symbol_name, &source_line);
    if (!found) {
        return;
    }

    /* Iterate over inlined functions as long as we find them and the callback
       has not retuned error status */
    while (bfd_find_inliner_info(abfd, &source_file, &symbol_name,
                                 &source_line) &&
           ucs_debug_bfd_frame(frame_ctx, symbol_name, source_file,
                               source_line))
        ;
}

static int
ucs_debug_bfd_process_file(ucs_debug_bfd_backtrace_frame_ctx_t *frame_ctx,
                           const char *dl_name, unsigned long dl_base)
{
    ucs_debug_bfd_backtrace_file_ctx_t ctx = {
        .frame_ctx = frame_ctx,
        .dl_base   = dl_base,
        .found     = 0
    };
    long num_symbols;
    unsigned size;
    bfd *abfd;

    abfd = bfd_openr(dl_name, NULL);
    if (abfd == NULL) {
        goto out;
    }

    if (!bfd_check_format(abfd, bfd_object) ||
        bfd_check_format(abfd, bfd_archive) ||
        !(bfd_get_file_flags(abfd) & HAS_SYMS)) {
        goto out_bfd_close;
    }

    num_symbols = bfd_read_minisymbols(abfd, 0, (PTR)&ctx.symbols, &size);
    if (num_symbols == 0) {
        free(ctx.symbols);
        num_symbols = bfd_read_minisymbols(abfd, 1, (PTR)&ctx.symbols, &size);
    }
    if (num_symbols < 0) {
        goto out_bfd_close;
    }

    bfd_map_over_sections(abfd, ucs_debug_bfd_process_section, &ctx);
    free(ctx.symbols);

out_bfd_close:
    bfd_close(abfd);
out:
    return ctx.found;
}

static int
ucs_debug_bfd_iterate_phdr(struct dl_phdr_info *info, size_t size, void *data)
{
    ucs_debug_bfd_backtrace_frame_ctx_t *ctx = data;
    ElfW(Addr) address                       = (uintptr_t)ctx->address;
    const ElfW(Phdr) * phdr;
    ElfW(Addr) vbaseaddr;
    const char *dl_name;

    for (phdr = info->dlpi_phdr; phdr < info->dlpi_phdr + info->dlpi_phnum;
         ++phdr) {
        if (phdr->p_type != PT_LOAD) {
            continue;
        }

        vbaseaddr = phdr->p_vaddr + info->dlpi_addr;
        if ((address >= vbaseaddr) && (address < (vbaseaddr + phdr->p_memsz))) {
            /* Found a matching section in the file */
            dl_name = (strlen(info->dlpi_name) > 0) ? info->dlpi_name :
                                                      ucs_get_exe();
            return ucs_debug_bfd_process_file(ctx, dl_name, info->dlpi_addr);
        }
    }

    return 0;
}

static ucs_status_t
ucs_debug_bfd_get_backtrace(ucs_debug_backtrace_frame_cb_t frame_cb, void *arg)
{
    ucs_debug_bfd_backtrace_frame_ctx_t ctx = {
        .backoff  = 1,
        .frame_cb = frame_cb,
        .arg      = arg
    };
    void *addresses[UCS_DEBUG_BACKTRACE_MAX_FRAMES];
    int address_index, address_count;
    ucs_status_t status;

    address_count = backtrace(addresses, ucs_static_array_size(addresses));
    for (address_index = 0; address_index < address_count; ++address_index) {
        ctx.address = addresses[address_index];
        if (dl_iterate_phdr(ucs_debug_bfd_iterate_phdr, &ctx)) {
            status = ctx.status;
        } else {
            /* Could not find a loaded object that contains the address, so call
               the frame callback with NULL values */
            status = frame_cb(arg, ctx.address, NULL, 0, NULL, 0);
        }
        if (status != UCS_OK) {
            return status;
        }
    }

    return UCS_OK;
}

static ucs_status_t
ucs_debug_bfd_get_symbol_callback(void *arg, const void *address,
                                  const char *function_name, ptrdiff_t offset,
                                  const char *source_file, unsigned source_line)
{
    ucs_debug_bfd_get_symbol_ctx_t *ctx = arg;

    ucs_strncpy_safe(ctx->buffer, function_name, ctx->max);
    ctx->found = 1;
    return UCS_ERR_EXCEEDS_LIMIT;
}

static int
ucs_debug_bfd_get_symbol_name(const void *address, char *buffer, size_t max)
{
    ucs_debug_bfd_get_symbol_ctx_t ctx                = {
        .buffer = buffer,
        .max    = max,
        .found  = 0
    };
    ucs_debug_bfd_backtrace_frame_ctx_t backtrace_ctx = {
        .address  = address,
        .backoff  = 0,
        .frame_cb = ucs_debug_bfd_get_symbol_callback,
        .arg      = &ctx
    };

    dl_iterate_phdr(ucs_debug_bfd_iterate_phdr, &backtrace_ctx);
    return ctx.found;
}

static ucs_debug_backtrace_provider_t ucs_debug_bfd_backtrace_provider = {
    .name            = "bfd",
    .get_symbol_name = ucs_debug_bfd_get_symbol_name,
    .get_backtrace   = ucs_debug_bfd_get_backtrace
};

UCS_STATIC_INIT
{
    ucs_list_add_tail(&ucs_debug_backtrace_providers,
                      &ucs_debug_bfd_backtrace_provider.list);
    bfd_init();
}

UCS_STATIC_CLEANUP {
    ucs_list_del(&ucs_debug_bfd_backtrace_provider.list);
}