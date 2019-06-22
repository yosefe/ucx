/**
 * Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 * Copyright (c) Los Alamos National Security, LLC. 2016.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "xpmem.h"

#include <uct/sm/mm/base/mm_md.h>
#include <uct/sm/mm/base/mm_iface.h>
#include <ucs/datastruct/khash.h>
#include <ucs/debug/memtrack.h>
#include <ucs/memory/rcache.h>
#include <ucs/debug/log.h>


typedef struct uct_xpmem_md_config {
    uct_mm_md_config_t      super;
} uct_xpmem_md_config_t;

/* cache entry for remote memory of a process */
typedef struct uct_xpmem_remote_mem {
    xpmem_apid_t            apid;
    ucs_rcache_t            *rcache;
} uct_xpmem_remote_mem_t;

/* cache entry for remote memory of a process */
typedef struct uct_xpmem_remote_mem_region {
    ucs_rcache_region_t     super;
    void                    *attach_address;
    ucs_rcache_t            *rcache;
} uct_xpmem_remote_region_t;


KHASH_INIT(xpmem_remote_mem, xpmem_segid_t, uct_xpmem_remote_mem_t, 1,
           kh_int64_hash_func, kh_int64_hash_equal)

static khash_t(xpmem_remote_mem) uct_xpmem_remote_mem_hash;
static pthread_spinlock_t        uct_xpmem_remote_mem_lock;

static ucs_config_field_t uct_xpmem_md_config_table[] = {
  {"MM_", "", NULL,
   ucs_offsetof(uct_xpmem_md_config_t, super),
   UCS_CONFIG_TYPE_TABLE(uct_mm_md_config_table)},

  {NULL}
};

UCS_STATIC_INIT {
    pthread_spin_init(&uct_xpmem_remote_mem_lock, 0);
    kh_init_inplace(xpmem_remote_mem, &uct_xpmem_remote_mem_hash);
}

UCS_STATIC_CLEANUP {
    // TODO make sure hash is clean?? detach remote segs??
    kh_destroy_inplace(xpmem_remote_mem, &uct_xpmem_remote_mem_hash);
    pthread_spin_destroy(&uct_xpmem_remote_mem_lock);
}

static ucs_status_t uct_xpmem_md_query(uct_md_h md, uct_md_attr_t *md_attr)
{
    uct_mm_md_query(md, md_attr, 0);

    md_attr->cap.flags        |= UCT_MD_FLAG_REG;
    md_attr->reg_cost.overhead = 5.0e-9;
    md_attr->reg_cost.growth   = 0;
    md_attr->cap.max_reg       = ULONG_MAX;
    md_attr->cap.reg_mem_types = UCS_BIT(UCT_MD_MEM_TYPE_HOST);
    md_attr->rkey_packed_size  = sizeof(uct_mm_packed_rkey_t);

    return UCS_OK;
}

static inline size_t
uct_xpmem_rcache_region_length(uct_xpmem_remote_region_t *xpmem_region)
{
    return xpmem_region->super.super.end - xpmem_region->super.super.start;
}

static ucs_status_t uct_xpmem_rcache_mem_reg(void *context, ucs_rcache_t *rcache,
                                             void *arg, ucs_rcache_region_t *region,
                                             uint16_t flags)
{
    uct_xpmem_remote_mem_t    *rmem         = context;
    uct_xpmem_remote_region_t *xpmem_region =
                    ucs_derived_of(region, uct_xpmem_remote_region_t);
    struct xpmem_addr addr;
    size_t length;

    addr.apid   = rmem->apid;
    addr.offset = xpmem_region->super.super.start;
    length      = uct_xpmem_rcache_region_length(xpmem_region);

    xpmem_region->attach_address = xpmem_attach(addr, length, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&xpmem_region->attach_address,
                              sizeof(xpmem_region->attach_address));
    if (xpmem_region->attach_address == MAP_FAILED) {
        ucs_error("failed to attach xpmem apid 0x%llx offset %zu length %zu: %m",
                  addr.apid, addr.offset, length);
        return UCS_ERR_IO_ERROR;
    }

    xpmem_region->rcache = rcache;

    ucs_trace("xpmem attached apid 0x%llx length %zu at %p",
              rmem->apid, length, xpmem_region->attach_address);

    VALGRIND_MAKE_MEM_DEFINED(xpmem_region->attach_address, length);
    return UCS_OK;
}

static void uct_xpmem_rcache_mem_dereg(void *context, ucs_rcache_t *rcache,
                                       ucs_rcache_region_t *region)
{
    uct_xpmem_remote_region_t *xpmem_region =
                    ucs_derived_of(region, uct_xpmem_remote_region_t);
    int ret;

    ucs_trace("xpmem detaching address %p", xpmem_region->attach_address);
    ret = xpmem_detach(xpmem_region->attach_address);
    if (ret < 0) {
        ucs_warn("Failed to xpmem_detach: %m");
    }

    VALGRIND_MAKE_MEM_UNDEFINED(xpmem_region->attach_address,
                                uct_xpmem_rcache_region_length(xpmem_region));
    xpmem_region->attach_address = NULL;
    xpmem_region->rcache         = NULL;
}

static void uct_xpmem_rcache_dump_region(void *context, ucs_rcache_t *rcache,
                                         ucs_rcache_region_t *region, char *buf,
                                         size_t max)
{
    uct_xpmem_remote_mem_t    *rmem         = context;
    uct_xpmem_remote_region_t *xpmem_region =
                    ucs_derived_of(region, uct_xpmem_remote_region_t);

    snprintf(buf, max, "apid 0x%llx attach_addr %p rmem %p", rmem->apid,
             xpmem_region->attach_address, rmem);
}

static ucs_rcache_ops_t uct_xpmem_rcache_ops = {
    .mem_reg     = uct_xpmem_rcache_mem_reg,
    .mem_dereg   = uct_xpmem_rcache_mem_dereg,
    .dump_region = uct_xpmem_rcache_dump_region
};

static ucs_status_t uct_xmpem_mem_reg(uct_md_h md, void *address, size_t length,
                                      unsigned flags, uct_mem_h *memh_p)
{
    static xpmem_segid_t segid = -1;
    ucs_status_t status;

    if (ucs_unlikely(segid == -1)) {
        // TODO thread safety with double-checked lock
        segid = xpmem_make(0, XPMEM_MAXADDR_SIZE, XPMEM_PERMIT_MODE, (void*)0666);
        VALGRIND_MAKE_MEM_DEFINED(&segid, sizeof(segid));
        if (segid < 0) {
            ucs_error("failed to register address space xpmem: %m");
            return UCS_ERR_IO_ERROR;
        }

        ucs_debug("registered full address space with xpmem, segid=%lld", segid);
    }

    status = uct_mm_md_mem_seg_new(sizeof(uct_mm_seg_t), segid, address, length,
                                   (uct_mm_seg_t**)memh_p);
    if (status != UCS_OK) {
        return UCS_ERR_NO_MEMORY;
    }

    return UCS_OK;
}

static ucs_status_t uct_xmpem_mem_dereg(uct_md_h md, uct_mem_h memh)
{
    uct_mm_seg_t *seg = memh;
    ucs_free(seg);
    return UCS_OK;
}

/* must hold a reference to rcache (by rmem->refcount) */
static inline ucs_status_t
uct_xpmem_rcache_get_region(ucs_rcache_t *rcache, uintptr_t remote_address,
                            size_t length, uct_rkey_t *rkey_p, void **handle_p)
{
    uct_xpmem_remote_region_t *xpmem_region;
    ucs_rcache_region_t *region;
    ucs_status_t status;
    ptrdiff_t offset;

    /* TODO align up to 1G granularity? */

    status = ucs_rcache_get(rcache, (void*)remote_address, length,
                            PROT_READ|PROT_WRITE, NULL, &region);
    if (status != UCS_OK) {
        return status;
    }

    xpmem_region     = ucs_derived_of(region, uct_xpmem_remote_region_t);
    offset           = remote_address - region->super.start;
    *handle_p        = xpmem_region;

    uct_mm_md_make_rkey(xpmem_region->attach_address + offset, remote_address,
                         rkey_p);
    return UCS_OK;
}

/* lock must be held */
static ucs_status_t uct_xpmem_remote_mem_init(uct_xpmem_remote_mem_t *rmem,
                                              uct_mm_id_t mmid)
{
    ucs_rcache_params_t rcache_params;

    rmem->apid = xpmem_get(mmid, XPMEM_RDWR, XPMEM_PERMIT_MODE, NULL);
    VALGRIND_MAKE_MEM_DEFINED(&rmem->apid, sizeof(rmem->apid));
    if (rmem->apid < 0) {
        ucs_error("failed to acquire xpmem segment 0x%"PRIx64": %m", mmid);
        return UCS_ERR_IO_ERROR;
    }

    ucs_trace("xpmem acquired segment 0x%lx apid 0x%llx", mmid, rmem->apid);

    rcache_params.region_struct_size = sizeof(uct_xpmem_remote_region_t);
    rcache_params.alignment          = ucs_get_page_size();
    rcache_params.max_alignment      = ucs_get_page_size();
    rcache_params.ucm_events         = 0;
    rcache_params.ucm_event_priority = 0;
    rcache_params.ops                = &uct_xpmem_rcache_ops;
    rcache_params.context            = rmem;
// TODO set alignment to some large value eg 1g, and enable adjacent region merge
    return ucs_rcache_create(&rcache_params, "xpmem_remote_mem",
                             NULL /*TODO stats*/, &rmem->rcache);
}

/* lock must be held */
static UCS_F_NOINLINE ucs_status_t
uct_xpmem_remote_mem_add(uct_mm_id_t mmid, uct_xpmem_remote_mem_t **rmem_p)
{
    uct_xpmem_remote_mem_t *rmem;
    ucs_status_t status;
    khiter_t khiter;
    int khret;

    khiter = kh_put(xpmem_remote_mem, &uct_xpmem_remote_mem_hash, mmid,
                     &khret);
    ucs_assertv_always((khret == 1) || (khret == 2), "khret=%d", khret); // TODO err handle
    ucs_assert_always(khiter != kh_end(&uct_xpmem_remote_mem_hash));

    rmem = &kh_val(&uct_xpmem_remote_mem_hash, khiter);
    status = uct_xpmem_remote_mem_init(rmem, mmid);
    if (status != UCS_OK) {
        return status;
    }

    *rmem_p = rmem;
    return UCS_OK;
}

static ucs_status_t
uct_xpmem_rkey_unpack(uct_component_t *component, const void *rkey_buffer,
                      uct_rkey_t *rkey_p, void **handle_p)
{
    const uct_mm_packed_rkey_t *packed_rkey = rkey_buffer;
    uct_xpmem_remote_mem_t *rmem;
    ucs_rcache_t *rcache;
    ucs_status_t status;
    khiter_t khiter;

    pthread_spin_lock(&uct_xpmem_remote_mem_lock);
    khiter = kh_get(xpmem_remote_mem, &uct_xpmem_remote_mem_hash,
                    packed_rkey->mmid);
    if (ucs_likely(khiter != kh_end(&uct_xpmem_remote_mem_hash))) {
        rmem = &kh_val(&uct_xpmem_remote_mem_hash, khiter);
    } else {
        status = uct_xpmem_remote_mem_add(packed_rkey->mmid, &rmem);
        if (status != UCS_OK) {
            pthread_spin_unlock(&uct_xpmem_remote_mem_lock);
            return status;
        }
    }

    rcache = rmem->rcache;
    pthread_spin_unlock(&uct_xpmem_remote_mem_lock);

    status = uct_xpmem_rcache_get_region(rcache, packed_rkey->owner_ptr,
                                         packed_rkey->length, rkey_p, handle_p);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    return UCS_OK;
}

static void
uct_xpmem_rkey_release(uct_component_t *component, uct_rkey_t rkey, void *handle)
{
    uct_xpmem_remote_region_t *xpmem_region = handle;

    ucs_rcache_region_put(xpmem_region->rcache, &xpmem_region->super);
}

static int uct_xpmem_is_supported()
{
    int version;

    version = xpmem_version();
    if (version < 0) {
        ucs_debug("xpmem_version returned %d: %m. xpmem is unsupported", version);
        return 0;
    }

    return 1;
}

static uct_mm_md_ops_t uct_xpmem_md_ops = {
   .super = {
        .close                  = uct_mm_md_close,
        .query                  = uct_xpmem_md_query,
        .mem_alloc              = (void*)ucs_empty_function_return_unsupported,
        .mem_free               = (void*)ucs_empty_function_return_unsupported,
        .mem_advise             = (void*)ucs_empty_function_return_unsupported,
        .mem_reg                = uct_xmpem_mem_reg,
        .mem_dereg              = uct_xmpem_mem_dereg,
        .mkey_pack              = uct_mm_mkey_pack,
        .is_sockaddr_accessible = (void*)ucs_empty_function_return_zero,
        .detect_memory_type     = (void*)ucs_empty_function_return_unsupported
    },
   .is_supported                = uct_xpmem_is_supported,
   .rkey_extra_size             = (void*)ucs_empty_function_return_zero_int64,
};

UCT_MM_TL_DEFINE(xpmem, &uct_xpmem_md_ops, uct_xpmem_rkey_unpack,
                 uct_xpmem_rkey_release, "XPMEM_")
