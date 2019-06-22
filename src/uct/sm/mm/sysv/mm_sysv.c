/**
 * Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include <uct/sm/mm/base/mm_md.h>
#include <uct/sm/mm/base/mm_iface.h>
#include <ucs/debug/memtrack.h>
#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>


#define UCT_MM_SYSV_PERM (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)
#define UCT_MM_SYSV_MSTR (UCT_MM_SYSV_PERM | IPC_CREAT | IPC_EXCL)

typedef struct uct_sysv_md_config {
    uct_mm_md_config_t      super;
} uct_sysv_md_config_t;

static ucs_config_field_t uct_sysv_md_config_table[] = {
  {"MM_", "", NULL,
   ucs_offsetof(uct_sysv_md_config_t, super), UCS_CONFIG_TYPE_TABLE(uct_mm_md_config_table)},

  {NULL}
};

static ucs_status_t uct_sysv_md_query(uct_md_h md, uct_md_attr_t *md_attr)
{
    uct_mm_md_query(md, md_attr, 1);
    return UCS_OK;
}

static ucs_status_t
uct_sysv_mem_alloc(uct_md_h md, size_t *length_p, void **address_p,
                   unsigned flags, const char *alloc_name, uct_mem_h *memh_p)
{
    uct_mm_md_t *mm_md  = ucs_derived_of(md, uct_mm_md_t);
    ucs_status_t status;
    int shm_flags, shmid;

    shm_flags = UCT_MM_SYSV_MSTR;

    if (0 == *length_p) {
        ucs_error("invalid length %zu", *length_p);
        status = UCS_ERR_INVALID_PARAM;
        goto err;
    }

    if (!(flags & UCT_MD_MEM_FLAG_FIXED)) {
        *address_p = NULL;
    }

    if (mm_md->config->hugetlb_mode != UCS_NO) {
        status = ucs_sysv_alloc(length_p, (*length_p) * 2, address_p,
                                shm_flags | SHM_HUGETLB, alloc_name, &shmid);
        if (status == UCS_OK) {
            goto out_ok;
        }

        ucs_debug("mm failed to allocate %zu bytes with hugetlb", *length_p);
    }

    if (mm_md->config->hugetlb_mode != UCS_YES) {
        status = ucs_sysv_alloc(length_p, SIZE_MAX, address_p, shm_flags,
                                alloc_name, &shmid);
        if (status == UCS_OK) {
            goto out_ok;
        }

        ucs_debug("mm failed to allocate %zu bytes without hugetlb", *length_p);
    }

    ucs_warn("htm=%d", mm_md->config->hugetlb_mode);

err:
    ucs_error("failed to allocate %zu bytes with mm for %s", *length_p, alloc_name);
    return status;

out_ok:

    status = uct_mm_md_mem_seg_new(sizeof(uct_mm_seg_t), shmid, *address_p,
                                   *length_p, (uct_mm_seg_t**)memh_p);
    if (status != UCS_OK) {
        ucs_sysv_free(*address_p);
        goto err;
    }

    return UCS_OK;
}

static ucs_status_t uct_sysv_mem_free(uct_md_h md, uct_mem_h memh)
{
    uct_mm_seg_t *seg = memh;
    ucs_status_t status;

    status = ucs_sysv_free(seg->address);
    if (status != UCS_OK) {
        return status;
    }

    ucs_free(seg);
    return UCS_OK;
}

static ucs_status_t
uct_sysv_rkey_unpack(uct_component_t *component, const void *rkey_buffer,
                     uct_rkey_t *rkey_p, void **handle_p)
{
    const uct_mm_packed_rkey_t *packed_rkey = rkey_buffer;
    void *ptr;

    ptr = shmat(packed_rkey->mmid, NULL, 0);
    if (ptr == MAP_FAILED) {
        ucs_error("shmat(shmid=%d) failed: %m", (int)packed_rkey->mmid);
        return UCS_ERR_SHMEM_SEGMENT;
    }

    ucs_trace("attached remote segment %d remote_address 0x%lx at address %p",
              (int)packed_rkey->mmid, packed_rkey->owner_ptr, ptr);

    *handle_p = ptr;
    uct_mm_md_make_rkey(ptr, packed_rkey->owner_ptr, rkey_p);

    return UCS_OK;
}

static void
uct_sysv_rkey_release(uct_component_t *component, uct_rkey_t rkey, void *handle)
{
    void *address = handle;
    ucs_sysv_free(address);
}

static uct_mm_md_ops_t uct_sysv_md_ops = {
   .super = {
        .close                  = uct_mm_md_close,
        .query                  = uct_sysv_md_query,
        .mem_alloc              = uct_sysv_mem_alloc,
        .mem_free               = uct_sysv_mem_free,
        .mem_advise             = (void*)ucs_empty_function_return_unsupported,
        .mem_reg                = (void*)ucs_empty_function_return_unsupported,
        .mem_dereg              = (void*)ucs_empty_function_return_unsupported,
        .mkey_pack              = uct_mm_mkey_pack,
        .is_sockaddr_accessible = (void*)ucs_empty_function_return_zero,
        .detect_memory_type     = (void*)ucs_empty_function_return_unsupported
    },
   .is_supported                = ucs_empty_function_return_one,
   .rkey_extra_size             = (void*)ucs_empty_function_return_zero_int64,
};

UCT_MM_TL_DEFINE(sysv, &uct_sysv_md_ops, uct_sysv_rkey_unpack,
                 uct_sysv_rkey_release, "SYSV_")
