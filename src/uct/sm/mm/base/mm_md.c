/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
* Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include "mm_md.h"

#include <ucs/debug/log.h>
#include <inttypes.h>
#include <limits.h>


ucs_config_field_t uct_mm_md_config_table[] = {
  {"", "", NULL,
   ucs_offsetof(uct_mm_md_config_t, super), UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

  {"HUGETLB_MODE", "try",
   "Enable using huge pages for internal buffers. "
   "Possible values are:\n"
   " y   - Allocate memory using huge pages only.\n"
   " n   - Allocate memory using regular pages only.\n"
   " try - Try to allocate memory using huge pages and if it fails, allocate regular pages.\n",
   ucs_offsetof(uct_mm_md_config_t, hugetlb_mode), UCS_CONFIG_TYPE_TERNARY},

  {NULL}
};

ucs_status_t uct_mm_query_md_resources(uct_component_t *component,
                                       uct_md_resource_desc_t **resources_p,
                                       unsigned *num_resources_p)
{
    uct_mm_component_t *mmc = ucs_derived_of(component, uct_mm_component_t);

    if (mmc->md_ops->is_supported()) {
        return uct_md_query_single_md_resource(component, resources_p,
                                               num_resources_p);
    } else {
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }
}

ucs_status_t
uct_mm_md_mem_seg_new(size_t seg_struct_size, uct_mm_id_t mmid, void *address,
                      size_t length, uct_mm_seg_t **seg_p)
{
    uct_mm_seg_t *seg;

    ucs_assert(sizeof(*seg) <= seg_struct_size);

    seg = ucs_malloc(seg_struct_size, "mm seg");
    if (seg == NULL) {
        ucs_error("failed to allocate memory for mm segment");
        return UCS_ERR_NO_MEMORY;
    }

    seg->mmid    = mmid;
    seg->address = address;
    seg->length  = length;
    *seg_p       = seg;

    ucs_debug("mm registered address %p length %zu mmid %"PRIu64, address,
              length, seg->mmid);
    return UCS_OK;
}

void uct_mm_md_query(uct_md_h md, uct_md_attr_t *md_attr, int support_alloc)
{
    uct_mm_md_t *mm_md = ucs_derived_of(md, uct_mm_md_t);

    memset(md_attr, 0, sizeof(*md_attr));

    md_attr->cap.flags            = UCT_MD_FLAG_RKEY_PTR |
                                    UCT_MD_FLAG_NEED_RKEY;
    md_attr->cap.max_reg          = 0;
    md_attr->cap.max_alloc        = 0;
    md_attr->rkey_packed_size     = sizeof(uct_mm_packed_rkey_t) +
                                    mm_md->rkey_extra_size;
    md_attr->cap.access_mem_type  = UCT_MD_MEM_TYPE_HOST;
    md_attr->cap.detect_mem_types = 0;

    if (support_alloc) {
        md_attr->cap.flags       |= UCT_MD_FLAG_ALLOC | UCT_MD_FLAG_FIXED;
        md_attr->cap.max_alloc    = ULONG_MAX;
    }

    memset(&md_attr->local_cpus, 0xff, sizeof(md_attr->local_cpus));
}

ucs_status_t uct_mm_mkey_pack(uct_md_h md, uct_mem_h memh, void *rkey_buffer)
{
    uct_mm_packed_rkey_t *rkey = rkey_buffer;
    uct_mm_seg_t         *seg  = memh;

    rkey->length    = seg->length;
    rkey->mmid      = seg->mmid;
    rkey->owner_ptr = (uintptr_t)seg->address;

    ucs_trace("packed rkey: mmid %"PRIu64" owner_ptr 0x%lx", rkey->mmid,
              rkey->owner_ptr);
    return UCS_OK;
}

ucs_status_t uct_mm_rkey_ptr(uct_component_t *component, uct_rkey_t rkey,
                             void *handle, uint64_t raddr, void **laddr_p)
{
    /* rkey stores offset from the remote va */
    *laddr_p = (void*)raddr + (ptrdiff_t)rkey;
    return UCS_OK;
}

ucs_status_t uct_mm_md_open(uct_component_t *component, const char *md_name,
                            const uct_md_config_t *config, uct_md_h *md_p)
{
    uct_mm_component_t *mmc = ucs_derived_of(component, uct_mm_component_t);
    uct_mm_md_t *mm_md;
    ucs_status_t status;

    mm_md = ucs_malloc(sizeof(*mm_md), "uct_mm_md_t");
    if (mm_md == NULL) {
        ucs_error("Failed to allocate memory for uct_mm_md_t");
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    mm_md->config = ucs_malloc(mmc->super.md_config.size, "mm_md config");
    if (mm_md->config == NULL) {
        ucs_error("Failed to allocate memory for mm_md config");
        status = UCS_ERR_NO_MEMORY;
        goto err_free_mm_md;
    }

    status = ucs_config_parser_clone_opts(config, mm_md->config,
                                          mmc->super.md_config.table);
    if (status != UCS_OK) {
        ucs_error("Failed to clone opts");
        goto err_free_mm_md_config;
    }

    mm_md->super.ops       = &mmc->md_ops->super;
    mm_md->super.component = &mmc->super;
    mm_md->rkey_extra_size = mmc->md_ops->rkey_extra_size(mm_md->config);

    *md_p = &mm_md->super;
    return UCS_OK;

err_free_mm_md_config:
    ucs_free(mm_md->config);
err_free_mm_md:
    ucs_free(mm_md);
err:
    return status;
}

void uct_mm_md_close(uct_md_h md)
{
    uct_mm_md_t *mm_md = ucs_derived_of(md, uct_mm_md_t);

    ucs_config_parser_release_opts(mm_md->config,
                                   md->component->md_config.table);
    ucs_free(mm_md->config);
    ucs_free(mm_md);
}
