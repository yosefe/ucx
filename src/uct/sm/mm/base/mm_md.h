/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
* Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_MM_MD_H_
#define UCT_MM_MD_H_

#include "mm_def.h"

#include <uct/base/uct_md.h>
#include <ucs/config/types.h>
#include <ucs/debug/memtrack.h>
#include <ucs/type/status.h>


extern ucs_config_field_t uct_mm_md_config_table[];

/*
 * Descriptor of the mapped memory
 */
struct uct_mm_remote_seg {
    void             *local_address;    /**< local memory address */
    void             *cookie;           /**< cookie for mmap, xpmem, etc. */
};


/**
 * Local memory segment structure.
 */
typedef struct uct_mm_seg {
    uct_mm_id_t      mmid;       /* Shared memory ID */
    void             *address;   /* Virtual address */
    size_t           length;     /* Size of the memory */
} uct_mm_seg_t;


/**
 * Packed remote key
 */
typedef struct uct_mm_packed_rkey {
    size_t           length;       /* Size of the memory */
    uct_mm_id_t      mmid;         /* Shared memory ID */
    uintptr_t        owner_ptr;    /* VA of in allocating process */
} uct_mm_packed_rkey_t;


/*
 * Memory mapper operations - MM uses them to implement MD and TL functionality.
 */
typedef struct uct_mm_md_ops {
    uct_md_ops_t   super;
    int           (*is_supported)();
    size_t        (*rkey_extra_size)(const uct_mm_md_config_t *config);
} uct_mm_md_ops_t;


/**
 * MM component
 */
typedef struct uct_mm_component {
    uct_component_t       super;
    uct_mm_md_ops_t       *md_ops;
} uct_mm_component_t;


#define UCT_MM_COMPONENT_DEFINE(_var, _name, _md_ops, _rkey_unpack, \
                                _rkey_release, _cfg_prefix) \
    \
    static uct_mm_component_t _var = { \
        .super = { \
            .query_md_resources = uct_mm_query_md_resources, \
            .md_open            = uct_mm_md_open, \
            .rkey_unpack        = _rkey_unpack, \
            .rkey_ptr           = uct_mm_rkey_ptr, \
            .rkey_release       = _rkey_release, \
            .name               = # _name, \
            .md_config          = { \
                .name           = #_name " memory domain", \
                .prefix         = _cfg_prefix, \
                .table          = uct_##_name##_md_config_table, \
                .size           = sizeof(uct_##_name##_md_config_t), \
            }, \
            .tl_list            = UCT_COMPONENT_TL_LIST_INITIALIZER( \
                                      &(_var).super) \
       }, \
       .md_ops                  = _md_ops \
    }; \
    UCT_COMPONENT_REGISTER(&(_var).super); \


/* Extract mapped ops from MD */
#define uct_mm_md_ops(_md) \
    ucs_derived_of((_md)->ops, uct_mm_md_ops_t)


/**
 * MM memory domain
 */
typedef struct uct_mm_md {
    uct_md_t           super;
    uct_mm_md_config_t *config;
    size_t             rkey_extra_size;
} uct_mm_md_t;


ucs_status_t uct_mm_query_md_resources(uct_component_t *component,
                                       uct_md_resource_desc_t **resources_p,
                                       unsigned *num_resources_p);

ucs_status_t
uct_mm_md_mem_seg_new(size_t seg_struct_size, uct_mm_id_t mmid, void *address,
                      size_t length, uct_mm_seg_t **seg_p);

void uct_mm_md_query(uct_md_h md, uct_md_attr_t *md_attr, int support_alloc);

ucs_status_t uct_mm_mkey_pack(uct_md_h md, uct_mem_h memh, void *rkey_buffer);

ucs_status_t uct_mm_rkey_ptr(uct_component_t *component, uct_rkey_t rkey,
                             void *handle, uint64_t raddr, void **laddr_p);

ucs_status_t uct_mm_md_open(uct_component_t *component, const char *md_name,
                            const uct_md_config_t *config, uct_md_h *md_p);

void uct_mm_md_close(uct_md_h md);

static inline void
uct_mm_md_make_rkey(void *local_address, uintptr_t remote_address,
                     uct_rkey_t *rkey_p)
{
    *rkey_p = (uintptr_t)local_address - remote_address;
}

#endif
