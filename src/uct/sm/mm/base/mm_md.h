/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2019.  ALL RIGHTS RESERVED.
* Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_MM_MD_H_
#define UCT_MM_MD_H_

#include <uct/base/uct_md.h>
#include <ucs/config/types.h>
#include <ucs/debug/memtrack.h>
#include <ucs/type/status.h>


/* Memory mapper segment unique id for FIFO and bcopy descriptors
 * the exact structure depends on specific mapper */
typedef uint64_t          uct_mm_seg_id_t;


/**
 * Local memory segment structure. Also used as uct_mem_h.
 */
typedef struct uct_mm_seg {
    uct_mm_seg_id_t       seg_id;        /* Shared memory ID */
    void                  *address;      /* Virtual address */
    size_t                length;        /* Size of the memory TODO remove? */
} uct_mm_seg_t;


/*
 * Descriptor of remote attached memory
 */
typedef struct uct_mm_remote_seg {
    void                  *address;      /* Local address of attached memory */
    void                  *cookie;       /* Mapper-specific data */
} uct_mm_remote_seg_t;


/**
 * MM memory domain configuration
 */
typedef struct uct_mm_md_config {
    uct_md_config_t       super;
    ucs_ternary_value_t   hugetlb_mode; /* Enable using huge pages */
} uct_mm_md_config_t;


/**
 * MM memory domain
 */
typedef struct uct_mm_md {
    uct_md_t               super;
    uct_mm_md_config_t     *config;     /* Clone of MD configuration */
    size_t                 iface_addr_len; /* As returned from
                                           uct_mm_md_mapper_ops_t::iface_addr_length */
} uct_mm_md_t;


/*
 * Memory mapper operations - MM uses them to implement MD and TL functionality
 */
typedef struct uct_mm_mapper_ops {
    uct_md_ops_t           super;

    /* check if available on current machine */
    ucs_status_t           (*query)();

    /* return the size of memory-domain specific iface address (e.g mmap path) */
    size_t                 (*iface_addr_length)(uct_mm_md_t *md);

    void                   (*iface_addr_pack)(uct_mm_md_t *md, void *buffer);

    ucs_status_t           (*mem_alloc)(uct_mm_md_t *md, uct_mm_seg_t *seg,
                                        unsigned uct_flags, const char *alloc_name);

    ucs_status_t           (*mem_free)(uct_mm_md_t *md, const uct_mm_seg_t *seg);

    ucs_status_t           (*mem_attach)(uct_mm_md_t *md, uct_mm_seg_id_t seg_id,
                                         const void *iface_addr,
                                         uct_mm_remote_seg_t *rseg);

    void                   (*mem_detach)(uct_mm_md_t *md,
                                         const uct_mm_remote_seg_t *rseg);
} uct_mm_md_mapper_ops_t;


/**
 * MM component
 */
typedef struct uct_mm_component {
    uct_component_t        super;
    uct_mm_md_mapper_ops_t *md_ops;
} uct_mm_component_t;


/*
 * Define a memory-mapper component for MM.
 *
 * @param _var          Variable for MM component.
 * @param _name         String which is the component name.
 * @param _md_ops       Mapper operations, of type uct_mm_mapper_ops_t.
 * @param _cfg_prefix   Prefix for configuration environment vars.
 */
#define UCT_MM_COMPONENT_DEFINE(_var, _name, _md_ops, _rkey_unpack, \
                                _rkey_release, _cfg_prefix) \
    \
    static uct_mm_component_t _var = { \
        .super = { \
            .query_md_resources = uct_mm_query_md_resources, \
            .md_open            = uct_mm_md_open, \
            .cm_open            = ucs_empty_function_return_unsupported, \
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
                                      &(_var).super), \
            .flags              = 0, \
       }, \
       .md_ops                  = (_md_ops) \
    }; \
    UCT_COMPONENT_REGISTER(&(_var).super); \


#define uct_mm_md_mapper_ops(_md) \
    ucs_derived_of((_md)->super.ops, uct_mm_md_mapper_ops_t)

#define uct_mm_md_mapper_call(_md, _func, ...) \
    uct_mm_md_mapper_ops(_md)->_func(_md, ## __VA_ARGS__)

extern ucs_config_field_t uct_mm_md_config_table[];


ucs_status_t uct_mm_query_md_resources(uct_component_t *component,
                                       uct_md_resource_desc_t **resources_p,
                                       unsigned *num_resources_p);

ucs_status_t uct_mm_md_mem_alloc(uct_md_h tl_md, size_t *length_p,
                                 void **address_p, unsigned flags,
                                 const char *alloc_name, uct_mem_h *memh_p);

ucs_status_t uct_mm_md_mem_free(uct_md_h md, uct_mem_h memh);

void uct_mm_md_query(uct_md_h md, uct_md_attr_t *md_attr, int support_alloc);

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
