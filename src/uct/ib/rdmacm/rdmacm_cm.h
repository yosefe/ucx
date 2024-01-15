/**
* Copyright (C) Mellanox Technologies Ltd. 2019.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_RDMACM_CM_H
#define UCT_RDMACM_CM_H

#include "rdmacm_def.h"

#include <uct/base/uct_cm.h>
#include <ucs/datastruct/khash.h>


KHASH_MAP_INIT_INT64(uct_rdmacm_cm_device_contexts,
                     struct uct_rdmacm_cm_device_context*);


/**
 * An rdmacm connection manager
 */
typedef struct uct_rdmacm_cm {
    uct_cm_t                               super;
    struct rdma_event_channel              *ev_ch;
    khash_t(uct_rdmacm_cm_device_contexts) ctxs;

    struct {
        struct sockaddr                    *src_addr;
    } config;
} uct_rdmacm_cm_t;


typedef struct uct_rdmacm_cm_config {
    uct_cm_config_t            super;
    char                       *src_addr;
} uct_rdmacm_cm_config_t;


typedef struct uct_rdmacm_cm_device_context {
    struct ibv_cq *cq;
    uint8_t       eth_ports;
} uct_rdmacm_cm_device_context_t;


UCS_CLASS_DECLARE_NEW_FUNC(uct_rdmacm_cm_t, uct_cm_t, uct_component_h,
                           uct_worker_h, const uct_cm_config_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_rdmacm_cm_t, uct_cm_t);

static UCS_F_ALWAYS_INLINE ucs_async_context_t *
uct_rdmacm_cm_get_async(uct_rdmacm_cm_t *cm)
{
    uct_priv_worker_t *wpriv = ucs_derived_of(cm->super.iface.worker,
                                              uct_priv_worker_t);

    return wpriv->async;
}

ucs_status_t uct_rdmacm_cm_destroy_id(struct rdma_cm_id *id);

ucs_status_t uct_rdmacm_cm_ack_event(struct rdma_cm_event *event);

ucs_status_t uct_rdmacm_cm_reject(struct rdma_cm_id *id);

ucs_status_t
uct_rdmacm_cm_get_device_context(uct_rdmacm_cm_t *cm,
                                 struct ibv_context *verbs,
                                 uct_rdmacm_cm_device_context_t **ctx_p);

void uct_rdmacm_cm_cqs_cleanup(uct_rdmacm_cm_t *cm);

#endif
