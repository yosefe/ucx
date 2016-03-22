/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */


#ifndef UCP_WIREUP_STUB_EP_H_
#define UCP_WIREUP_STUB_EP_H_

#include "address.h"

#include <uct/api/uct.h>
#include <ucp/api/ucp.h>
#include <ucp/core/ucp_ep.h>
#include <ucs/datastruct/queue_types.h>


ucs_status_t ucp_stub_ep_create(ucp_ep_h ep, ucp_ep_op_t optype,
                                unsigned address_count,
                                const ucp_address_entry_t *address_list,
                                uct_ep_h *ep_p);

/**
 * @return Auxiliary resource index used by the stub endpoint.
 *   If the endpoint is not a stub endpoint, return UCP_NULL_RESOURCE.
 */
ucp_rsc_index_t ucp_stub_ep_get_aux_rsc_index(uct_ep_h uct_ep);


static inline ucs_queue_elem_t* ucp_stub_ep_req_priv(uct_pending_req_t *req)
{
    UCS_STATIC_ASSERT(sizeof(ucs_queue_elem_t) <= UCT_PENDING_REQ_PRIV_LEN);
    return (ucs_queue_elem_t*)req->priv;
}

void ucp_stub_ep_progress(void *arg);

#endif
