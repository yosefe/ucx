/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RNDV_PPLN_INL_
#define UCP_RNDV_PPLN_INL_

#include "rndv_ppln.h"


static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_ppln_frag_copy(ucp_request_t *req, ucp_rndv_frag_t *frag,
                              void *buffer, size_t length,
                              uct_ep_put_zcopy_func_t copy_func,
                              uct_completion_callback_t comp_func,
                              const char *mode)
{
    ucp_ep_h ep                = req->send.ep;
    ucp_worker_h worker        = ep->worker;
    ucs_memory_type_t mem_type = req->send.state.dt_iter.mem_info.type;
    ucp_ep_h memtype_ep        = worker->mem_type_ep[mem_type];
    ucp_lane_index_t lane      = ucp_ep_config(memtype_ep)->key.rma_bw_lanes[0];
    ucp_md_index_t md_index    = ucp_ep_md_index(memtype_ep, lane);
    ucs_status_t status;
    uct_iov_t iov;

    ucs_assert(lane != UCP_NULL_LANE);
    ucp_trace_req(req, "frag %p copy-%s %p (%s) using memtype-ep %p lane[%d]",
                  frag, mode, buffer, ucs_memory_type_names[mem_type],
                  memtype_ep, lane);

    /* Set up IOV pointing to the frag */
    req->send.frag = frag;
    iov.buffer     = frag + 1;
    iov.length     = length;
    iov.memh       = ucp_memh2uct(frag->super.memh, md_index);
    iov.count      = 1;
    iov.stride     = 0;
    ucp_proto_completion_init(&frag->comp, comp_func);

    /* Copy from frag to user buffer */
    status = copy_func(memtype_ep->uct_eps[lane], &iov, 1, (uintptr_t)buffer,
                       UCT_INVALID_RKEY, &frag->comp);
    ucp_trace_req(req, "frag %p copy-%s %p returned %s, comp-count %d", frag,
                  mode, buffer, ucs_status_string(status), frag->comp.count);
    return status;
}

#endif
