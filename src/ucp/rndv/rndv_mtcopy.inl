/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RNDV_FRAG_INL_
#define UCP_RNDV_FRAG_INL_

#include "proto_rndv.inl"

#include <ucp/core/ucp_worker.h>


static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_mtcopy_init(const ucp_proto_init_params_t *init_params,
                          ucp_md_map_t *md_map_p, size_t *frag_size_p)
{
    ucp_worker_h worker = init_params->worker;
    ucp_mem_desc_t *mdesc;

    if (worker->mem_type_ep[init_params->select_param->mem_type] == NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    if (md_map_p != NULL) {
        mdesc = ucp_worker_mpool_get(&worker->rndv_frag_mp);
        if (mdesc == NULL) {
            return UCS_ERR_UNSUPPORTED;
        }

        *md_map_p = mdesc->memh->md_map;
        ucs_mpool_put(mdesc);
    }

    *frag_size_p = worker->context->config.ext.rndv_frag_size;
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_mtcopy_request_init(ucp_request_t *req)
{
    ucp_worker_h worker = req->send.ep->worker;

    req->send.rndv.mdesc = ucp_worker_mpool_get(&worker->rndv_frag_mp);
    if (req->send.rndv.mdesc == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_mtcopy_next_iov(ucp_request_t *req,
                              const ucp_proto_rndv_bulk_priv_t *rpriv,
                              const ucp_proto_multi_lane_priv_t *lpriv,
                              ucp_datatype_iter_t *next_iter, uct_iov_t *iov)
{
    ucp_mem_desc_t *mdesc      = req->send.rndv.mdesc;
    ucp_rsc_index_t memh_index = lpriv->super.memh_index;
    size_t offset              = req->send.state.dt_iter.offset;

    iov->length = ucp_proto_rndv_bulk_max_payload(req, rpriv, lpriv);
    iov->buffer = UCS_PTR_BYTE_OFFSET(mdesc + 1, offset);
    iov->memh   = (memh_index == UCP_NULL_RESOURCE) ?
                            UCT_MEM_HANDLE_NULL :
                            mdesc->memh->uct[memh_index];
    iov->stride = 0;
    iov->count  = 1;

    next_iter->offset = offset + iov->length;
}

static UCS_F_ALWAYS_INLINE ucs_status_t ucp_proto_rndv_mtcopy_copy(
        ucp_request_t *req, uct_ep_put_zcopy_func_t copy_func,
        uct_completion_callback_t comp_func, const char *mode)
{
    ucp_ep_h ep                = req->send.ep;
    ucp_worker_h worker        = ep->worker;
    ucs_memory_type_t mem_type = req->send.state.dt_iter.mem_info.type;
    ucp_ep_h memtype_ep        = worker->mem_type_ep[mem_type];
    ucp_lane_index_t lane    = ucp_ep_config(memtype_ep)->key.rma_bw_lanes[0];
    ucp_md_index_t md_index = ucp_ep_md_index(memtype_ep, lane);
    ucp_mem_desc_t *mdesc   = req->send.rndv.mdesc;
    ucs_status_t status;
    uct_iov_t iov;

    ucs_assert(lane != UCP_NULL_LANE);
    ucs_assert(mdesc != NULL);

    ucp_trace_req(req, "mdesc %p copy-%s %p %s using memtype-ep %p lane[%d]",
                  mdesc, mode, req->send.state.dt_iter.type.contig.buffer,
                  ucs_memory_type_names[mem_type], memtype_ep, lane);

    ucp_proto_completion_init(&req->send.state.uct_comp, comp_func);

    /* Set up IOV pointing to the mdesc */
    iov.buffer     = mdesc + 1;
    iov.length     = req->send.state.dt_iter.length;
    iov.memh       = ucp_memh2uct(mdesc->memh, md_index);
    iov.count      = 1;
    iov.stride     = 0;

    /* Copy from mdesc to user buffer */
    ucs_assert(req->send.state.dt_iter.dt_class == UCP_DATATYPE_CONTIG);
    status = copy_func(memtype_ep->uct_eps[lane], &iov, 1,
                       (uintptr_t)req->send.state.dt_iter.type.contig.buffer,
                       UCT_INVALID_RKEY, &req->send.state.uct_comp);
    ucp_trace_req(req, "mdesc %p copy returned %s", mdesc,
                  ucs_status_string(status));
    ucs_assert(status != UCS_ERR_NO_RESOURCE);

    if (status != UCS_INPROGRESS) {
        ucp_invoke_uct_completion(&req->send.state.uct_comp, status);
    }

    return status;
}

#endif
