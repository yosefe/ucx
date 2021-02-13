/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "rndv_ppln.h"
#include "rndv_ppln.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/proto/proto_multi.inl>


ucs_status_t
ucp_proto_rndv_ppln_get_frag_md_map(ucp_worker_h worker, ucp_md_map_t *md_map_p)
{
    ucp_rndv_frag_t *frag = ucp_worker_mpool_get(&worker->rndv_frag_mp,
                                                 ucp_rndv_frag_t);
    if (frag == NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    *md_map_p = frag->super.memh->md_map;
    ucs_mpool_put(frag);
    return UCS_OK;
}

static ucs_status_t
ucp_proto_rndv_ppln_frag_get(ucp_worker_h worker, ucp_request_t *req,
                             ucp_proto_rndv_ppln_frag_init_cb_t frag_init)
{
    ucp_rndv_frag_t *frag;

    frag = ucp_worker_mpool_get(&worker->rndv_frag_mp, ucp_rndv_frag_t);
    if (frag == NULL) {
        ucp_proto_request_abort(req, UCS_ERR_NO_MEMORY);
        return UCS_OK;
    }

    req->send.frag = frag;
    return frag_init(req);
}

/**
 * Calculate the lane which should be used to send the chunk of data which
 * starts from position "offset".
 *
 * @param [in]  req
 * @param [in]  mpriv
 * @param [in]  offset      Send offset
 * @param [in]  length      Total data length
 * @param [out] lane_idx_p  Filled with lane index (in mpriv) to use
 *
 * @return Maximal size to send on the lane.
 */
static size_t
ucp_proto_rndv_ppln_max_payload(ucp_request_t *req,
                                const ucp_proto_multi_priv_t *mpriv,
                                size_t offset, size_t length,
                                ucp_lane_index_t *lane_idx_p)
{
    size_t total_frag_size = mpriv->lanes[mpriv->num_lanes - 1].max_frag_sum;
    size_t frag_offset     = offset % total_frag_size;
    const ucp_proto_multi_lane_priv_t *lpriv;
    size_t lane_send_offset, lane_start_offset;
    ucp_lane_index_t lane_idx;
    size_t end_offset;
    size_t max_payload;

    lane_start_offset = 0;
    for (lane_idx = 0; lane_idx < (mpriv->num_lanes - 1); ++lane_idx) {
        lpriv = &mpriv->lanes[lane_idx];
        if (length < total_frag_size) {
            /* request is small so use weight */
            end_offset = (lpriv->weight_sum * length) >>
                         UCP_PROTO_MULTI_WEIGHT_SHIFT;
        } else {
            /* request is large, so each sends full fragment */
            end_offset = lpriv->max_frag_sum;
        }

        ucp_trace_req(req, "lane[%d] end_offset=%zu max_frag_sum=%zu", lane_idx,
                      end_offset, lpriv->max_frag_sum);
        if (frag_offset < end_offset) {
            /* found lane */
            break;
        }

        lane_start_offset = end_offset;
    }

    lane_send_offset = frag_offset - lane_start_offset;
    lpriv            = &mpriv->lanes[lane_idx];
    max_payload      = lpriv->max_frag - lane_send_offset;
    *lane_idx_p      = lane_idx;

    ucp_trace_req(req,
                  "frag_offset %zu lane[%d] lane_offset %zu max_payload %zu",
                  frag_offset, lane_idx, lane_send_offset, max_payload);
    return max_payload;
}

/*
 * frag_init - initializes fragment including its completion.
 *       returns UCS_INPROGRESS to continue, otherwise - return/desched
 */
ucs_status_t
ucp_proto_rndv_ppln_send_progress(ucp_request_t *req,
                                  const ucp_proto_multi_priv_t *mpriv,
                                  size_t total_length,
                                  uct_completion_callback_t req_comp_func,
                                  ucp_proto_rndv_ppln_frag_init_cb_t frag_init,
                                  ucp_proto_rndv_ppln_frag_send_cb_t frag_send,
                                  ucp_proto_complete_cb_t sent_func)
{
    ucp_worker_h worker = req->send.ep->worker;
    size_t frag_size    = ucs_min(worker->context->config.ext.rndv_frag_size,
                                  req->send.state.dt_iter.length -
                                          req->send.state.dt_iter.offset);
    size_t send_offset  = req->send.rndv.ppln.offset +
                          req->send.state.dt_iter.offset;
    const ucp_proto_multi_lane_priv_t *lpriv;
    ucp_lane_index_t lane_idx;
    ucp_rndv_frag_t *frag;
    ucs_status_t status;
    size_t max_payload;
    size_t send_size;
    size_t frag_offset;
    uct_iov_t iov;

    ucp_trace_req(req,
                  "rndv ppln_progress %zu/%zu (%zu/%zu) "
                  "rva 0x%" PRIx64 " rreq 0x%" PRIx64 " rkey %p",
                  req->send.state.dt_iter.offset,
                  req->send.state.dt_iter.length, send_offset, total_length,
                  req->send.rndv.remote_address, req->send.rndv.remote_req_id,
                  req->send.rndv.rkey);

    ucs_assert(req->send.state.dt_iter.length > 0);
    ucs_assert(!ucp_datatype_iter_is_end(&req->send.state.dt_iter));

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        ucp_proto_completion_init(&req->send.state.uct_comp, req_comp_func);
        ucp_proto_multi_request_init(req);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;

        status = ucp_proto_rndv_ppln_frag_get(worker, req, frag_init);
        if (status != UCS_INPROGRESS) {
            return status;
        }
    }

    ucp_trace_req(req, "comp.count=%d", req->send.state.uct_comp.count);
    max_payload = ucp_proto_rndv_ppln_max_payload(req, mpriv, send_offset,
                                                  total_length, &lane_idx);
    lpriv       = &mpriv->lanes[lane_idx];
    frag_offset = req->send.state.dt_iter.offset % frag_size;
    send_size   = ucs_min(frag_size - frag_offset, max_payload);

    /* Set IOV to next portion of frag to send, according to dt_iter */
    frag       = req->send.frag;
    iov.buffer = UCS_PTR_BYTE_OFFSET(frag + 1, frag_offset);
    iov.length = send_size;
    if (lpriv->super.memh_index == UCP_NULL_RESOURCE) {
        iov.memh = UCT_MEM_HANDLE_NULL;
    } else {
        iov.memh = frag->super.memh->uct[lpriv->super.memh_index];
    }
    iov.count  = 1;
    iov.stride = 0;

    ucs_assertv(frag->comp.count > 0, "frag=%p", frag);
    status = frag_send(req, lpriv, &iov, &frag->comp);
    if (ucs_likely(status == UCS_OK)) {
        /* fast path is OK */
    } else if (status == UCS_INPROGRESS) {
         /* operation started and completion will be called later */
        ++frag->comp.count;
    } else if (status == UCS_ERR_NO_RESOURCE) {
        return ucp_proto_multi_no_resource(req, lpriv);
    } else {
        ucp_proto_request_abort(req, status);
        return UCS_OK;
    }

    /* When fragment send is completed, just release it */
    ucp_datatype_iter_advance(&req->send.state.dt_iter, send_size,
                              &req->send.state.dt_iter);

    if ((frag_offset + send_size) != frag_size) {
        return UCS_INPROGRESS;
    }

    ucp_invoke_uct_completion(&frag->comp, UCS_OK);
    if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
        status = sent_func(req);
        ucp_trace_req(req, "calling sent_func %p: status %d", sent_func,
                      status);
        return status;
    }

    return ucp_proto_rndv_ppln_frag_get(worker, req, frag_init);
}

static void
ucp_proto_rndv_ppln_frag_copy_out_completion(uct_completion_t *uct_comp)
{
    ucp_rndv_frag_t *frag = ucs_container_of(uct_comp, ucp_rndv_frag_t, comp);
    ucp_request_t *req    = frag->req;

    /* complete related rndv_rtr request */
    ucp_trace_req(req, "frag %p copy out completion, req count: %d", frag,
                  req->send.state.uct_comp.count);
    ucp_invoke_uct_completion(&req->send.state.uct_comp, frag->comp.status);
    ucs_mpool_put(frag);
}

void ucp_proto_rndv_ppln_frag_recv_completion(uct_completion_t *uct_comp)
{
    ucp_rndv_frag_t *frag = ucs_container_of(uct_comp, ucp_rndv_frag_t, comp);
    ucp_request_t *req    = frag->req;
    ucs_status_t status;
    void *buffer;

    buffer = UCS_PTR_BYTE_OFFSET(req->send.state.dt_iter.type.contig.buffer,
                                 frag->offset);
    status = ucp_proto_rndv_ppln_frag_copy(
            req, frag, buffer, frag->length, uct_ep_put_zcopy,
            ucp_proto_rndv_ppln_frag_copy_out_completion, "out to");
    if (status == UCS_OK) {
        ucp_invoke_uct_completion(&frag->comp, UCS_OK);
    } else if (status != UCS_INPROGRESS) {
        ucp_proto_request_abort(req, status);
    }
}

int ucp_proto_rndv_ppln_is_supported(const ucp_proto_init_params_t *init_params)
{
    ucp_worker_h worker = init_params->worker;

    return worker->mem_type_ep[init_params->select_param->mem_type] != NULL;
}