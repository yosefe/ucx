/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "rndv_ppln.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/proto/proto_am.inl>
#include <ucp/proto/proto_multi.inl>
#include <ucp/proto/proto_single.inl>


static ucs_status_t
ucp_proto_rndv_put_common_init(const ucp_proto_init_params_t *init_params,
                               unsigned flags, size_t max_frag,
                               uint64_t rndv_modes, ucp_md_map_t prereg_md_map)
{
    const size_t atp_size                = sizeof(ucp_rndv_atp_hdr_t);
    ucp_context_t *context               = init_params->worker->context;
    ucp_proto_multi_init_params_t params = {
        .super.super         = *init_params,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority  = 0,
        .super.flags         = flags | UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS,
        .super.overhead      = 0,
        .super.latency       = 0,
        .super.min_length    = 1,
        .super.min_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.min_zcopy),
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.put.max_zcopy),
        .super.hdr_size      = 0,
        .max_lanes           = context->config.ext.max_rndv_lanes,
        .max_frag            = max_frag,
        .first.tl_cap_flags  = UCT_IFACE_FLAG_PUT_ZCOPY,
        .first.lane_type     = UCP_LANE_TYPE_RMA_BW,
        .middle.tl_cap_flags = UCT_IFACE_FLAG_PUT_ZCOPY,
        .middle.lane_type    = UCP_LANE_TYPE_RMA_BW,
        .prereg_md_map       = prereg_md_map
    };
    ucp_proto_rndv_bulk_priv_t *rpriv;
    const uct_iface_attr_t *iface_attr;
    ucp_lane_index_t lane_idx, lane;
    int atp_same_lane;
    ucs_status_t status;

    if ((init_params->select_param->op_id != UCP_OP_ID_RNDV_SEND) ||
        (init_params->select_param->dt_class != UCP_DATATYPE_CONTIG)) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_bulk_init(&params);
    if (status != UCS_OK) {
        return status;
    }

    /* check if all lanes support AM */
    rpriv         = params.super.super.priv;
    atp_same_lane = 1;
    for (lane_idx = 0; lane_idx < rpriv->mpriv.num_lanes; ++lane_idx) {
        lane          = rpriv->mpriv.lanes[lane_idx].super.lane;
        iface_attr    = ucp_proto_common_get_iface_attr(init_params, lane);
        atp_same_lane = atp_same_lane &&
                        (((iface_attr->cap.flags & UCT_IFACE_FLAG_AM_SHORT) &&
                          (iface_attr->cap.am.max_short >= atp_size)) ||
                         ((iface_attr->cap.flags & UCT_IFACE_FLAG_AM_BCOPY) &&
                          (iface_attr->cap.am.max_bcopy >= atp_size)));
    }

    /* All lanes can send ATP - invalidate am_lane, to use mpriv->lanes.
     * Otherwise, would need to flush all lanes and send ATP on
     * rpriv->super.lane when the flush is completed
     */
    if (atp_same_lane) {

        // commented out the below code - force flush mode
        // TODO add UCP context config param
        //rpriv->super.lane = UCP_NULL_LANE;
    }

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE int
ucp_proto_rndv_put_common_use_fence(const ucp_proto_rndv_bulk_priv_t *rpriv)
{
    return rpriv->super.lane == UCP_NULL_LANE;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_send(ucp_request_t *req,
                               const ucp_proto_multi_lane_priv_t *lpriv,
                               const uct_iov_t *iov, uct_completion_t *comp)
{
    ucp_rkey_h    rkey = req->send.rndv.rkey;
    uct_rkey_t tl_rkey = rkey->tl_rkey[lpriv->super.rkey_index].rkey.rkey;

    return uct_ep_put_zcopy(req->send.ep->uct_eps[lpriv->super.lane], iov, 1,
                            req->send.rndv.remote_address +
                            req->send.state.dt_iter.offset, tl_rkey, comp);
}

static void ucp_proto_rndv_put_common_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_rkey_destroy(req->send.rndv.rkey);
    ucp_proto_request_zcopy_complete(req, req->send.state.uct_comp.status);
}


static void ucp_proto_rndv_put_flush_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    if (ucs_likely(req->send.state.uct_comp.status == UCS_OK)) {
        ucp_proto_completion_init(&req->send.state.uct_comp,
                                  ucp_proto_rndv_put_common_completion);
        ucp_request_send(req, 0);
    } else {
        ucp_proto_rndv_put_common_completion(uct_comp);
    }
}

static ucs_status_t
ucp_proto_rndv_put_common_flush_send(ucp_request_t *req, ucp_lane_index_t lane)
{
    return uct_ep_flush(req->send.ep->uct_eps[lane], 0,
                        &req->send.state.uct_comp);
}

static size_t ucp_proto_rndv_put_common_pack_atp(void *dest, void *arg)
{
    ucp_request_t *req                      = arg;
    ucp_rndv_atp_hdr_t *atp                 = dest;
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    atp->super.req_id = req->send.rndv.remote_req_id;
    atp->super.status = UCS_OK;

    if (ucp_proto_rndv_put_common_use_fence(rpriv)) {
        atp->count = rpriv->mpriv.num_lanes;
    } else {
        atp->count = 1;
    }

    return sizeof(*atp);
}

static ucs_status_t
ucp_proto_rndv_put_common_atp_send(ucp_request_t *req, ucp_lane_index_t lane)
{
    ucs_status_t status;

    status = uct_ep_fence(req->send.ep->uct_eps[lane], 0);
    if (ucs_unlikely(status != UCS_OK)) {
        return status;
    }

    return ucp_proto_am_bcopy_single_send(req, UCP_AM_ID_RNDV_ATP, lane,
                                          ucp_proto_rndv_put_common_pack_atp,
                                          req, sizeof(ucp_rndv_atp_hdr_t));
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_put_common_request_init(ucp_request_t *req)
{
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    if (ucp_proto_rndv_put_common_use_fence(rpriv)) {
        /* Send fence+ATP on all lanes */
        ucp_proto_request_zcopy_init(req, rpriv->mpriv.reg_md_map,
                                     ucp_proto_rndv_put_common_completion,
                                     UCT_MD_MEM_ACCESS_LOCAL_READ);
        req->send.rndv.put.atp_map   = rpriv->mpriv.lane_map;
        req->send.rndv.put.flush_map = 0;
    } else {
        /* Flush all lanes and send ATP on control messages lane */
        ucp_proto_request_zcopy_init(req, rpriv->mpriv.reg_md_map,
                                     ucp_proto_rndv_put_flush_completion,
                                     UCT_MD_MEM_ACCESS_LOCAL_READ);
        req->send.rndv.put.atp_map   = UCS_BIT(rpriv->super.lane);
        req->send.rndv.put.flush_map = rpriv->mpriv.lane_map;
    }
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_common_notify_progress(ucp_request_t *req)
{
    if (req->send.rndv.put.flush_map != 0) {
        /* Flush lanes */
        ucp_trace_req(req, "rndv_put send flush, map 0x%x comp_count %u",
                      req->send.rndv.put.flush_map,
                      req->send.state.uct_comp.count);
        return ucp_proto_common_lane_map_progress(
                req, &req->send.rndv.put.flush_map,
                ucp_proto_rndv_put_common_flush_send);
    }

    /* Send ATP */
    ucp_trace_req(req, "rndv_put send atp, map 0x%x comp_count %u",
                  req->send.rndv.put.flush_map, req->send.state.uct_comp.count);
    return ucp_proto_common_lane_map_progress(
            req, &req->send.rndv.put.atp_map,
            ucp_proto_rndv_put_common_atp_send);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_put_zcopy_send_func(ucp_request_t *req,
                                   const ucp_proto_multi_lane_priv_t *lpriv,
                                   ucp_datatype_iter_t *next_iter)
{
    uct_iov_t iov;

    ucp_datatype_iter_next_iov(&req->send.state.dt_iter, lpriv->super.memh_index,
                               ucp_proto_multi_max_payload(req, lpriv, 0),
                               next_iter, &iov);
    return ucp_proto_rndv_put_common_send(req, lpriv, &iov, &req->send.state.uct_comp);
}

static ucs_status_t ucp_proto_rndv_put_zcopy_progress(uct_pending_req_t *uct_req)
{
    /*!
     * Build the progress differently:
     * 1. ep_put_zcopy
     * 2. when reached the end:
     *      2.1  = 1 lane: fence + send ATP
     *      2.2  > 1 lane: flush all lanes and send ATP when flush done
     * 3. after sending ATP, decrement completion by 1 to finish
     */
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        ucp_proto_rndv_put_common_request_init(req);
        ucp_proto_multi_request_init(req);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

   if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
       return ucp_proto_rndv_put_common_notify_progress(req);
   } else {
       /* Send data */
       return ucp_proto_multi_progress(
               req, &rpriv->mpriv, ucp_proto_rndv_put_zcopy_send_func,
               ucp_proto_rndv_put_common_notify_progress,
               UCS_BIT(UCP_DATATYPE_CONTIG));
   }
}

static ucs_status_t
ucp_proto_rndv_put_zcopy_init(const ucp_proto_init_params_t *init_params)
{
    return ucp_proto_rndv_put_common_init(init_params,
                                          UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY,
                                          SIZE_MAX,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_ZCOPY), 0);
}

static ucp_proto_t ucp_rndv_put_zcopy_proto = {
    .name        = "rndv/put/zcopy",
    .flags       = 0,
    .init        = ucp_proto_rndv_put_zcopy_init,
    .config_str  = ucp_proto_rndv_bulk_config_str,
    .progress    = ucp_proto_rndv_put_zcopy_progress,
};
UCP_PROTO_REGISTER(&ucp_rndv_put_zcopy_proto);


static void
ucp_proto_rndv_put_ppln_frag_send_completion(uct_completion_t *uct_comp)
{
    ucp_rndv_frag_t *frag = ucs_container_of(uct_comp, ucp_rndv_frag_t, comp);

    // we probably don't care when the frag is finished being sent, since ATP
    // will be schedule by flush/fence, and data is already copied out of user
    // buffer. This is similar to UCT's bcopy method.
    ucs_mpool_put_inline(frag);
}

static void
ucp_proto_rndv_put_ppln_frag_prepare_to_send(ucp_request_t *req)
{
    ucp_rndv_frag_t *frag = req->send.frag;

    ucp_proto_completion_init(&frag->comp,
                              ucp_proto_rndv_put_ppln_frag_send_completion);
}

static void
ucp_proto_rndv_put_ppln_frag_copy_completion(uct_completion_t *uct_comp)
{
    ucp_rndv_frag_t *frag = ucs_container_of(uct_comp, ucp_rndv_frag_t, comp);
    ucp_request_t *req    = frag->req;

    ucp_trace_req(req, "frag %p copy-in completed", frag);
    ucp_proto_rndv_put_ppln_frag_prepare_to_send(req);
    ucp_request_send(req, 0);
}

static ucs_status_t ucp_proto_rndv_put_ppln_frag_init(ucp_request_t *req)
{
    ucp_worker_h worker   = req->send.ep->worker;
    size_t frag_size      = worker->context->config.ext.rndv_frag_size;
    ucp_rndv_frag_t *frag = req->send.frag;
    ucs_status_t status;
    size_t length;
    void *buffer;

    frag->req = req;

    length = ucp_datatype_iter_get_ptr(&req->send.state.dt_iter, frag_size,
                                       &buffer);
    status = ucp_proto_rndv_ppln_frag_copy(
            req, frag, buffer, length, uct_ep_get_zcopy,
            ucp_proto_rndv_put_ppln_frag_copy_completion, "in from");
    if (status == UCS_OK) {
        /* copy finished, can keep on schedule queue */
        ucp_proto_rndv_put_ppln_frag_prepare_to_send(req);
        return UCS_INPROGRESS;
    } else if (status == UCS_INPROGRESS) {
        /* copy not finished, need to desched */
        return UCS_OK;
    } else {
        ucp_proto_request_abort(req, status);
        return UCS_OK;
    }
}

static ucs_status_t
ucp_proto_rndv_put_ppln_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;
    size_t total_length;

    if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
        return ucp_proto_rndv_put_common_notify_progress(req);
    } else {
        total_length = (req->flags & UCP_REQUEST_FLAG_RNDV_FRAG) ?
                               req->super_req->send.state.dt_iter.length :
                               req->send.state.dt_iter.length;
        return ucp_proto_rndv_ppln_send_progress(
                req, &rpriv->mpriv, total_length,
                ucp_proto_rndv_put_common_completion,
                ucp_proto_rndv_put_ppln_frag_init,
                ucp_proto_rndv_put_common_send,
                ucp_proto_rndv_put_common_notify_progress);
    }
}

static ucs_status_t
ucp_proto_rndv_put_ppln_init(const ucp_proto_init_params_t *init_params)
{
    ucp_worker_h worker    = init_params->worker;
    ucp_context_t *context = worker->context;
    unsigned flags         = UCP_PROTO_COMMON_INIT_FLAG_MEM_TYPE |
                             UCP_PROTO_COMMON_INIT_FLAG_ASYNC_COPY;
    ucp_md_map_t prereg_md_map;
    ucs_status_t status;

    if (!ucp_proto_rndv_ppln_is_supported(init_params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_ppln_get_frag_md_map(worker, &prereg_md_map);
    if (status != UCS_OK) {
        return status;
    }

    return ucp_proto_rndv_put_common_init(init_params, flags,
                                          context->config.ext.rndv_frag_size,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_PIPELINE),
                                          prereg_md_map);
}

static ucp_proto_t ucp_rndv_put_ppln_proto = {
    .name        = "rndv/put/ppln",
    .flags       = 0,
    .init        = ucp_proto_rndv_put_ppln_init,
    .config_str  = ucp_proto_rndv_bulk_config_str,
    .progress    = ucp_proto_rndv_put_ppln_progress,
};
UCP_PROTO_REGISTER(&ucp_rndv_put_ppln_proto);
