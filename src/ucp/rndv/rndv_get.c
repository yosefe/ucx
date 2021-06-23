/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "proto_rndv.inl"
#include "rndv_mtcopy.inl"


enum {
     UCP_PROTO_RNDV_GET_STAGE_FETCH = UCP_PROTO_STAGE_START,
     UCP_PROTO_RNDV_GET_STAGE_ATS
};

static ucs_status_t
ucp_proto_rndv_get_common_init(const ucp_proto_init_params_t *init_params,
                               uint64_t rndv_modes, size_t max_length,
                               unsigned flags, ucp_md_map_t prereg_md_map)
{
    ucp_context_t *context               = init_params->worker->context;
    ucp_proto_multi_init_params_t params = {
        .super.super         = *init_params,
        .super.latency       = 0,
        .super.overhead      = 0,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority  = 0,
        .super.min_length    = 1,
        .super.max_length    = max_length,
        .super.min_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.get.min_zcopy),
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.get.max_zcopy),
        .super.hdr_size      = 0,
        .super.flags         = flags | UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS |
                               UCP_PROTO_COMMON_INIT_FLAG_RESPONSE,
        .max_lanes           = context->config.ext.max_rndv_lanes,
        .max_frag            = max_length,
        .prereg_md_map       = prereg_md_map,
        .first.lane_type     = UCP_LANE_TYPE_RMA_BW,
        .first.tl_cap_flags  = UCT_IFACE_FLAG_GET_ZCOPY,
        .middle.lane_type    = UCP_LANE_TYPE_RMA_BW,
        .middle.tl_cap_flags = UCT_IFACE_FLAG_GET_ZCOPY,
    };

    if ((init_params->select_param->op_id != UCP_OP_ID_RNDV_RECV) ||
        (init_params->select_param->dt_class != UCP_DATATYPE_CONTIG)) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_bulk_init(&params,
                                    ucs_offsetof(ucp_proto_rndv_bulk_priv_t,
                                                 mpriv));
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_get_common_request_init(ucp_request_t *req)
{
    ucp_proto_rndv_bulk_request_init(req, req->send.proto_config->priv);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_get_common_send(ucp_request_t *req,
                               const ucp_proto_multi_lane_priv_t *lpriv,
                               const uct_iov_t *iov, uct_completion_t *comp)
{
    ucp_rkey_h    rkey = req->send.rndv.rkey;
    uct_rkey_t tl_rkey = rkey->tl_rkey[lpriv->super.rkey_index].rkey.rkey;

    return uct_ep_get_zcopy(req->send.ep->uct_eps[lpriv->super.lane], iov, 1,
                            req->send.rndv.remote_address +
                            req->send.state.dt_iter.offset, tl_rkey, comp);
}

static ucs_status_t
ucp_proto_rndv_get_common_ats_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_ack_priv_t *apriv = req->send.proto_config->priv;

    ucs_assert(ucp_datatype_iter_is_end(&req->send.state.dt_iter));
    return ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_RNDV_ATS,
                                              apriv->lane,
                                              ucp_proto_rndv_pack_ack, req,
                                              sizeof(ucp_reply_hdr_t),
                                              ucp_proto_rndv_recv_complete);
}

static void
ucp_proto_rndv_get_common_complete(ucp_request_t *req)
{
    ucp_proto_rndv_rkey_destroy(req);
    ucp_proto_request_set_stage(req, UCP_PROTO_RNDV_GET_STAGE_ATS);
    ucp_request_send(req, 0);
}

static void
ucp_proto_rndv_get_zcopy_fetch_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_proto_rndv_get_common_complete(req);
}

static ucs_status_t
ucp_proto_rndv_get_zcopy_init(const ucp_proto_init_params_t *init_params)
{
    if (ucp_proto_rndv_init_params_is_ppln_frag(init_params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_get_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_GET_ZCOPY),
                                          SIZE_MAX,
                                          UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY,
                                          0);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_get_zcopy_send_func(ucp_request_t *req,
                                   const ucp_proto_multi_lane_priv_t *lpriv,
                                   ucp_datatype_iter_t *next_iter)
{
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;
    size_t max_payload;
    uct_iov_t iov;

    max_payload = ucp_proto_rndv_bulk_max_payload(req, rpriv, lpriv);
    ucp_datatype_iter_next_iov(&req->send.state.dt_iter, max_payload,
                               lpriv->super.memh_index, next_iter, &iov);
    return ucp_proto_rndv_get_common_send(req, lpriv, &iov,
                                          &req->send.state.uct_comp);
}

static ucs_status_t
ucp_proto_rndv_get_zcopy_fetch_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_multi_zcopy_progress(
            req, &rpriv->mpriv, ucp_proto_rndv_get_common_request_init,
            UCT_MD_MEM_ACCESS_LOCAL_WRITE, ucp_proto_rndv_get_zcopy_send_func,
            ucp_request_invoke_uct_completion_success,
            ucp_proto_rndv_get_zcopy_fetch_completion);
}

static ucp_proto_t ucp_rndv_get_zcopy_proto = {
    .name       = "rndv/get/zcopy",
    .flags      = 0,
    .init       = ucp_proto_rndv_get_zcopy_init,
    .config_str = ucp_proto_rndv_bulk_config_str,
    .progress   = {
         [UCP_PROTO_RNDV_GET_STAGE_FETCH] = ucp_proto_rndv_get_zcopy_fetch_progress,
         [UCP_PROTO_RNDV_GET_STAGE_ATS]   = ucp_proto_rndv_get_common_ats_progress
    }
};
UCP_PROTO_REGISTER(&ucp_rndv_get_zcopy_proto);

static UCS_F_ALWAYS_INLINE ucs_status_t ucp_proto_rndv_get_mtcopy_send_func(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *lpriv,
        ucp_datatype_iter_t *next_iter)
{
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;
    uct_iov_t iov;

    ucp_proto_rndv_mtcopy_next_iov(req, rpriv, lpriv, next_iter, &iov);
    return ucp_proto_rndv_get_common_send(req, lpriv, &iov,
                                          &req->send.state.uct_comp);
}

static void
ucp_proto_rndv_get_mtcopy_unpack_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucs_mpool_put_inline(req->send.rndv.mdesc);
    if (ucp_proto_rndv_request_is_ppln_frag(req)) {
        ucp_proto_rndv_ppln_recv_frag_complete(req, 1);
    } else {
        ucp_proto_rndv_get_common_complete(req);
    }
}

static void
ucp_proto_rndv_get_mtcopy_fetch_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_proto_rndv_mtcopy_copy(req, uct_ep_put_zcopy,
                               ucp_proto_rndv_get_mtcopy_unpack_completion,
                               "out to");
}

static ucs_status_t
ucp_proto_rndv_get_mtcopy_fetch_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;
    ucs_status_t status;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        status = ucp_proto_rndv_mtcopy_request_init(req);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            return UCS_OK;
        }

        ucp_proto_rndv_get_common_request_init(req);
        ucp_proto_completion_init(&req->send.state.uct_comp,
                                  ucp_proto_rndv_get_mtcopy_fetch_completion);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    return ucp_proto_multi_progress(req, &rpriv->mpriv,
                                    ucp_proto_rndv_get_mtcopy_send_func,
                                    ucp_request_invoke_uct_completion_success,
                                    UCS_BIT(UCP_DATATYPE_CONTIG));
}

static ucs_status_t
ucp_proto_rndv_get_mtcopy_init(const ucp_proto_init_params_t *init_params)
{
    unsigned flags = UCP_PROTO_COMMON_INIT_FLAG_MEM_TYPE |
                     UCP_PROTO_COMMON_INIT_FLAG_ASYNC_COPY;
    ucp_md_map_t prereg_md_map;
    ucs_status_t status;
    size_t frag_size;

    status = ucp_proto_rndv_mtcopy_init(init_params, &prereg_md_map,
                                        &frag_size);
    if (status != UCS_OK) {
        return status;
    }

    return ucp_proto_rndv_get_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_GET_PIPELINE),
                                          frag_size, flags, prereg_md_map);
}

static ucp_proto_t ucp_rndv_get_mtcopy_proto = {
    .name       = "rndv/get/mtcopy",
    .flags      = 0,
    .init       = ucp_proto_rndv_get_mtcopy_init,
    .config_str = ucp_proto_rndv_bulk_config_str,
    .progress   = {
        [UCP_PROTO_RNDV_GET_STAGE_FETCH] = ucp_proto_rndv_get_mtcopy_fetch_progress,
        [UCP_PROTO_RNDV_GET_STAGE_ATS]   = ucp_proto_rndv_get_common_ats_progress,
    }
};
UCP_PROTO_REGISTER(&ucp_rndv_get_mtcopy_proto);


static ucs_status_t
ucp_proto_rndv_ats_init(const ucp_proto_init_params_t *params)
{
    ucs_status_t status;

    if ((params->select_param->op_id != UCP_OP_ID_RNDV_RECV) ||
        ucp_proto_rndv_init_params_is_ppln_frag(params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    if (params->rkey_config_key != NULL) {
        /* This ATS-only protocol will not take care of releasing the remote, so
           disqualify if remote key is present */
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_ack_init(params);
    if (status != UCS_OK) {
        return UCS_OK;
    }

    /* Support only 0-length messages */
    *params->priv_size                 = sizeof(ucp_proto_rndv_ack_priv_t);
    params->caps->cfg_thresh           = 0;
    params->caps->cfg_priority         = 0;
    params->caps->min_length           = 0;
    params->caps->num_ranges           = 1;
    params->caps->ranges[0].max_length = 0;
    params->caps->ranges[0].perf       = ucp_proto_rndv_ack_time(params);
    params->caps->ranges[0].pperf      = ucp_proto_rndv_ack_time(params);
    return UCS_OK;
}

static ucp_proto_t ucp_rndv_ats_proto = {
    .name       = "rndv/ats",
    .flags      = 0,
    .init       = ucp_proto_rndv_ats_init,
    .config_str = ucp_proto_rndv_ack_config_str,
    .progress   = {ucp_proto_rndv_get_common_ats_progress},
};
UCP_PROTO_REGISTER(&ucp_rndv_ats_proto);
