/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "proto_rndv.inl"
#include "rndv_ppln.inl"


static ucs_status_t
ucp_proto_rndv_get_common_init(const ucp_proto_init_params_t *init_params,
                               unsigned flags, size_t frag_size,
                               uint64_t rndv_modes, ucp_md_map_t prereg_md_map)
{
    ucp_context_t *context               = init_params->worker->context;
    ucp_proto_multi_init_params_t params = {
        .super.super         = *init_params,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority  = 0,
        .super.flags         = flags | UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY |
                               UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS |
                               UCP_PROTO_COMMON_INIT_FLAG_RESPONSE,
        .super.overhead      = 0,
        .super.latency       = 0,
        .max_lanes           = context->config.ext.max_rndv_lanes,
        .max_frag            = frag_size,
        .first.tl_cap_flags  = UCT_IFACE_FLAG_GET_ZCOPY,
        .super.min_length    = 1,
        .super.min_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.get.min_zcopy),
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t,
                                            cap.get.max_zcopy),
        .first.lane_type     = UCP_LANE_TYPE_RMA_BW,
        .super.hdr_size      = 0,
        .middle.tl_cap_flags = UCT_IFACE_FLAG_GET_ZCOPY,
        .middle.lane_type    = UCP_LANE_TYPE_RMA_BW,
        .prereg_md_map       = prereg_md_map
    };

    if ((init_params->select_param->op_id != UCP_OP_ID_RNDV_RECV) ||
        (init_params->select_param->dt_class != UCP_DATATYPE_CONTIG)) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_bulk_init(&params);
}

static ucs_status_t ucp_proto_rndv_get_common_complete(ucp_request_t *req)
{
    ucp_rkey_destroy(req->send.rndv.rkey);
    ucp_proto_request_zcopy_complete(req, req->send.state.uct_comp.status);
    return UCS_OK;
}

static void ucp_proto_rndv_get_common_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);

    ucp_trace_req(req, "%s completed", req->send.proto_config->proto->name);
    ucp_request_send(req, 0); /* reschedule to send ATS */
}

static ucs_status_t
ucp_proto_rndv_get_zcopy_init(const ucp_proto_init_params_t *init_params)
{
    return ucp_proto_rndv_get_common_init(init_params,
                                          UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY,
                                          SIZE_MAX,
                                          UCS_BIT(UCP_RNDV_MODE_GET_ZCOPY), 0);
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

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_rndv_get_zcopy_send_func(ucp_request_t *req,
                                   const ucp_proto_multi_lane_priv_t *lpriv,
                                   ucp_datatype_iter_t *next_iter)
{
    uct_iov_t iov;

    ucp_datatype_iter_next_iov(&req->send.state.dt_iter,
                               lpriv->super.memh_index,
                               ucp_proto_multi_max_payload(req, lpriv, 0),
                               next_iter, &iov);
    return ucp_proto_rndv_get_common_send(req, lpriv, &iov,
                                          &req->send.state.uct_comp);
}

static ucs_status_t ucp_proto_rndv_get_zcopy_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
        return ucp_proto_rndv_ack_progress(
                req, UCP_AM_ID_RNDV_ATS, ucp_proto_rndv_get_common_complete);
    } else {
        return ucp_proto_multi_zcopy_progress(
                req, &rpriv->mpriv, NULL, UCT_MD_MEM_ACCESS_LOCAL_WRITE,
                ucp_proto_rndv_get_zcopy_send_func,
                ucp_proto_rndv_get_common_completion);
    }
}

static ucp_proto_t ucp_rndv_get_zcopy_proto = {
    .name       = "rndv/get/zcopy",
    .flags      = 0,
    .init       = ucp_proto_rndv_get_zcopy_init,
    .config_str = ucp_proto_rndv_bulk_config_str,
    .progress   = ucp_proto_rndv_get_zcopy_progress
};
UCP_PROTO_REGISTER(&ucp_rndv_get_zcopy_proto);


static ucs_status_t ucp_proto_rndv_get_ppln_frag_init(ucp_request_t *req)
{
    ucp_worker_h worker = req->send.ep->worker;
    ucp_rndv_frag_t *frag = req->send.frag;

    /* count outstanding fragments */
    ++req->send.state.uct_comp.count;

    frag->req       = req;
    frag->offset    = req->send.state.dt_iter.offset;
    frag->length    = ucs_min(worker->context->config.ext.rndv_frag_size,
                              req->send.state.dt_iter.length - frag->offset);
    ucp_proto_completion_init(&frag->comp,
                              ucp_proto_rndv_ppln_frag_recv_completion);
    return UCS_INPROGRESS;
}

static ucs_status_t ucp_proto_rndv_get_ppln_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_rndv_bulk_priv_t *rpriv = req->send.proto_config->priv;

    if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
        return ucp_proto_rndv_ack_progress(req, UCP_AM_ID_RNDV_ATS,
                                           ucp_proto_rndv_get_common_complete);
    } else {
        return ucp_proto_rndv_ppln_send_progress(
                req, &rpriv->mpriv, req->send.state.dt_iter.length,
                ucp_proto_rndv_get_common_completion,
                ucp_proto_rndv_get_ppln_frag_init,
                ucp_proto_rndv_get_common_send,
                ucp_request_invoke_uct_completion_success);
    }
}

static ucs_status_t
ucp_proto_rndv_get_ppln_init(const ucp_proto_init_params_t *init_params)
{
    ucp_worker_h worker    = init_params->worker;
    ucp_context_t *context = worker->context;
    unsigned flags         = UCP_PROTO_COMMON_INIT_FLAG_MEM_TYPE |
                             UCP_PROTO_COMMON_INIT_FLAG_ASYNC_COPY;
    // ucp_proto_select_param_t select_param;
    // ucp_proto_init_params_t params;
    ucp_md_map_t prereg_md_map;
    ucs_status_t status;

    if (!ucp_proto_rndv_ppln_is_supported(init_params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_ppln_get_frag_md_map(worker, &prereg_md_map);
    if (status != UCS_OK) {
        return status;
    }

    // select_param          = *init_params->select_param;
    // select_param.mem_type = UCS_MEMORY_TYPE_HOST;
    // select_param.sys_dev  = UCS_SYS_DEVICE_ID_UNKNOWN;

    // params              = *init_params;
    // params.select_param = &select_param;

    return ucp_proto_rndv_get_common_init(init_params, flags,
                                          context->config.ext.rndv_frag_size,
                                          UCS_BIT(UCP_RNDV_MODE_GET_PIPELINE),
                                          prereg_md_map);
}

static ucp_proto_t ucp_rndv_get_ppln_proto = {
    .name       = "rndv/get/ppln",
    .flags      = 0,
    .init       = ucp_proto_rndv_get_ppln_init,
    .config_str = ucp_proto_rndv_bulk_config_str,
    .progress   = ucp_proto_rndv_get_ppln_progress
};
UCP_PROTO_REGISTER(&ucp_rndv_get_ppln_proto);


static ucs_status_t
ucp_proto_rndv_ats_init(const ucp_proto_init_params_t *params)
{
    ucs_status_t status;

    if (params->select_param->op_id != UCP_OP_ID_RNDV_RECV) {
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
    params->caps->cfg_priority         = 1;
    params->caps->min_length           = 0;
    params->caps->num_ranges           = 1;
    params->caps->ranges[0].max_length = 0;
    params->caps->ranges[0].perf       = ucp_proto_rndv_ack_time(params);
    return UCS_OK;
}

static ucs_status_t ucp_proto_rndv_ats_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);

    return ucp_proto_rndv_ack_progress(
            req, UCP_AM_ID_RNDV_ATS, ucp_proto_request_zcopy_complete_success);
}

static ucp_proto_t ucp_rndv_ats_proto = {
    .name       = "rndv/ats",
    .flags      = 0,
    .init       = ucp_proto_rndv_ats_init,
    .config_str = ucp_proto_rndv_ack_config_str,
    .progress   = ucp_proto_rndv_ats_progress
};
UCP_PROTO_REGISTER(&ucp_rndv_ats_proto);
