/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "proto_rndv.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/proto/proto_multi.inl>


enum {
    UCP_PROTO_RNDV_PPLN_STAGE_SEND = UCP_PROTO_STAGE_START,

    /* Send ATS/ATP */
    UCP_PROTO_RNDV_PPLN_STAGE_ACK,
};

typedef struct {
    /* Which protocol will be used for each fragment */
    ucp_proto_select_elem_t frag_proto;

    /* Fragment size to push to the underlying protocol */
    size_t                  frag_size;

    /* Lane for sending the ack message */
    ucp_lane_index_t        ack_lane;

} ucp_proto_rndv_ppln_priv_t;


static ucs_status_t
ucp_proto_rndv_ppln_init(const ucp_proto_init_params_t *init_params)
{
    ucp_worker_h worker               = init_params->worker;
    ucp_proto_rndv_ppln_priv_t *rpriv = init_params->priv;
    ucp_proto_caps_t *caps            = init_params->caps;
    const ucp_proto_perf_range_t *perf_range, *best_perf_range;
    const ucp_proto_select_elem_t *select_elem;
    ucp_proto_select_param_t sel_param;
    ucp_rkey_config_t *rkey_config;
    double perf_m, best_perf_m;

    if ((init_params->rkey_cfg_index == UCP_WORKER_CFG_INDEX_NULL) ||
        (init_params->select_param->op_flags & UCP_PROTO_SELECT_OP_FLAG_PPLN)) {
        return UCS_ERR_UNSUPPORTED;
    }

    /* Find lane to send the ack message */
    rpriv->ack_lane = ucp_proto_common_find_am_bcopy_lane(init_params);
    if (rpriv->ack_lane == UCP_NULL_LANE) {
        return UCS_ERR_NO_ELEM;
    }

    /* Select a protocol for rndv recv */
    sel_param          = *init_params->select_param;
    sel_param.op_flags = UCP_PROTO_SELECT_OP_FLAG_PPLN;
    rkey_config        = &worker->rkey_config[init_params->rkey_cfg_index];
    select_elem        = ucp_proto_select_lookup_slow(worker,
                                                      &rkey_config->proto_select,
                                                      init_params->ep_cfg_index,
                                                      init_params->rkey_cfg_index,
                                                      &sel_param);
    if (select_elem == NULL) {
        return UCS_ERR_UNSUPPORTED;
    }

    /* Find protocol with best bandwidth when used in pipeline mode */
    perf_range      = select_elem->perf_ranges;
    best_perf_range = NULL; /* Silence bogus warning */
    best_perf_m     = 0; /* Silence bogus warning */
    do {
        /* Pipeline bandwidth: worst between bandwidth and amortized overhead */
        perf_m = ucs_max(perf_range->perf.c / perf_range->max_length,
                         perf_range->perf.m);
        if ((perf_range == select_elem->perf_ranges) ||
            (perf_m < best_perf_m)) {
            best_perf_m     = perf_m;
            best_perf_range = perf_range;
        }
    } while ((perf_range++)->max_length != SIZE_MAX);

    /* Initialize private data */
    *init_params->priv_size = sizeof(*rpriv);
    rpriv->frag_proto       = *select_elem;
    rpriv->frag_size        = best_perf_range->max_length;

    /* The pipeline protocol only covers ranges beyond the maximal fragment
    *  size. There is no point to conver smaller ranges, since better protocols
    *  exist there.
     */
    caps->cfg_thresh           = worker->context->config.ext.rndv_thresh;
    caps->cfg_priority         = 60;
    caps->min_length           = rpriv->frag_size + 1;
    caps->num_ranges           = 1;
    caps->ranges[0].max_length = SIZE_MAX;
    caps->ranges[0].perf.c     = best_perf_range->perf.c + 50e-9;
    caps->ranges[0].perf.m     = best_perf_m;

    return UCS_OK;
}

static void ucp_proto_rndv_ppln_complete_one(void *request, ucs_status_t status,
                                             void *user_data)
{
    ucp_request_t *freq = (ucp_request_t*)request - 1;
    ucp_request_t *req  = ucp_request_user_data_get_super(request, user_data);

    if (ucp_proto_rndv_frag_completed(req, freq)) {
        ucp_proto_request_set_stage(req, UCP_PROTO_RNDV_PPLN_STAGE_ACK);
        ucp_request_send(req, 0);
    }
}

static ucs_status_t ucp_proto_rndv_ppln_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req  = ucs_container_of(uct_req, ucp_request_t, send.uct);
    ucp_worker_h worker = req->send.ep->worker;
    const ucp_proto_rndv_ppln_priv_t *rpriv;
    ucp_datatype_iter_t next_iter;
    ucs_status_t status;
    ucp_request_t *freq;

    /* Nested pipeline is prevented during protocol selection */
    ucs_assert(!(req->flags & UCP_REQUEST_FLAG_RNDV_FRAG));
    ucs_assert(!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED));
    req->send.state.completed_size = 0;

    rpriv = req->send.proto_config->priv;
    do {
        status = ucp_proto_rndv_frag_request_alloc(
                worker, req, ucp_proto_rndv_ppln_complete_one, &freq);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            break;
        }

        /* Initialize datatype for the fragment */
        ucp_datatype_iter_next_slice(&req->send.state.dt_iter, rpriv->frag_size,
                                     &freq->send.state.dt_iter, &next_iter);

        /* Initialize rendezvous parameters */
        freq->send.rndv.remote_req_id  = UCS_PTR_MAP_KEY_INVALID;
        freq->send.rndv.remote_address = req->send.rndv.remote_address +
                                         req->send.state.dt_iter.offset;
        freq->send.rndv.rkey           = req->send.rndv.rkey;
        freq->send.rndv.offset         = req->send.rndv.offset +
                                         req->send.state.dt_iter.offset;
        ucp_proto_request_select_proto(req, &rpriv->frag_proto,
                                       req->send.state.dt_iter.length);

        ucp_trace_req(req, "send fragment request %p", freq);
        ucp_request_send(freq, 0);

    } while (!ucp_datatype_iter_is_next_end(&req->send.state.dt_iter,
                                            &next_iter));
    return UCS_OK;
}

static void ucp_proto_rndv_ppln_config_str(size_t min_length, size_t max_length,
                                           const void *priv,
                                           ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_ppln_priv_t *rpriv = priv;

    ucs_string_buffer_appendf(strb, "frag:%zu ", rpriv->frag_size);
    ucp_proto_threshold_elem_str(rpriv->frag_proto.thresholds, min_length,
                                 max_length, strb);
}

static ucs_status_t
ucp_proto_rndv_send_ppln_init(const ucp_proto_init_params_t *init_params)
{
    if (init_params->select_param->op_id != UCP_OP_ID_RNDV_SEND) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_ppln_init(init_params);
}

static size_t ucp_proto_rndv_send_ppln_pack_atp(void *dest, void *arg)
{
    return ucp_proto_rndv_send_pack_atp(arg, dest, 1);
}

static ucs_status_t
ucp_proto_rndv_send_ppln_atp_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_ppln_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_am_bcopy_single_progress(
            req, UCP_AM_ID_RNDV_ATP, rpriv->ack_lane,
            ucp_proto_rndv_send_ppln_pack_atp, req, sizeof(ucp_rndv_atp_hdr_t),
            ucp_proto_request_complete_success);
}

static ucp_proto_t ucp_rndv_send_ppln_proto = {
    .name       = "rndv/send/ppln",
    .flags      = 0,
    .init       = ucp_proto_rndv_send_ppln_init,
    .config_str = ucp_proto_rndv_ppln_config_str,
    .progress   = {
        [UCP_PROTO_RNDV_PPLN_STAGE_SEND] = ucp_proto_rndv_ppln_progress,
        [UCP_PROTO_RNDV_PPLN_STAGE_ACK]  = ucp_proto_rndv_send_ppln_atp_progress,
    },
};
UCP_PROTO_REGISTER(&ucp_rndv_send_ppln_proto);

static ucs_status_t
ucp_proto_rndv_recv_ppln_init(const ucp_proto_init_params_t *init_params)
{
    if (init_params->select_param->op_id != UCP_OP_ID_RNDV_RECV) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_ppln_init(init_params);
}

static ucs_status_t
ucp_proto_rndv_recv_ppn_ats_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_ppln_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_am_bcopy_single_progress(
            req, UCP_AM_ID_RNDV_ATS, rpriv->ack_lane, ucp_proto_rndv_pack_ack,
            req, sizeof(ucp_reply_hdr_t), ucp_proto_request_complete_success);
}

static ucp_proto_t ucp_rndv_recv_ppln_proto = {
    .name       = "rndv/recv/ppln",
    .flags      = 0,
    .init       = ucp_proto_rndv_recv_ppln_init,
    .config_str = ucp_proto_rndv_ppln_config_str,
    .progress   = {
        [UCP_PROTO_RNDV_PPLN_STAGE_SEND] = ucp_proto_rndv_ppln_progress,
        [UCP_PROTO_RNDV_PPLN_STAGE_ACK]  = ucp_proto_rndv_recv_ppn_ats_progress,
    },
};
UCP_PROTO_REGISTER(&ucp_rndv_recv_ppln_proto);
