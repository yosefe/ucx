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
    const ucp_proto_select_range_t *frag_range, *best_perf_range;
    const ucp_proto_select_elem_t *select_elem;
    ucp_proto_select_param_t sel_param;
    ucp_rkey_config_t *rkey_config;
    double perf_m, best_perf_m;

    if ((init_params->rkey_cfg_index == UCP_WORKER_CFG_INDEX_NULL) ||
        (init_params->select_param->dt_class != UCP_DATATYPE_CONTIG) ||
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
    sel_param.op_flags = UCP_PROTO_SELECT_OP_FLAG_PPLN |
                         0*ucp_proto_select_op_attr_to_flags(
                                 UCP_OP_ATTR_FLAG_MULTI_SEND);
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
    frag_range      = select_elem->ranges;
    best_perf_range = NULL; /* Silence bogus warning */
    best_perf_m     = 0; /* Silence bogus warning */
    do {
        /* Pipeline bandwidth: worst between bandwidth and amortized overhead */
        perf_m = ucs_max(frag_range->super.perf.c /
                                 frag_range->super.max_length,
                         frag_range->super.pperf.m);
        ucs_assertv(perf_m > 1.0 / (15000 * UCS_MBYTE), "perf_m=%e se=%p",
                    perf_m, select_elem);

        if ((frag_range == select_elem->ranges) ||
            (perf_m < best_perf_m)) {
            best_perf_m     = perf_m;
            best_perf_range = frag_range;
        }
    } while ((frag_range++)->super.max_length != SIZE_MAX);


    /* Initialize private data */
    *init_params->priv_size = sizeof(*rpriv);
    rpriv->frag_proto       = *select_elem;
    rpriv->frag_size        = best_perf_range->super.max_length;

    /* The pipeline protocol only covers ranges beyond the maximal fragment
    *  size. There is no point to conver smaller ranges, since better protocols
    *  exist there.
     */
    caps->cfg_thresh           = best_perf_range->cfg_thresh;
    caps->cfg_priority         = 0;
    caps->min_length           = rpriv->frag_size + 1;
    caps->num_ranges           = 1;
    caps->ranges[0].max_length = SIZE_MAX;
    caps->ranges[0].perf.c     = best_perf_range->super.perf.c + 50e-9;
    caps->ranges[0].perf.m     = best_perf_m;
    caps->ranges[0].pperf      = caps->ranges[0].perf;

    return UCS_OK;
}

static void
ucp_proto_rndv_ppln_frag_complete(ucp_request_t *freq, int send_ack,
                                  ucp_proto_complete_cb_t complete_func)
{
    ucp_request_t *req = ucp_request_get_super(freq);

    req->send.rndv.ppln.send_ack |= send_ack;
    if (!ucp_proto_rndv_frag_complete(req, freq)) {
        return;
    }

    if (req->send.rndv.rkey != NULL) {
        ucp_proto_rndv_rkey_destroy(req);
    }

    if (req->send.rndv.ppln.send_ack) {
        ucp_proto_request_set_stage(req, UCP_PROTO_RNDV_PPLN_STAGE_ACK);
        ucp_request_send(req, 0);
    } else {
        complete_func(req);
    }
}

void ucp_proto_rndv_ppln_send_frag_complete(ucp_request_t *freq, int send_ack)
{
    ucp_proto_rndv_ppln_frag_complete(freq, send_ack,
                                      ucp_proto_request_complete_success);
}

void ucp_proto_rndv_ppln_recv_frag_complete(ucp_request_t *freq, int send_ack)
{
    ucp_proto_rndv_ppln_frag_complete(freq, send_ack,
                                      ucp_proto_rndv_recv_complete);
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

    req->send.state.completed_size = 0;
    req->send.rndv.ppln.send_ack   = 0;
    rpriv                          = req->send.proto_config->priv;
    for (;;) {
        status = ucp_proto_rndv_frag_request_alloc(worker, req, &freq);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            return UCS_OK;
        }

        /* Initialize datatype for the fragment */
        ucp_datatype_iter_next_slice(&req->send.state.dt_iter, rpriv->frag_size,
                                     &freq->send.state.dt_iter, &next_iter);

        /* Initialize rendezvous parameters */
        freq->send.rndv.remote_req_id  = req->send.rndv.remote_req_id;
        freq->send.rndv.remote_address = req->send.rndv.remote_address +
                                         req->send.state.dt_iter.offset;
        freq->send.rndv.rkey           = req->send.rndv.rkey;
        freq->send.rndv.offset         = req->send.rndv.offset +
                                         req->send.state.dt_iter.offset;
        ucp_proto_request_select_proto(freq, &rpriv->frag_proto,
                                       freq->send.state.dt_iter.length);

        ucp_trace_req(req, "send fragment request %p", freq);
        ucp_request_send(freq, 0);

        if (ucp_datatype_iter_is_next_end(&req->send.state.dt_iter,
                                          &next_iter)) {
            return UCS_OK;
        }

        // TODO non-contig?
        ucp_datatype_iter_copy_from_next(&req->send.state.dt_iter, &next_iter,
                                         UCS_BIT(UCP_DATATYPE_CONTIG));
    }
}

static void ucp_proto_rndv_ppln_config_str(size_t min_length, size_t max_length,
                                           const void *priv,
                                           ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_ppln_priv_t *rpriv = priv;
    char str[128];

    ucs_memunits_to_str(rpriv->frag_size, str, sizeof(str));
    ucs_string_buffer_appendf(strb, "fr:%s ", str);
    ucp_proto_threshold_elem_str(rpriv->frag_proto.thresholds,
                                 ucs_min(rpriv->frag_size, min_length),
                                 ucs_min(rpriv->frag_size, max_length), strb);
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
ucp_proto_rndv_recv_ppln_ats_progress(uct_pending_req_t *uct_req)
{
    ucp_request_t *req = ucs_container_of(uct_req, ucp_request_t, send.uct);
    const ucp_proto_rndv_ppln_priv_t *rpriv = req->send.proto_config->priv;

    return ucp_proto_am_bcopy_single_progress(
            req, UCP_AM_ID_RNDV_ATS, rpriv->ack_lane, ucp_proto_rndv_pack_ack,
            req, sizeof(ucp_reply_hdr_t), ucp_proto_rndv_recv_complete);
}

static ucp_proto_t ucp_rndv_recv_ppln_proto = {
    .name       = "rndv/recv/ppln",
    .flags      = 0,
    .init       = ucp_proto_rndv_recv_ppln_init,
    .config_str = ucp_proto_rndv_ppln_config_str,
    .progress   = {
        [UCP_PROTO_RNDV_PPLN_STAGE_SEND] = ucp_proto_rndv_ppln_progress,
        [UCP_PROTO_RNDV_PPLN_STAGE_ACK]  = ucp_proto_rndv_recv_ppln_ats_progress,
    },
};
UCP_PROTO_REGISTER(&ucp_rndv_recv_ppln_proto);
