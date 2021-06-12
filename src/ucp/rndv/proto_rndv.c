/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "proto_rndv.inl"

#include <ucp/proto/proto_common.inl>


static void
ucp_proto_rndv_ctrl_get_md_map(const ucp_proto_rndv_ctrl_init_params_t *params,
                               ucp_md_map_t *md_map, uint64_t *sys_dev_map,
                               ucs_sys_dev_distance_t *sys_distance)
{
    ucp_worker_h worker                      = params->super.super.worker;
    const ucp_ep_config_key_t *ep_config_key = params->super.super.ep_config_key;
    ucp_rsc_index_t mem_sys_dev, ep_sys_dev;
    const uct_iface_attr_t *iface_attr;
    const uct_md_attr_t *md_attr;
    ucp_md_index_t md_index;
    ucp_lane_index_t lane;
    ucs_status_t status;

    /* md_map is all lanes which support get_zcopy on the given mem_type and
     * require remote key
     * TODO register only on devices close to the memory
     */
    *md_map      = 0;
    *sys_dev_map = 0;
    for (lane = 0; lane < ep_config_key->num_lanes; ++lane) {
        if (ep_config_key->lanes[lane].rsc_index == UCP_NULL_RESOURCE) {
            continue;
        }

        /* Check the lane supports get_zcopy */
        iface_attr = ucp_proto_common_get_iface_attr(&params->super.super,
                                                     lane);
        if (!(iface_attr->cap.flags & (UCT_IFACE_FLAG_GET_ZCOPY |
                                       UCT_IFACE_FLAG_PUT_ZCOPY))) {
            continue;
        }

        /* Check the memory domain requires remote key, and capable of
         * registering the memory type
         */
        ep_sys_dev  = ucp_proto_common_get_sys_dev(&params->super.super, lane);
        md_index = ucp_proto_common_get_md_index(&params->super.super, lane);
        md_attr  = &worker->context->tl_mds[md_index].attr;
        if (!(md_attr->cap.flags & UCT_MD_FLAG_NEED_RKEY) ||
            !(md_attr->cap.reg_mem_types & UCS_BIT(params->mem_info.type))) {
            continue;
        }

        *md_map |= UCS_BIT(md_index);

        if (ep_sys_dev < 64) {
            *sys_dev_map |= UCS_BIT(ep_sys_dev);

            mem_sys_dev = params->super.super.select_param->sys_dev;
            status      = ucs_topo_get_distance(mem_sys_dev, ep_sys_dev,
                                                sys_distance);
            ucs_assertv_always(status == UCS_OK,
                               "mem_info->sys_dev=%d sys_dev=%d", mem_sys_dev,
                               ep_sys_dev);
            ++sys_distance;
        }
    }
}

/*
 * Select (guess) the protocol that would be used by the remote peer.
 * We report the rendezvous protocol performance according to the protocol we
 * think the remote peer would select.
 */
static ucs_status_t ucp_proto_rndv_ctrl_select_remote_proto(
        const ucp_proto_rndv_ctrl_init_params_t *params,
        const ucp_proto_select_param_t *remote_select_param,
        ucp_proto_rndv_ctrl_priv_t *rpriv)
{
    ucp_worker_h worker                 = params->super.super.worker;
    ucp_worker_cfg_index_t ep_cfg_index = params->super.super.ep_cfg_index;
    const ucp_ep_config_t *ep_config    = &worker->ep_config[ep_cfg_index];
    ucs_sys_dev_distance_t lanes_distance[UCP_MAX_LANES];
    const ucp_proto_select_elem_t *select_elem;
    ucp_rkey_config_key_t rkey_config_key;
    ucp_worker_cfg_index_t rkey_cfg_index;
    ucp_rkey_config_t *rkey_config;
    ucs_status_t status;
    ucp_lane_index_t lane;

    /* Construct remote key for remote protocol lookup according to the local
     * buffer properties (since remote side is expected to access the local
     * buffer)
     */
    ucs_debug("params memtype: %s",
              ucs_memory_type_names[params->super.super.select_param->mem_type]);

    rkey_config_key.md_map       = rpriv->md_map;
    rkey_config_key.ep_cfg_index = ep_cfg_index;
    rkey_config_key.sys_dev      = params->mem_info.sys_dev;
    rkey_config_key.mem_type     = params->mem_info.type;
    for (lane = 0; lane < ep_config->key.num_lanes; ++lane) {
        ucp_proto_common_get_lane_distance(&params->super.super, lane,
                                           params->mem_info.sys_dev,
                                           &lanes_distance[lane]);
    }

    status = ucp_worker_rkey_config_get(worker, &rkey_config_key,
                                        lanes_distance, &rkey_cfg_index);
    if (status != UCS_OK) {
        return status;
    }

    rkey_config = &worker->rkey_config[rkey_cfg_index];
    select_elem = ucp_proto_select_lookup_slow(worker,
                                               &rkey_config->proto_select,
                                               ep_cfg_index, rkey_cfg_index,
                                               remote_select_param);
    if (select_elem == NULL) {
        ucs_debug("%s: did not find protocol for %s",
                  params->super.super.proto_name,
                  ucp_operation_names[params->remote_op_id]);
        return UCS_ERR_UNSUPPORTED;
    }

    rpriv->remote_proto = *select_elem;
    return UCS_OK;
}

ucs_status_t
ucp_proto_rndv_ctrl_init(const ucp_proto_rndv_ctrl_init_params_t *params)
{
    ucp_context_h context             = params->super.super.worker->context;
    ucp_proto_rndv_ctrl_priv_t *rpriv = params->super.super.priv;
    const ucp_proto_select_param_t *select_param =
            params->super.super.select_param;
    const ucp_proto_select_range_t *remote_range;
    ucp_proto_select_param_t remote_select_param;
    ucp_proto_perf_range_t *perf_range;
    const uct_iface_attr_t *iface_attr;
    ucs_linear_func_t send_overheads;
    ucs_linear_func_t xfer_time;
    ucp_memory_info_t mem_info;
    ucp_md_index_t md_index;
    ucp_proto_caps_t *caps;
    ucs_status_t status;
    double rts_latency;

    ucs_assert(params->super.flags & UCP_PROTO_COMMON_INIT_FLAG_RESPONSE);
    ucs_assert(!(params->super.flags & UCP_PROTO_COMMON_INIT_FLAG_MAX_FRAG));
    // ucs_assert(params->super.min_length > 0);

    /* Find lane to send the initial message */
    rpriv->lane = ucp_proto_common_find_am_bcopy_lane(&params->super.super);
    if (rpriv->lane == UCP_NULL_LANE) {
        return UCS_ERR_NO_ELEM;
    }

    ucs_debug("params memtype: %s",
              ucs_memory_type_names[select_param->mem_type]);

    /* Construct select parameter for the remote protocol */
    if (params->super.super.rkey_config_key == NULL) {
        /* Remote buffer is unknown, assume same params as local */
        remote_select_param          = *select_param;
        remote_select_param.op_id    = params->remote_op_id;
        remote_select_param.op_flags = 0;
    } else {
        /* If we know the remote buffer parameters, these are actually the local
         * parameters for the remote protocol
         */
        mem_info.sys_dev = params->super.super.rkey_config_key->sys_dev;
        mem_info.type    = params->super.super.rkey_config_key->mem_type;
        ucp_proto_select_param_init(&remote_select_param, params->remote_op_id,
                                    0, UCP_DATATYPE_CONTIG, &mem_info, 1);
    }

    // if (ucp_proto_rndv_init_params_is_ppln_frag(&params->super.super)) {
    //     remote_select_param.op_flags |= ucp_proto_select_op_attr_to_flags(
    //             UCP_OP_ATTR_FLAG_MULTI_SEND);
    // }

    /* Initialize estimated memory registration map */
    ucp_proto_rndv_ctrl_get_md_map(params, &rpriv->md_map, &rpriv->sys_dev_map,
                                   rpriv->sys_dev_distance);
    rpriv->packed_rkey_size = ucp_rkey_packed_size(context, rpriv->md_map,
                                                   select_param->sys_dev,
                                                   rpriv->sys_dev_map);
    ucs_debug("params memtype: %s",
              ucs_memory_type_names[select_param->mem_type]);

    /* Guess the protocol the remote side will select */
    // TODO set rkey_config in params according to local memtype
    status = ucp_proto_rndv_ctrl_select_remote_proto(params,
                                                     &remote_select_param,
                                                     rpriv);
    if (status != UCS_OK) {
        return status;
    }

    /* Set send_overheads to the time to send and receive RTS message */
    iface_attr     = ucp_proto_common_get_iface_attr(&params->super.super,
                                                     rpriv->lane);
    rts_latency    = (iface_attr->overhead * 2) +
                     ucp_tl_iface_latency(context, &iface_attr->latency);
    send_overheads = ucs_linear_func_make(rts_latency, 0.0);

    /* Add registration cost to send_overheads */
    ucs_for_each_bit(md_index, rpriv->md_map) {
        ucs_linear_func_add_inplace(&send_overheads,
                                    context->tl_mds[md_index].attr.reg_cost);
    }

    /* Set rendezvous protocol properties */
    *params->super.super.priv_size         = sizeof(ucp_proto_rndv_ctrl_priv_t);
    params->super.super.caps->cfg_thresh   = params->super.cfg_thresh;
    params->super.super.caps->cfg_priority = params->super.cfg_priority;
    params->super.super.caps->min_length   = params->super.min_length;
    params->super.super.caps->num_ranges   = 0;

    /* Copy performance ranges from the remote protocol, and add overheads */
    remote_range = rpriv->remote_proto.ranges;
    caps         = params->super.super.caps;
    do {
        perf_range             = &caps->ranges[caps->num_ranges];
        perf_range->max_length = ucs_min(remote_range->super.max_length,
                                         params->super.max_length);
        xfer_time              = remote_range->super.perf;
        xfer_time.m            = ucs_max(xfer_time.m, params->unpack_time.m);
        xfer_time.c           += params->unpack_time.c;

        /* Add send overheads and apply perf_bias */
        perf_range->perf = ucs_linear_func_compose(
                ucs_linear_func_make(0, 1.0 - params->perf_bias),
                ucs_linear_func_add(xfer_time, send_overheads));

        ++caps->num_ranges;
    } while ((remote_range++)->super.max_length < params->super.max_length);

    return UCS_OK;
}

void ucp_proto_rndv_ctrl_config_str(size_t min_length, size_t max_length,
                                    const void *priv, ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_ctrl_priv_t *rpriv = priv;
    ucp_md_index_t md_index;

    /* Print message lane and memory domains list */
    ucs_string_buffer_appendf(strb, "ln:%d md:", rpriv->lane);
    ucs_for_each_bit(md_index, rpriv->md_map) {
        ucs_string_buffer_appendf(strb, "%d,", md_index);
    }
    ucs_string_buffer_rtrim(strb, ",");
    ucs_string_buffer_appendf(strb, " ");

    /* Print estimated remote protocols for each message size */
    ucp_proto_threshold_elem_str(rpriv->remote_proto.thresholds, min_length,
                                 max_length, strb);
}

ucs_status_t ucp_proto_rndv_rts_init(const ucp_proto_init_params_t *init_params)
{
    ucp_context_h context                    = init_params->worker->context;
    ucp_proto_rndv_ctrl_init_params_t params = {
        .super.super        = *init_params,
        .super.latency      = 0,
        .super.overhead     = 40e-9,
        .super.cfg_thresh   = context->config.ext.rndv_thresh,
        .super.cfg_priority = 60,
        .super.min_length   = 1,
        .super.max_length   = SIZE_MAX,
        .super.flags        = UCP_PROTO_COMMON_INIT_FLAG_RESPONSE,
        .remote_op_id       = UCP_OP_ID_RNDV_RECV,
        .unpack_time        = ucs_linear_func_make(0, 0),
        .perf_bias          = context->config.ext.rndv_perf_diff / 100.0,
        .mem_info.type      = init_params->select_param->mem_type,
        .mem_info.sys_dev   = init_params->select_param->sys_dev,
    };

    UCP_RMA_PROTO_INIT_CHECK(init_params, UCP_OP_ID_TAG_SEND);

    return ucp_proto_rndv_ctrl_init(&params);
}

ucs_status_t ucp_proto_rndv_ack_init(const ucp_proto_init_params_t *init_params)
{
    ucp_proto_rndv_ack_priv_t *apriv = init_params->priv;

    if (ucp_proto_rndv_init_params_is_ppln_frag(init_params)) {
        /* Not sending ACK */
        apriv->lane = UCP_NULL_LANE;
    } else {
        apriv->lane = ucp_proto_common_find_am_bcopy_lane(init_params);
        if (apriv->lane == UCP_NULL_LANE) {
            return UCS_ERR_NO_ELEM;
        }
    }

    return UCS_OK;
}

ucs_linear_func_t
ucp_proto_rndv_ack_time(const ucp_proto_init_params_t *init_params)
{
    ucp_context_t *context           = init_params->worker->context;
    ucp_proto_rndv_ack_priv_t *apriv = init_params->priv;
    const uct_iface_attr_t *iface_attr;
    double ack_time;

    if (apriv->lane == UCP_NULL_LANE) {
        return ucs_linear_func_make(0, 0);
    }

    iface_attr = ucp_proto_common_get_iface_attr(init_params, apriv->lane);
    ack_time   = (iface_attr->overhead * 2) +
                 ucp_tl_iface_latency(context, &iface_attr->latency);

    return ucs_linear_func_make(ack_time, 0);
}

void ucp_proto_rndv_ack_config_str(size_t min_length, size_t max_length,
                                   const void *priv, ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_ack_priv_t *apriv = priv;

    if (apriv->lane != UCP_NULL_LANE) {
        ucs_string_buffer_appendf(strb, "aln:%d", apriv->lane);
    }
}

ucs_status_t
ucp_proto_rndv_bulk_init(const ucp_proto_multi_init_params_t *init_params,
                         size_t headroom)
{
    ucp_proto_multi_init_params_t multi_params = *init_params;
    void *priv                                 = init_params->super.super.priv;
    ucs_linear_func_t ack_time;
    ucp_proto_caps_t *caps;
    ucs_status_t status;
    size_t mpriv_size;
    unsigned i;

    ucs_assert(init_params->super.min_length > 0);

    /* Change priv pointer, since proto_multi priv is not the first element in
     * ucp_proto_rndv_bulk_priv_t struct. Later on, we also update priv size.
     */
    multi_params.super.super.priv      = UCS_PTR_BYTE_OFFSET(priv, headroom);
    multi_params.super.super.priv_size = &mpriv_size;
    status = ucp_proto_multi_init(&multi_params);
    if (status != UCS_OK) {
        return status;
    }

    status = ucp_proto_rndv_ack_init(&init_params->super.super);
    if (status != UCS_OK) {
        return status;
    }

    /* Add ack latency */
    ack_time = ucp_proto_rndv_ack_time(&init_params->super.super);
    caps     = init_params->super.super.caps;
    for (i = 0; i < caps->num_ranges; ++i) {
        ucs_linear_func_add_inplace(&caps->ranges[i].perf, ack_time);
    }

    /* Update private data size based of ucp_proto_multi_priv_t variable size */
    *init_params->super.super.priv_size = headroom + mpriv_size;
    return UCS_OK;
}

size_t ucp_proto_rndv_pack_ack(void *dest, void *arg)
{
    ucp_request_t *req       = arg;
    ucp_reply_hdr_t *ack_hdr = dest;

    ack_hdr->req_id = req->send.rndv.remote_req_id;
    ack_hdr->status = UCS_OK;

    return sizeof(*ack_hdr);
}

void ucp_proto_rndv_bulk_config_str(size_t min_length, size_t max_length,
                                    const void *priv, ucs_string_buffer_t *strb)
{
    const ucp_proto_rndv_bulk_priv_t *rpriv = priv;

    ucp_proto_multi_config_str(min_length, max_length, &rpriv->mpriv, strb);
    if (rpriv->super.lane != UCP_NULL_LANE) {
        ucs_string_buffer_appendf(strb, " ");
        ucp_proto_rndv_ack_config_str(min_length, max_length, &rpriv->super,
                                      strb);
    }
}

static ucs_status_t
ucp_proto_rndv_send_reply(ucp_worker_h worker, ucp_request_t *req,
                          ucp_operation_id_t op_id, uint32_t op_attr_mask,
                          size_t send_length, const void *rkey_buffer,
                          size_t rkey_length)
{
    ucp_worker_cfg_index_t rkey_cfg_index;
    ucp_proto_select_param_t sel_param;
    ucp_proto_select_t *proto_select;
    ucs_status_t status;
    ucp_rkey_h rkey;

    ucs_assert((op_id == UCP_OP_ID_RNDV_RECV) ||
               (op_id == UCP_OP_ID_RNDV_SEND));

    if (rkey_length > 0) {
        ucs_assert(rkey_buffer != NULL);
        status = ucp_ep_rkey_unpack_internal(req->send.ep, rkey_buffer,
                                             rkey_length, &rkey);
        if (status != UCS_OK) {
            return status;
        }

        proto_select   = &ucp_rkey_config(worker, rkey)->proto_select;
        rkey_cfg_index = rkey->cfg_index;
    } else {
        /* No remote key, use endpoint protocols */
        proto_select   = &ucp_ep_config(req->send.ep)->proto_select;
        rkey_cfg_index = UCP_WORKER_CFG_INDEX_NULL;
        rkey           = NULL;
    }

    ucp_proto_select_param_init(&sel_param, op_id, op_attr_mask,
                                req->send.state.dt_iter.dt_class,
                                &req->send.state.dt_iter.mem_info, 1);

    status = ucp_proto_request_lookup_proto(worker, req->send.ep, req,
                                            proto_select, rkey_cfg_index,
                                            &sel_param, send_length);
    if (status != UCS_OK) {
        goto err_destroy_rkey;
    }

    req->send.rndv.rkey = rkey;

    ucp_trace_req(req,
                  "%s rva 0x%" PRIx64 " rreq_id 0x%" PRIx64 " with protocol %s",
                  ucp_operation_names[op_id], req->send.rndv.remote_address,
                  req->send.rndv.remote_req_id,
                  req->send.proto_config->proto->name);

    ucp_request_send(req, 0);
    return UCS_OK;

err_destroy_rkey:
    if (rkey != NULL) {
        ucp_rkey_destroy(rkey);
    }
err:
    return status;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_check_rkey_length(uint64_t address, size_t rkey_length,
                                 const char *title)
{
    ucs_assertv((ssize_t)rkey_length >= 0, "%s rkey_length=%zd", title,
                (ssize_t)rkey_length);
    ucs_assertv((address != 0) == (rkey_length > 0),
                "%s rts->address=0x%" PRIx64 " rkey_length=%zu", title, address,
                rkey_length);
}

void ucp_proto_rndv_receive(ucp_worker_h worker, ucp_request_t *recv_req,
                            const ucp_rndv_rts_hdr_t *rts,
                            const void *rkey_buffer, size_t rkey_length)
{
    ucs_status_t status;
    ucp_request_t *req;
    uint8_t sg_count;
    size_t send_length;
    ucp_ep_h ep;

    UCP_WORKER_GET_VALID_EP_BY_ID(&ep, worker, rts->sreq.ep_id, return,
                                  "RTS on non-existing endpoint");

    if (!UCP_DT_IS_CONTIG(recv_req->recv.datatype)) {
        ucs_fatal("non-contiguous types are not supported with rndv protocol");
    }

    req = ucp_request_get(worker);
    if (req == NULL) {
        ucs_error("failed to allocate rendezvous reply");
        return;
    }

    /* TODO
     * - Avoid re-detection of recv buffer. For now it's needed because recv
     *   request does not have memory locality information.
     * - Reorganize request structure so that receive request itself can be
     *   reused for rndv operation (move callback and iter to common part)
     */
    if (ucs_likely(rts->size <= recv_req->recv.length)) {
        ucp_proto_rndv_check_rkey_length(rts->address, rkey_length, "rts");
        send_length      = rts->size;
        recv_req->status = UCS_OK;
    } else {
        /* Short receive: complete with error, and send reply to sender */
        rkey_length      = 0; /* Override rkey length to disable data fetch */
        send_length      = 0;
        recv_req->status = UCS_ERR_MESSAGE_TRUNCATED;
    }

    req->flags                    = 0;
    req->send.ep                  = ep;
    req->send.rndv.remote_req_id  = rts->sreq.req_id;
    req->send.rndv.remote_address = rts->address;
    req->send.rndv.offset         = 0;
    recv_req->recv.remaining      = send_length;
    ucp_request_set_super(req, recv_req);

    ucs_assert(recv_req->recv.count == recv_req->recv.length);
    ucp_datatype_iter_init(worker->context, recv_req->recv.buffer,
                           recv_req->recv.count, recv_req->recv.datatype,
                           send_length, &req->send.state.dt_iter, &sg_count);
    ucs_assert(sg_count == 1);

    status = ucp_proto_rndv_send_reply(worker, req, UCP_OP_ID_RNDV_RECV, 0,
                                       send_length, rkey_buffer, rkey_length);
    if (status != UCS_OK) {
        ucp_datatype_iter_cleanup(&req->send.state.dt_iter, UINT_MAX);
        ucs_mpool_put(req);
        return;
    }
}

static ucs_status_t
ucp_proto_rndv_send_start(ucp_worker_h worker, ucp_request_t *req,
                          uint32_t op_attr_mask, const ucp_rndv_rtr_hdr_t *rtr,
                          size_t header_length)
{
    ucs_status_t status;
    size_t rkey_length;

    ucs_assert(header_length >= sizeof(*rtr));
    rkey_length = header_length - sizeof(*rtr);

    ucp_proto_rndv_check_rkey_length(rtr->address, rkey_length, "rtr");
    req->send.rndv.remote_address = rtr->address;
    req->send.rndv.remote_req_id  = rtr->rreq_id;
    req->send.rndv.offset         = rtr->offset;

    ucs_assert(rtr->size == req->send.state.dt_iter.length);
    status = ucp_proto_rndv_send_reply(worker, req, UCP_OP_ID_RNDV_SEND,
                                       op_attr_mask, rtr->size, rtr + 1,
                                       rkey_length);
    if (status != UCS_OK) {
        return status;
    }

    return UCS_OK;
}

static void ucp_proto_rndv_send_complete_one(void *request, ucs_status_t status,
                                             void *user_data)
{
    ucp_request_t *freq = (ucp_request_t*)request - 1;
    ucp_request_t *req  = ucp_request_user_data_get_super(request, user_data);

    if (!ucp_proto_rndv_frag_complete(req, freq)) {
        return;
    }

    ucp_send_request_id_release(req);
    ucp_proto_request_zcopy_complete(req, UCS_OK);
}

ucs_status_t
ucp_proto_rndv_handle_rtr(void *arg, void *data, size_t length, unsigned flags)
{
    ucp_worker_h worker           = arg;
    const ucp_rndv_rtr_hdr_t *rtr = data;
    ucp_request_t *req, *freq;
    ucs_status_t status;

    UCP_SEND_REQUEST_GET_BY_ID(&req, worker, rtr->sreq_id, 0, return UCS_OK,
                               "RTR %p", rtr);

    ucs_assert(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED);

    if (rtr->size == req->send.state.dt_iter.length) {
        /* RTR covers the whole send request - use the send request directly */
        ucs_assert(rtr->offset == 0);

        ucp_send_request_id_release(req);
        req->flags &= ~UCP_REQUEST_FLAG_PROTO_INITIALIZED;
        status      = ucp_proto_rndv_send_start(worker, req, 0, rtr, length);
        if (status != UCS_OK) {
            goto err_request_fail;
        }
    } else {
        /* Partial RTR, its "offset" and "size" fields specify part to send */
        status = ucp_proto_rndv_frag_request_alloc(worker, req, &freq);
        if (status != UCS_OK) {
            goto err_request_fail;
        }

        /* When this fragment is completed, count total size and complete the
           super request if needed */
        freq->flags  |= UCP_REQUEST_FLAG_CALLBACK | UCP_REQUEST_FLAG_RELEASED;
        freq->send.cb = ucp_proto_rndv_send_complete_one;

        ucp_datatype_iter_slice(&req->send.state.dt_iter, rtr->offset,
                                rtr->size, &freq->send.state.dt_iter);

        /* Send rendezvous fragment, when it's completed update 'remaining'
         * and complete 'req' when it reaches zero
         */
        status = ucp_proto_rndv_send_start(worker, freq,
                                           UCP_OP_ATTR_FLAG_MULTI_SEND, rtr,
                                           length);
        if (status != UCS_OK) {
            goto err_put_freq;
        }
    }

    return UCS_OK;

err_put_freq:
    ucp_request_put(freq);
err_request_fail:
    ucp_proto_request_abort(req, status);
    return UCS_OK;
}

void ucp_proto_rndv_bulk_request_init_lane_idx(
        ucp_request_t *req, const ucp_proto_rndv_bulk_priv_t *rpriv)
{
    size_t total_length = ucp_proto_rndv_request_total_length(req);
    size_t max_frag_sum = rpriv->mpriv.max_frag_sum;
    const ucp_proto_multi_lane_priv_t *lpriv;
    size_t end_offset, rel_offset;
    ucp_lane_index_t lane_idx;

    /* Find initial lane index */
    lane_idx = 0;
    if (ucs_likely(total_length < max_frag_sum)) {
        do {
            lpriv      = &rpriv->mpriv.lanes[lane_idx++];
            end_offset = ucp_proto_multi_scaled_length(lpriv->weight_sum,
                                                       total_length);
        } while (req->send.rndv.offset >= end_offset);
    } else {
        rel_offset = req->send.rndv.offset % rpriv->mpriv.max_frag_sum;
        do {
            lpriv = &rpriv->mpriv.lanes[lane_idx++];
        } while (rel_offset >= lpriv->max_frag_sum);
    }

    req->send.multi_lane_idx = lane_idx - 1;
}
