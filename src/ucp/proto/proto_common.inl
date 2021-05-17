/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_PROTO_COMMON_INL_
#define UCP_PROTO_COMMON_INL_

#include "proto_common.h"
#include "proto_select.inl"

#include <ucp/dt/datatype_iter.inl>
#include <ucp/core/ucp_request.inl>
#include <ucs/debug/debug_int.h>


static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_request_complete_success(ucp_request_t *req)
{
    ucp_request_complete_send(req, UCS_OK);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_request_bcopy_complete_success(ucp_request_t *req)
{
    ucp_datatype_iter_cleanup(&req->send.state.dt_iter, UINT_MAX);
    return ucp_proto_request_complete_success(req);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_msg_multi_request_init(ucp_request_t *req)
{
    req->send.msg_proto.message_id = req->send.ep->worker->am_message_id++;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_completion_init(uct_completion_t *comp,
                          uct_completion_callback_t comp_func)
{
    comp->func   = comp_func;
    comp->count  = 1;
    comp->status = UCS_OK;
    /* extra ref to be decremented when all sent */
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_request_zcopy_init(ucp_request_t *req, ucp_md_map_t md_map,
                             uct_completion_callback_t comp_func,
                             unsigned uct_reg_flags)
{
    ucp_ep_h ep = req->send.ep;
    ucs_status_t status;

    ucp_trace_req(req, "ucp_proto_zcopy_request_init for %s",
                  req->send.proto_config->proto->name);

    ucp_proto_completion_init(&req->send.state.uct_comp, comp_func);

    status = ucp_datatype_iter_mem_reg(ep->worker->context,
                                       &req->send.state.dt_iter,
                                       md_map, uct_reg_flags);
    if (status != UCS_OK) {
        return status;
    }

    ucp_trace_req(req, "registered md_map 0x%"PRIx64"/0x%"PRIx64,
                  req->send.state.dt_iter.type.contig.reg.md_map, md_map);

    /* We expect the registration to happen on all desired memory domains, since
     * the protocol initialization code would already disqualify any memory
     * domain which does not support registration, or does not require a local
     * memory key for zero-copy operations. This assumption simplifies memory
     * key lookups during protocol progress.
     */
    ucs_assertv((req->send.state.dt_iter.type.contig.reg.md_map == md_map) ||
                (req->send.state.dt_iter.length == 0),
                "md_map=0x%" PRIx64 " reg.md_map=0x%" PRIx64, md_map,
                req->send.state.dt_iter.type.contig.reg.md_map);

    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_request_zcopy_cleanup(ucp_request_t *req)
{
    ucp_datatype_iter_mem_dereg(req->send.ep->worker->context,
                                &req->send.state.dt_iter);
    ucp_datatype_iter_cleanup(&req->send.state.dt_iter,
                              UCS_BIT(UCP_DATATYPE_CONTIG));
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_request_zcopy_complete(ucp_request_t *req, ucs_status_t status)
{
    ucp_proto_request_zcopy_cleanup(req);
    ucp_request_complete_send(req, status);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_request_zcopy_complete_success(ucp_request_t *req)
{
    ucp_proto_request_zcopy_complete(req, UCS_OK);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_request_set_stage(ucp_request_t *req, uint8_t stage)
{
    const ucp_proto_t *proto = req->send.proto_config->proto;

    ucs_assert(stage < UCP_PROTO_STAGE_LAST);
    ucs_assert(proto->progress[stage] != NULL);

    ucp_trace_req(req, "set to stage %u, progress function '%s'", stage,
                  ucs_debug_get_symbol_name(proto->progress[stage]));
    req->send.stage = stage;

    /* Set pointer to progress function */
    if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_REQ)) {
        req->send.uct.func = ucp_request_progress_wrapper;
    } else {
        req->send.uct.func = proto->progress[stage];
    }
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_request_set_proto(ucp_request_t *req,
                            const ucp_proto_config_t *proto_config,
                            size_t msg_length)
{
    req->send.proto_config = proto_config;
    if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_REQ)) {
        ucp_proto_trace_selected(req, msg_length);
    }

    ucp_proto_request_set_stage(req, UCP_PROTO_STAGE_START);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_request_select_proto(ucp_request_t *req,
                               const ucp_proto_select_elem_t *select_elem,
                               size_t msg_length)
{
    const ucp_proto_threshold_elem_t *thresh_elem =
            ucp_proto_thresholds_search(select_elem->thresholds, msg_length);
    ucp_proto_request_set_proto(req, &thresh_elem->proto_config, msg_length);
}

/* Select protocol for the request and initialize protocol-related fields */
static UCS_F_ALWAYS_INLINE ucs_status_t ucp_proto_request_lookup_proto(
        ucp_worker_h worker, ucp_ep_h ep, ucp_request_t *req,
        ucp_proto_select_t *proto_select, ucp_worker_cfg_index_t rkey_cfg_index,
        const ucp_proto_select_param_t *sel_param, size_t msg_length)
{
    const ucp_proto_threshold_elem_t *thresh_elem;

    thresh_elem = ucp_proto_select_lookup(worker, proto_select, ep->cfg_index,
                                          rkey_cfg_index, sel_param, msg_length);
    if (UCS_ENABLE_ASSERT && (thresh_elem == NULL)) {
        /* We expect that a protocol will always be found, or we will fallback
           to 'reconfig' placeholder */
        ucp_proto_request_select_error(req, proto_select, rkey_cfg_index,
                                       sel_param, msg_length);
        return UCS_ERR_UNREACHABLE;
    }

    /* Set pointer to request's protocol configuration */
    ucs_assert(thresh_elem->proto_config.ep_cfg_index == ep->cfg_index);
    ucs_assert(thresh_elem->proto_config.rkey_cfg_index == rkey_cfg_index);

    ucp_proto_request_set_proto(req, &thresh_elem->proto_config, msg_length);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_ptr_t
ucp_proto_request_send_op(ucp_ep_h ep, ucp_proto_select_t *proto_select,
                          ucp_worker_cfg_index_t rkey_cfg_index,
                          ucp_request_t *req, ucp_operation_id_t op_id,
                          const void *buffer, size_t count, ucp_datatype_t datatype,
                          size_t contig_length, const ucp_request_param_t *param)
{
    static int counter      = 0;
    ucp_worker_h worker     = ep->worker;
    ucp_proto_select_param_t sel_param;
    ucs_status_t status;
    uint8_t sg_count;

    req->flags   = 0;
    req->send.ep = ep;

    UCS_PROFILE_CALL_VOID(ucp_datatype_iter_init, worker->context,
                          (void*)buffer, count, datatype, contig_length,
                          &req->send.state.dt_iter, &sg_count);

    ucp_proto_select_param_init(&sel_param, op_id, param->op_attr_mask, 0,
                                req->send.state.dt_iter.dt_class,
                                &req->send.state.dt_iter.mem_info, sg_count);

    status = UCS_PROFILE_CALL(ucp_proto_request_lookup_proto, worker, ep, req,
                              proto_select, rkey_cfg_index, &sel_param,
                              contig_length);
    if (status != UCS_OK) {
        goto out_put_request;
    }

    if ((counter++) % 128 == 0) {
        const ucp_proto_select_elem_t *select_elem =
        ucp_proto_select_lookup_slow(worker, proto_select, ep->cfg_index,
                                     rkey_cfg_index, &sel_param);

        ucp_proto_set_wjh(req, select_elem, contig_length);
    }

    UCS_PROFILE_CALL_VOID(ucp_request_send, req, 0);
    if (req->flags & UCP_REQUEST_FLAG_COMPLETED) {
        goto out_put_request;
    }

    /* set callback flag to allow calling it. we didn't set it before to prevent
     * it from being called if the send is completed immediately.
     */
    ucp_request_set_send_callback_param(param, req, send);

    ucs_trace_req("returning send request %p", req);
    return req + 1;

out_put_request:
    ucs_trace_req("releasing send request %p, returning status %s", req,
                  ucs_status_string(status));
    status = req->status;
    ucp_request_put_param(param, req);
    return UCS_STATUS_PTR(status);
}

static UCS_F_ALWAYS_INLINE size_t ucp_proto_request_pack_rkey(
        ucp_request_t *req, uint64_t distance_dev_map,
        const ucs_sys_dev_distance_t *dev_distance, void *rkey_buffer)
{
    ssize_t packed_rkey_size;

    /* For contiguous buffer, pack one rkey
     * TODO to support IOV datatype write N [address+length] records,
     */
    ucs_assert(req->send.state.dt_iter.dt_class == UCP_DATATYPE_CONTIG);

    packed_rkey_size =
            ucp_rkey_pack_uct(req->send.ep->worker->context,
                              req->send.state.dt_iter.type.contig.reg.md_map,
                              req->send.state.dt_iter.type.contig.reg.memh,
                              &req->send.state.dt_iter.mem_info,
                              distance_dev_map, dev_distance, rkey_buffer);
    if (packed_rkey_size < 0) {
        ucs_error("failed to pack remote key: %s",
                  ucs_status_string((ucs_status_t)packed_rkey_size));
        return 0;
    }

    return packed_rkey_size;
}

static UCS_F_ALWAYS_INLINE ucs_status_t ucp_proto_common_handle_send_error(
        ucp_request_t *req, ucp_lane_index_t lane, ucs_status_t status)
{
    ucs_assert(UCS_STATUS_IS_ERR(status));
    if (ucs_likely(status == UCS_ERR_NO_RESOURCE)) {
        /* keep on pending queue */
        req->send.lane = lane;
        return UCS_ERR_NO_RESOURCE;
    }

    ucp_proto_request_abort(req, status);
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_proto_common_lane_map_progress(ucp_request_t *req, ucp_lane_map_t *lane_map,
                                   ucp_proto_common_lane_send_func_t send_func)
{
    ucp_lane_index_t lane = ucs_ffs32(*lane_map);
    ucs_status_t status;

    ucs_assert(*lane_map != 0);

    status = send_func(req, lane);
    if (ucs_likely(status == UCS_OK)) {
        /* fast path is OK */
    } else if (status == UCS_INPROGRESS) {
        ++req->send.state.uct_comp.count;
    } else {
        return ucp_proto_common_handle_send_error(req, lane, status);
    }

    *lane_map &= ~UCS_BIT(lane);
    if (*lane_map != 0) {
        return UCS_INPROGRESS; /* Not finished all lanes yet */
    }

    ucp_request_invoke_uct_completion_success(req);
    return UCS_OK;
}

#endif
