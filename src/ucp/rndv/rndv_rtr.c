/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "proto_rndv.inl"
#include "rndv_ppln.h"

#include <ucp/proto/proto_single.inl>


static ucs_status_t
ucp_proto_rndv_rtr_common_init(const ucp_proto_init_params_t *init_params,
                               uint64_t rndv_modes, ucs_memory_type_t mem_type,
                               ucs_sys_device_t sys_dev, int is_pipeline)
{
    ucp_context_h context                    = init_params->worker->context;
    ucp_proto_rndv_ctrl_init_params_t params = {
        .super.super        = *init_params,
        .super.latency      = 0,
        .super.overhead     = 40e-9,
        .super.cfg_thresh   = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority = 0,
        .super.flags        = UCP_PROTO_COMMON_INIT_FLAG_RESPONSE,
        .remote_op_id       = UCP_OP_ID_RNDV_SEND,
        .perf_bias          = 0.0,
        .mem_info.type      = mem_type,
        .mem_info.sys_dev   = sys_dev,
        .min_length         = 1,
        .is_pipeline        = is_pipeline
    };

    if (init_params->select_param->op_id != UCP_OP_ID_RNDV_RECV) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_ctrl_init(&params);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rtr_common_request_init(ucp_request_t *req)
{
    ucp_request_t *recv_req = ucp_request_get_super(req);

    recv_req->status             = UCS_OK;
    recv_req->recv.remaining     = req->send.state.dt_iter.length;
    // TODO send byte count in ATP, and update "remaining"?
    req->send.rndv.rtr.atp_count = 0;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rdnv_rtr_common_comp_init(ucp_ep_h ep, uct_completion_t *comp,
                                    ucs_ptr_map_key_t *ptr_id_p,
                                    uct_completion_callback_t comp_func)
{
    /* RTR sends the id of its &req->comp field, and not of the request, to
       support fragmented protocol with multiple RTRs per request */
    ucp_proto_completion_init(comp, comp_func);
    ucp_ep_ptr_id_alloc(ep, comp, ptr_id_p);
}

static ucs_status_t
ucp_proto_rndv_rtr_common_send(ucp_request_t *req, uct_pack_callback_t pack_cb)
{
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    size_t max_rtr_size = sizeof(ucp_rndv_rtr_hdr_t) + rpriv->packed_rkey_size;

    return ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_RNDV_RTR,
                                              rpriv->lane, pack_cb, req,
                                              max_rtr_size, NULL);
}

static void ucp_proto_rndv_rtr_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    ucp_request_id_reset(req);
    ucp_proto_rndv_rtr_common_complete(req, req->send.state.uct_comp.status);
}

static size_t ucp_proto_rndv_rtr_pack(void *dest, void *arg)
{
    ucp_rndv_rtr_hdr_t *rtr                 = dest;
    ucp_request_t *req                      = arg;
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    size_t rkey_size;

    rtr->sreq_id = req->send.rndv.remote_req_id;
    rtr->rreq_id = ucp_send_request_get_id(req);
    rtr->size    = req->send.state.dt_iter.length;
    rtr->offset  = 0;
    rtr->address = (uintptr_t)req->send.state.dt_iter.type.contig.buffer;

    rpriv = req->send.proto_config->priv;
    ucs_assert(rtr->size > 0);
    ucs_assert(rpriv->md_map == req->send.state.dt_iter.type.contig.reg.md_map);

    rkey_size = ucp_proto_request_pack_rkey(req, rpriv->sys_dev_map,
                                            rpriv->sys_dev_distance, rtr + 1);
    ucs_assert(rkey_size == rpriv->packed_rkey_size);
    return sizeof(*rtr) + rkey_size;
}

static ucs_status_t ucp_proto_rndv_rtr_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    ucs_status_t status;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        status = ucp_datatype_iter_mem_reg(req->send.ep->worker->context,
                                           &req->send.state.dt_iter,
                                           rpriv->md_map,
                                           UCT_MD_MEM_ACCESS_REMOTE_PUT);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            return UCS_OK;
        }

        ucp_proto_rtr_common_request_init(req);
        // ucp_proto_rdnv_rtr_common_comp_init(req->send.ep,
        //                                     &req->send.state.uct_comp, &req->id,
        //                                     ucp_proto_rndv_rtr_completion);
        ucp_proto_completion_init(&req->send.state.uct_comp,
                                  ucp_proto_rndv_rtr_completion);
        ucp_send_request_id_alloc(req);

        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    return ucp_proto_rndv_rtr_common_send(req, ucp_proto_rndv_rtr_pack);
}

static ucs_status_t
ucp_proto_rndv_rtr_init(const ucp_proto_init_params_t *init_params)
{
    return ucp_proto_rndv_rtr_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_ZCOPY) |
                                                  UCS_BIT(UCP_RNDV_MODE_AM),
                                          init_params->select_param->mem_type,
                                          init_params->select_param->sys_dev,
                                          0);
}

static ucp_proto_t ucp_rndv_rtr_proto = {
    .name       = "rndv/rtr",
    .flags      = 0,
    .init       = ucp_proto_rndv_rtr_init,
    .config_str = ucp_proto_rndv_ctrl_config_str,
    .progress   = ucp_proto_rndv_rtr_progress
};
UCP_PROTO_REGISTER(&ucp_rndv_rtr_proto);

static size_t ucp_proto_rndv_rtr_ppln_pack(void *dest, void *arg)
{
    ucp_rndv_rtr_hdr_t *rtr                 = dest;
    ucp_request_t *freq                     = arg;
    ucp_request_t *req                      = ucp_request_get_super(freq);
    ucp_context_h context                   = req->send.ep->worker->context;
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    ucp_md_map_t md_map                     = rpriv->md_map;
    ucp_rndv_frag_t *frag                   = req->send.frag;
    uct_mem_h uct_memh[UCP_MAX_LANES];
    ucp_memory_info_t mem_info;
    ucp_md_index_t md_index, n;
    ssize_t packed_rkey_size;

    ucs_assert(frag != NULL);
    ucs_assert(ucs_test_all_flags(frag->super.memh->md_map, md_map));

    rtr->sreq_id = req->send.rndv.remote_req_id;
    rtr->rreq_id = ucp_send_request_get_id(freq);
    rtr->address = (uintptr_t)(frag + 1);
    rtr->size    = frag->length;
    rtr->offset  = frag->offset;

    // TODO support filter map in ucp_rkey_pack_uct()

    ucs_trace("md_map=0x%lx/0x%lx", md_map, frag->super.memh->md_map);
    // ucs_assert(md_map != 0);

    n = 0;
    ucs_for_each_bit(md_index, md_map) {
        uct_memh[n++] = ucp_memh2uct(frag->super.memh, md_index);
    }

    /* Pack remote key for the fragment */
    mem_info.type    = frag->super.memh->mem_type;
    mem_info.sys_dev = UCS_SYS_DEVICE_ID_UNKNOWN;
    packed_rkey_size = ucp_rkey_pack_uct(context, md_map, uct_memh, &mem_info,
                                         0, NULL, rtr + 1);
    if (packed_rkey_size < 0) {
        ucs_error("failed to pack remote key: %s",
                  ucs_status_string((ucs_status_t)packed_rkey_size));
        packed_rkey_size = 0;
    }

    return sizeof(*rtr) + packed_rkey_size;
}

static ucs_status_t ucp_proto_rndv_rtr_ppln_frag_alloc(ucp_request_t *req)
{
    ucp_worker_h worker = req->send.ep->worker;
    ucp_rndv_frag_t *frag;

    if (req->send.frag != NULL) {
        return UCS_OK;
    }

    frag = ucp_worker_mpool_get(&worker->rndv_frag_mp, ucp_rndv_frag_t);
    if (frag == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    frag->req       = req;
    frag->offset    = req->send.state.dt_iter.offset;
    frag->length    = ucs_min(worker->context->config.ext.rndv_frag_size,
                              req->send.state.dt_iter.length - frag->offset);
    req->send.frag = frag;

    ucp_proto_completion_init(&frag->comp,
                              ucp_proto_rndv_ppln_frag_recv_completion);
    // ucp_proto_rdnv_rtr_common_comp_init(req->send.ep, &frag->comp,
    //                                     &frag->frag_id,
    //                                     ucp_proto_rndv_ppln_frag_recv_completion);

    return UCS_OK;
}

static void ucp_proto_rndv_rtr_ppln_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    ucp_proto_rndv_rtr_common_complete(req, req->send.state.uct_comp.status);
}

static ucs_status_t ucp_proto_rndv_rtr_ppln_progress(uct_pending_req_t *self)
{
    ucp_request_t *req  = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_rndv_ctrl_priv_t *rpriv = req->send.proto_config->priv;
    size_t max_rtr_size = sizeof(ucp_rndv_rtr_hdr_t) + rpriv->packed_rkey_size;
    ucp_worker_h worker = req->send.ep->worker;
    ucp_request_t *freq;
    ucs_status_t status;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        ucp_proto_completion_init(&req->send.state.uct_comp,
                                  ucp_proto_rndv_rtr_ppln_completion);
        ucp_proto_rtr_common_request_init(req);
        req->send.frag = NULL;
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    /* Allocate fragment */
    status = ucp_proto_rndv_rtr_ppln_frag_alloc(req);
    if (status != UCS_OK) {
        ucp_proto_request_abort(req, status);
        return UCS_OK;
    }

    freq = ucp_request_get(worker);
    if (freq == NULL) {
        ucp_proto_request_abort(req, UCS_ERR_NO_MEMORY);
        return UCS_OK;
    }

    ucp_send_request_id_alloc(freq);
    ucp_request_set_super(freq, req);
    freq->flags = 0;

    /* counts sent fragments for which we expect an ATP */
    ++req->send.state.uct_comp.count;

    // rpriv  = req->send.proto_config->priv;
    status = ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_RNDV_RTR,
                                                rpriv->lane,
                                                ucp_proto_rndv_rtr_ppln_pack,
                                                freq, max_rtr_size, NULL);

    // status = ucp_proto_rndv_rtr_common_send(req,ucp_proto_rndv_rtr_ppln_pack);
    if (status == UCS_OK) {
        // TODO pass pack context with pointer to next_iter
        ucp_datatype_iter_advance(&req->send.state.dt_iter,
                                  req->send.frag->length,
                                  &req->send.state.dt_iter);
        req->send.frag = NULL;
        if (ucp_datatype_iter_is_end(&req->send.state.dt_iter)) {
            ucp_invoke_uct_completion(&req->send.state.uct_comp, UCS_OK);
            return UCS_OK;
        }
        return UCS_INPROGRESS;
    } else if (status == UCS_ERR_NO_RESOURCE) {
        --req->send.state.uct_comp.count;
        return status;
    } else {
        --req->send.state.uct_comp.count;
        // TODO fail the request
        return UCS_OK;
    }
}

static ucs_status_t
ucp_proto_rndv_rtr_ppln_init(const ucp_proto_init_params_t *init_params)
{
    if (!ucp_proto_rndv_ppln_is_supported(init_params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_rtr_common_init(init_params,
                                          UCS_BIT(UCP_RNDV_MODE_PUT_PIPELINE),
                                          UCS_MEMORY_TYPE_HOST,
                                          UCS_SYS_DEVICE_ID_UNKNOWN, 1);
}

static ucp_proto_t ucp_rndv_rtr_ppln_proto = {
    .name       = "rndv/rtr/ppln",
    .flags      = 0,
    .init       = ucp_proto_rndv_rtr_ppln_init,
    .config_str = ucp_proto_rndv_ctrl_config_str,
    .progress   = ucp_proto_rndv_rtr_ppln_progress
};
UCP_PROTO_REGISTER(&ucp_rndv_rtr_ppln_proto);
