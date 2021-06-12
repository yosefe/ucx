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

#include <ucp/proto/proto_single.inl>


/**
 * @param in_buffer Whether data is already in user buffer (dt_iter) or in
 *  in the buffer we published as remote address.
 *
 */
typedef void (*ucp_proto_rndv_rtr_data_received_cb_t)(ucp_request_t *req,
                                                      int in_buffer);

typedef struct {
    ucp_proto_rndv_ctrl_priv_t            super;
    ucp_proto_rndv_rtr_data_received_cb_t data_received;
} ucp_proto_rndv_rtr_priv_t;


static ucs_status_t
ucp_proto_rndv_rtr_common_init(const ucp_proto_init_params_t *init_params,
                               ucp_proto_rndv_rtr_data_received_cb_t data_cb,
                               uint64_t rndv_modes, size_t max_length,
                               ucs_linear_func_t unpack_time,
                               ucs_memory_type_t mem_type,
                               ucs_sys_device_t sys_dev)
{
    ucp_context_h context                    = init_params->worker->context;
    ucp_proto_rndv_ctrl_init_params_t params = {
        .super.super         = *init_params,
        .super.latency       = 0,
        .super.overhead      = 40e-9,
        .super.cfg_thresh    = ucp_proto_rndv_cfg_thresh(context, rndv_modes),
        .super.cfg_priority  = 0,
        .super.min_length    = 1,
        .super.max_length    = max_length,
        .super.min_frag_offs = UCP_PROTO_COMMON_OFFSET_INVALID,
        .super.max_frag_offs = ucs_offsetof(uct_iface_attr_t, cap.am.max_bcopy),
        .super.hdr_size      = sizeof(ucp_rndv_rtr_hdr_t),
        .super.flags         = UCP_PROTO_COMMON_INIT_FLAG_RESPONSE,
        .remote_op_id        = UCP_OP_ID_RNDV_SEND,
        .unpack_time         = unpack_time,
        .perf_bias           = 0.0,
        .mem_info.type       = mem_type,
        .mem_info.sys_dev    = sys_dev,
    };
    ucp_proto_rndv_rtr_priv_t *rpriv;
    ucs_status_t status;

    if (init_params->select_param->op_id != UCP_OP_ID_RNDV_RECV) {
        return UCS_ERR_UNSUPPORTED;
    }

    status = ucp_proto_rndv_ctrl_init(&params);
    if (status != UCS_OK) {
        return status;
    }

    *init_params->priv_size = sizeof(ucp_proto_rndv_rtr_priv_t);
    rpriv                   = init_params->priv;
    rpriv->data_received    = data_cb;
    return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rtr_common_request_init(ucp_request_t *req)
{
    ucp_send_request_id_alloc(req);
    req->send.state.completed_size = 0;
}

static ucs_status_t
ucp_proto_rndv_rtr_common_send(ucp_request_t *req, uct_pack_callback_t pack_cb)
{
    const ucp_proto_rndv_rtr_priv_t *rpriv = req->send.proto_config->priv;
    size_t max_rtr_size                    = sizeof(ucp_rndv_rtr_hdr_t) +
                                             rpriv->super.packed_rkey_size;

    return ucp_proto_am_bcopy_single_progress(req, UCP_AM_ID_RNDV_RTR,
                                              rpriv->super.lane, pack_cb, req,
                                              max_rtr_size, NULL);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_rtr_common_pack(ucp_request_t *req, ucp_rndv_rtr_hdr_t *rtr,
                               void *buffer)
{
    rtr->sreq_id = req->send.rndv.remote_req_id;
    rtr->rreq_id = ucp_send_request_get_id(req);
    rtr->size    = req->send.state.dt_iter.length;
    rtr->offset  = req->send.rndv.offset;
    rtr->address = (uintptr_t)buffer;
    ucs_assert(rtr->size > 0);
}

static UCS_F_ALWAYS_INLINE void
ucp_proto_rndv_rtr_common_complete(ucp_request_t *req)
{
    if (req->send.rndv.rkey != NULL) {
        ucp_proto_rndv_rkey_destroy(req);
    }
    ucp_proto_rndv_recv_complete(req);
}

static void ucp_proto_rndv_rtr_data_received(ucp_request_t *req, int in_buffer)
{
    ucp_send_request_id_release(req);
    ucp_proto_rndv_rtr_common_complete(req);
}

static size_t ucp_proto_rndv_rtr_pack(void *dest, void *arg)
{
    ucp_rndv_rtr_hdr_t *rtr                = dest;
    ucp_request_t *req                     = arg;
    const ucp_proto_rndv_rtr_priv_t *rpriv = req->send.proto_config->priv;
    size_t rkey_size;

    ucp_proto_rndv_rtr_common_pack(req, rtr,
                                   req->send.state.dt_iter.type.contig.buffer);

    ucs_assert(rpriv->super.md_map == req->send.state.dt_iter.type.contig.reg.md_map);
    rkey_size = ucp_proto_request_pack_rkey(req, rpriv->super.sys_dev_map,
                                            rpriv->super.sys_dev_distance,
                                            rtr + 1);
    ucs_assert(rkey_size == rpriv->super.packed_rkey_size);
    return sizeof(*rtr) + rkey_size;
}

static ucs_status_t ucp_proto_rndv_rtr_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    const ucp_proto_rndv_rtr_priv_t *rpriv = req->send.proto_config->priv;
    ucs_status_t status;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        status = ucp_datatype_iter_mem_reg(req->send.ep->worker->context,
                                           &req->send.state.dt_iter,
                                           rpriv->super.md_map,
                                           UCT_MD_MEM_ACCESS_REMOTE_PUT);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            return UCS_OK;
        }

        ucp_proto_rtr_common_request_init(req);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    return ucp_proto_rndv_rtr_common_send(req, ucp_proto_rndv_rtr_pack);
}

static ucs_status_t
ucp_proto_rndv_rtr_init(const ucp_proto_init_params_t *init_params)
{
    uint64_t rndv_modes = UCS_BIT(UCP_RNDV_MODE_PUT_ZCOPY) |
                          UCS_BIT(UCP_RNDV_MODE_AM);

    if (ucp_proto_rndv_init_params_is_ppln_frag(init_params)) {
        return UCS_ERR_UNSUPPORTED;
    }

    return ucp_proto_rndv_rtr_common_init(init_params,
                                          ucp_proto_rndv_rtr_data_received,
                                          rndv_modes, SIZE_MAX,
                                          ucs_linear_func_make(0, 0),
                                          init_params->select_param->mem_type,
                                          init_params->select_param->sys_dev);
}

static ucp_proto_t ucp_rndv_rtr_proto = {
    .name       = "rndv/rtr",
    .flags      = 0,
    .init       = ucp_proto_rndv_rtr_init,
    .config_str = ucp_proto_rndv_ctrl_config_str,
    .progress   = {ucp_proto_rndv_rtr_progress},
};
UCP_PROTO_REGISTER(&ucp_rndv_rtr_proto);

static size_t ucp_proto_rndv_rtr_mtcopy_pack(void *dest, void *arg)
{
    ucp_rndv_rtr_hdr_t *rtr                = dest;
    ucp_request_t *req                     = arg;
    const ucp_proto_rndv_rtr_priv_t *rpriv = req->send.proto_config->priv;
    ucp_md_map_t md_map                    = rpriv->super.md_map;
    ucp_mem_desc_t *mdesc                  = req->send.rndv.mdesc;
    uct_mem_h uct_memh[UCP_MAX_LANES];
    ucp_memory_info_t mem_info;
    ucp_md_index_t md_index, n;
    ssize_t packed_rkey_size;

    ucs_assert(mdesc != NULL);
    ucp_proto_rndv_rtr_common_pack(req, rtr, mdesc + 1);

    // TODO support filter map in ucp_rkey_pack_uct()
    ucs_assert(ucs_test_all_flags(mdesc->memh->md_map, md_map));
    ucs_trace("md_map=0x%lx/0x%lx", md_map, mdesc->memh->md_map);
    n = 0;
    ucs_for_each_bit(md_index, md_map) {
        uct_memh[n++] = ucp_memh2uct(mdesc->memh, md_index);
    }

    /* Pack remote key for the fragment */
    mem_info.type    = mdesc->memh->mem_type;
    mem_info.sys_dev = UCS_SYS_DEVICE_ID_UNKNOWN;
    packed_rkey_size = ucp_rkey_pack_uct(req->send.ep->worker->context, md_map,
                                         uct_memh, &mem_info, 0, NULL, rtr + 1);
    if (packed_rkey_size < 0) {
        ucs_error("failed to pack remote key: %s",
                  ucs_status_string((ucs_status_t)packed_rkey_size));
        packed_rkey_size = 0;
    }

    return sizeof(*rtr) + packed_rkey_size;
}

static void ucp_proto_rndv_rtr_mtcopy_complete(ucp_request_t *req)
{
    ucs_mpool_put_inline(req->send.rndv.mdesc);
    ucp_send_request_id_release(req);
    if (ucp_proto_rndv_request_is_ppln_frag(req)) {
        ucp_proto_rndv_ppln_recv_frag_complete(req, 0);
    } else {
        ucp_proto_rndv_rtr_common_complete(req);
    }
}

static void
ucp_proto_rndv_rtr_mtcopy_copy_completion(uct_completion_t *uct_comp)
{
    ucp_request_t *req = ucs_container_of(uct_comp, ucp_request_t,
                                          send.state.uct_comp);
    ucp_proto_rndv_rtr_mtcopy_complete(req);
}

static void
ucp_proto_rndv_rtr_mtcopy_data_received(ucp_request_t *req, int in_buffer)
{
    ucp_send_request_id_release(req);
    if (in_buffer) {
        /* Data was already placed in used buffer because the sender responded
           with RNDV_DATA packets */
        ucp_proto_rndv_rtr_mtcopy_complete(req);
    } else {
        /* Data was not placed in user buffer, which means it was placed to
           the remote address we published, which is the fragment */
        ucp_proto_rndv_mtcopy_copy(req, uct_ep_put_zcopy,
                                  ucp_proto_rndv_rtr_mtcopy_copy_completion,
                                  "out to");
    }
}

static ucs_status_t ucp_proto_rndv_rtr_mtcopy_progress(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);
    ucs_status_t status;

    if (!(req->flags & UCP_REQUEST_FLAG_PROTO_INITIALIZED)) {
        status = ucp_proto_rndv_mtcopy_request_init(req);
        if (status != UCS_OK) {
            ucp_proto_request_abort(req, status);
            return UCS_OK;
        }

        ucp_proto_rtr_common_request_init(req);
        req->flags |= UCP_REQUEST_FLAG_PROTO_INITIALIZED;
    }

    return ucp_proto_rndv_rtr_common_send(req, ucp_proto_rndv_rtr_mtcopy_pack);
}

static ucs_status_t
ucp_proto_rndv_rtr_mtcopy_init(const ucp_proto_init_params_t *init_params)
{
    ucs_linear_func_t unpack_time;
    ucs_status_t status;
    size_t frag_size;

    status = ucp_proto_rndv_mtcopy_init(init_params, NULL, &frag_size);
    if (status != UCS_OK) {
        return status;
    }

    unpack_time = ucp_proto_common_get_pack_time(
            init_params->worker, init_params->select_param->mem_type, frag_size,
            0, 0, "rtr/mtcopy");

    return ucp_proto_rndv_rtr_common_init(
            init_params, ucp_proto_rndv_rtr_mtcopy_data_received,
            UCS_BIT(UCP_RNDV_MODE_PUT_PIPELINE), frag_size, unpack_time,
            UCS_MEMORY_TYPE_HOST, UCS_SYS_DEVICE_ID_UNKNOWN);
}

static ucp_proto_t ucp_rndv_rtr_mtcopy_proto = {
    .name       = "rndv/rtr/mtcopy",
    .flags      = 0,
    .init       = ucp_proto_rndv_rtr_mtcopy_init,
    .config_str = ucp_proto_rndv_ctrl_config_str,
    .progress   = {ucp_proto_rndv_rtr_mtcopy_progress},
};
UCP_PROTO_REGISTER(&ucp_rndv_rtr_mtcopy_proto);

ucs_status_t ucp_proto_rndv_rtr_handle_atp(void *arg, void *data, size_t length,
                                           unsigned flags)
{
    ucp_worker_h worker     = arg;
    ucp_rndv_atp_hdr_t *atp = data;
    const ucp_proto_rndv_rtr_priv_t *rpriv;
    ucp_request_t *req;

    UCP_SEND_REQUEST_GET_BY_ID(&req, worker, atp->super.req_id, 0,
                               return UCS_OK, "ATP %p", atp);

    ++req->send.state.completed_size;
    ucp_trace_req(req, "got atp, count %zu", req->send.state.completed_size);

    if (req->send.state.completed_size == atp->count) {
        /* TODO check status in ATP header */
        rpriv = req->send.proto_config->priv;
        rpriv->data_received(req, 0);
    }

    return UCS_OK;
}

ucs_status_t
ucp_proto_rndv_handle_data(void *arg, void *data, size_t length, unsigned flags)
{
    ucp_worker_h worker                = arg;
    ucp_rndv_data_hdr_t *rndv_data_hdr = data;
    size_t recv_len                    = length - sizeof(*rndv_data_hdr);
    const ucp_proto_rndv_rtr_priv_t *rpriv;
    ucp_request_t *req;
    size_t data_length;

    UCP_SEND_REQUEST_GET_BY_ID(&req, worker, rndv_data_hdr->rreq_id, 0,
                               return UCS_OK, "RNDV_DATA %p", rndv_data_hdr);

    /* TODO handle unpack status */
    ucp_datatype_iter_unpack(&req->send.state.dt_iter, worker, recv_len,
                             rndv_data_hdr->offset, rndv_data_hdr + 1);

    req->send.state.completed_size += recv_len;

    data_length = req->send.state.dt_iter.length;
    ucs_assert(req->send.state.completed_size <= data_length);
    if (req->send.state.completed_size == data_length) {
        rpriv = req->send.proto_config->priv;
        rpriv->data_received(req, 0);
    }

    return UCS_OK;
}
