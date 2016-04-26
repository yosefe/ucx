/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "rndv.h"
#include <ucp/proto/proto_am.inl>
#include <ucp/core/ucp_request.inl>
#include <ucs/datastruct/queue.h>

#define UCP_ALIGN 256
#define UCP_MTU_SIZE 4096

static size_t ucp_tag_rndv_rts_pack(void *dest, void *arg)
{
    ucp_rndv_rts_hdr_t *rndv_rts_hdr = dest;
    ucp_request_t *req = arg;

    rndv_rts_hdr->super.tag       = req->send.tag;
    rndv_rts_hdr->req.reqptr      = (uintptr_t)req;
    rndv_rts_hdr->req.sender_uuid = req->send.ep->worker->uuid;
    rndv_rts_hdr->address         = (uintptr_t)req->send.buffer;
    rndv_rts_hdr->size            = req->send.length;
    if (req->send.state.dt.contig.memh != UCT_INVALID_MEM_HANDLE) {
        uct_pd_mkey_pack(ucp_ep_pd(req->send.ep, UCP_EP_OP_AM),
                         req->send.state.dt.contig.memh,
                         rndv_rts_hdr + 1);
        return sizeof(*rndv_rts_hdr) +
                      ucp_ep_pd_attr(req->send.ep, UCP_EP_OP_AM)->rkey_packed_size;
    } else {
        /* For rndv emulation based on send-recv */
        return sizeof(*rndv_rts_hdr);
    }
}

static ucs_status_t ucp_proto_progress_rndv_rts(uct_pending_req_t *self)
{
    /* send the RTS. the pack_cb will pack all the necessary fields in the RTS */
    ucs_status_t status = ucp_do_am_bcopy_single(self, UCP_AM_ID_RNDV_RTS,
                                                 ucp_tag_rndv_rts_pack);
    return status;
}

ucs_status_t ucp_tag_send_start_rndv(ucp_request_t *req)
{
    ucs_status_t status;

    /* zcopy */
    status = ucp_request_send_buffer_reg(req, UCP_EP_OP_RMA);
    if (status != UCS_OK) {
        return status;
    }

    ucp_ep_connect_remote(req->send.ep);

    req->send.uct.func = ucp_proto_progress_rndv_rts;
    return UCS_OK;
}

static ucs_status_t ucp_proto_progress_rndv_get(uct_pending_req_t *self)
{
    ucp_request_t *get_req = ucs_container_of(self, ucp_request_t, send.uct);
    ucs_status_t status;
    size_t offset, length;

    offset = get_req->send.state.offset;

    ucs_debug("offset %zu remainder %zu", offset, (uintptr_t)get_req->send.buffer % UCP_ALIGN);

    if ((offset == 0) && ((uintptr_t)get_req->send.buffer % UCP_ALIGN)) {
        length = UCP_MTU_SIZE - ((uintptr_t)get_req->send.buffer % UCP_ALIGN);
    } else {
        length = ucs_min(get_req->send.length - offset,
                         ucp_ep_config(get_req->send.ep)->max_get_zcopy);
    }

    ucs_debug("read %p len %zu", (void*)get_req->send.buffer + offset, length);
    status = uct_ep_get_zcopy(get_req->send.ep->uct_eps[UCP_EP_OP_RMA],
                              (void*)get_req->send.buffer + offset,
                              length,
                              get_req->send.state.dt.contig.memh,
                              get_req->send.rndv_get.remote_address + offset,
                              get_req->send.rndv_get.rkey,
                              &get_req->send.uct_comp);

    if ((status == UCS_OK) || (status == UCS_INPROGRESS)) {
        get_req->send.state.offset += length;
        if (get_req->send.state.offset == get_req->send.length) {
            return UCS_OK;
        } else {
            return UCS_INPROGRESS;
        }
    } else {
       return status;
    }
}

static ucs_status_t ucp_rndv_truncated(uct_pending_req_t *self)
{
    ucp_request_t *get_req = ucs_container_of(self, ucp_request_t, send.uct);
    ucp_request_t *req     = get_req->send.rndv_get.rreq;
    uintptr_t remote_req   = get_req->send.rndv_get.remote_request;

    ucs_debug("rndv get truncated");

    ucp_request_complete(req, req->cb.tag_recv, UCS_ERR_MESSAGE_TRUNCATED, &req->recv.info);

    get_req->send.uct.func     = ucp_proto_progress_am_bcopy_single;
    get_req->send.proto.am_id  = UCP_AM_ID_RNDV_ATS;
    get_req->send.proto.status = UCS_OK;
    get_req->send.proto.remote_request = remote_req;

    ucs_debug("send rndv ats");
    ucp_ep_send_reply(get_req, UCP_EP_OP_AM, 0);

    return UCS_OK;
}

static void ucp_rndv_get_completion(uct_completion_t *self)
{
    ucp_request_t *get_req = ucs_container_of(self, ucp_request_t, send.uct_comp);
    ucp_request_t *req     = get_req->send.rndv_get.rreq;
    uintptr_t remote_req   = get_req->send.rndv_get.remote_request;

    ucs_debug("rndv get completed");

    ucp_request_complete(req, req->cb.tag_recv, UCS_OK, &req->recv.info);
    ucp_request_send_buffer_dereg(get_req, UCP_EP_OP_RMA);

    get_req->send.uct.func     = ucp_proto_progress_am_bcopy_single;
    get_req->send.proto.am_id  = UCP_AM_ID_RNDV_ATS;
    get_req->send.proto.status = UCS_OK;
    get_req->send.proto.remote_request = remote_req;

    ucs_debug("send rndv ats");
    ucp_ep_send_reply(get_req, UCP_EP_OP_AM, 0);
}

void ucp_rndv_matched(ucp_worker_h worker, ucp_request_t *req,
                      ucp_rndv_rts_hdr_t *rndv_rts_hdr)
{
    uct_rkey_bundle_t rkey_ob;
    ucp_request_t *get_req;
    ucs_status_t status;
    size_t recv_size;

    ucs_trace_req("ucp_rndv_matched");

    req->recv.info.sender_tag = rndv_rts_hdr->super.tag;
    req->recv.info.length     = rndv_rts_hdr->size;

    get_req = ucp_worker_allocate_reply(worker, rndv_rts_hdr->req.sender_uuid);
    get_req->send.uct.func     = ucp_proto_progress_rndv_get;
    get_req->send.buffer       = req->recv.buffer;

    ucs_assert_always(req->recv.count != 0);
    ucs_assertv_always((req->recv.datatype & UCP_DATATYPE_CLASS_MASK) == UCP_DATATYPE_CONTIG,
                       "dtype=0x%lx", req->recv.datatype);

    uct_rkey_unpack(rndv_rts_hdr + 1, &rkey_ob);
    get_req->send.rndv_get.remote_request = rndv_rts_hdr->req.reqptr;
    get_req->send.rndv_get.remote_address = rndv_rts_hdr->address;
    get_req->send.rndv_get.rkey = rkey_ob.rkey;
    get_req->send.rndv_get.rreq = req;

    recv_size = ucp_contig_dt_length(req->recv.datatype, req->recv.count);
    if (ucs_unlikely(recv_size < rndv_rts_hdr->size)) {
        ucs_debug("message truncated: recv_length %zu rts_send_size %zu",
                  recv_size, rndv_rts_hdr->size);
        get_req->send.uct.func  = ucp_rndv_truncated;
        goto out;
    }
    get_req->send.length = rndv_rts_hdr->size;
    status = ucp_request_send_buffer_reg(get_req, UCP_EP_OP_RMA);  /* TODO Not all UCTs need reg on recv side */
    ucs_assert_always(status == UCS_OK);
//ucs_warn("IN RNDV. max_get_zcopy: %zu", ucp_ep_config(get_req->send.ep)->max_get_zcopy);
    get_req->send.state.offset  = 0;
    {
        size_t max_get_zcopy = ucp_ep_config(get_req->send.ep)->max_get_zcopy;
        size_t remainder = (uintptr_t)get_req->send.buffer % UCP_ALIGN;

        if (remainder) {
            get_req->send.uct_comp.count = 1 +
               (get_req->send.length - (UCP_MTU_SIZE - remainder) + max_get_zcopy - 1) / max_get_zcopy;
        } else {
            get_req->send.uct_comp.count = (get_req->send.length + max_get_zcopy - 1) / max_get_zcopy;
        }
    }

    get_req->send.uct_comp.func  = ucp_rndv_get_completion;

out:
    /* Release the remote key since its content was copied to the get request
     * for the future get operation */
    uct_rkey_release(&rkey_ob);      //how can this be tested?

    ucs_debug("send rndv get");
    ucp_ep_send_reply(get_req, UCP_EP_OP_RMA,0);
}

static ucs_status_t
ucp_rndv_rts_handler(void *arg, void *data, size_t length, void *desc)
{
    ucp_worker_h worker = arg;
    ucp_rndv_rts_hdr_t *rndv_rts_hdr = data;
    ucp_context_h context = worker->context;
    ucp_recv_desc_t *rdesc = desc;
    ucp_tag_t recv_tag = rndv_rts_hdr->super.tag;
    ucp_request_t *req;
    ucs_queue_iter_t iter;

    /* Search in expected queue */
    ucs_queue_for_each_safe(req, iter, &context->tag.expected, recv.queue) {
        req = ucs_container_of(*iter, ucp_request_t, recv.queue);
        if (ucp_tag_recv_is_match(recv_tag, UCP_RECV_DESC_FLAG_FIRST, req->recv.tag,
                                  req->recv.tag_mask, req->recv.state.offset,
                                  req->recv.info.sender_tag))
        {
            ucp_tag_log_match(recv_tag, req, req->recv.tag, req->recv.tag_mask,
                              req->recv.state.offset, "expected-rndv");
            ucs_queue_del_iter(&context->tag.expected, iter);
            ucp_rndv_matched(worker, req, rndv_rts_hdr);
            return UCS_OK;
        }
    }

    ucs_trace_req("unexp rndv recv tag %"PRIx64" length %zu desc %p",
                  recv_tag, length, rdesc);
    if (data != rdesc + 1) {
        memcpy(rdesc + 1, data, length);
    }

    rdesc->length  = length;
    rdesc->hdr_len = sizeof(*rndv_rts_hdr);
    rdesc->flags   = UCP_RECV_DESC_FLAG_FIRST | UCP_RECV_DESC_FLAG_LAST |
                     UCP_RECV_DESC_FLAG_RNDV;
    ucs_queue_push(&context->tag.unexpected, &rdesc->queue);
    return UCS_INPROGRESS;
}

static ucs_status_t
ucp_rndv_ats_handler(void *arg, void *data, size_t length, void *desc)
{
    ucp_reply_hdr_t *rep_hdr = data;
    ucp_request_t *req = (ucp_request_t*) rep_hdr->reqptr;

    /* dereg the original send request and set it to complete */
    ucp_request_send_buffer_dereg(req, UCP_EP_OP_RMA);
    ucp_request_complete(req, req->cb.send, UCS_OK);

    return UCS_OK;
}

static void ucp_rndv_dump(ucp_worker_h worker, uct_am_trace_type_t type,
                          uint8_t id, const void *data, size_t length,
                          char *buffer, size_t max)
 {

    const ucp_rndv_rts_hdr_t *rndv_rts_hdr = data;
    const ucp_reply_hdr_t *rep_hdr = data;
    size_t header_len;
    char *p, *endp;
    size_t i;

    switch (id) {
    case UCP_AM_ID_RNDV_RTS:
        snprintf(buffer, max, "RNDV_RTS tag %"PRIx64" uuid %"PRIx64
                 "address 0x%"PRIx64" size %zu rkey ", rndv_rts_hdr->super.tag,
                 rndv_rts_hdr->req.sender_uuid,
                 rndv_rts_hdr->req.reqptr, rndv_rts_hdr->size);

        p    = buffer + strlen(buffer);
        endp = buffer + max;
        i    = sizeof(*rndv_rts_hdr);
        while ((p < endp) && (i < length)) {
            uint8_t b = ((const uint8_t*)data)[i++];
            snprintf(p, endp - p, "%hhx", b);
            p += strlen(p);
        }
        header_len = sizeof(*rndv_rts_hdr);
        break;
    case UCP_AM_ID_RNDV_ATS:
        snprintf(buffer, max, "RNDV_ATS request %0"PRIx64" status '%s'", rep_hdr->reqptr,
                 ucs_status_string(rep_hdr->status));
        header_len = sizeof(*rep_hdr);
        break;
    default:
        return;
    }
 }

UCP_DEFINE_AM(UCP_FEATURE_TAG, UCP_AM_ID_RNDV_RTS, ucp_rndv_rts_handler,
              ucp_rndv_dump, UCT_AM_CB_FLAG_SYNC);
UCP_DEFINE_AM(UCP_FEATURE_TAG, UCP_AM_ID_RNDV_ATS, ucp_rndv_ats_handler,
              ucp_rndv_dump, UCT_AM_CB_FLAG_SYNC);
