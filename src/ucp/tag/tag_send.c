/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "match.h"
#include "eager.h"
#include "rndv.h"

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/core/ucp_context.h>
#include <ucp/dt/dt_generic.h>
#include <ucs/datastruct/mpool.inl>
#include <string.h>


static void ucp_tag_zcopy_completion(uct_completion_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct_comp);

    (void)uct_pd_mem_dereg(ucp_ep_pd(req->send.ep), req->send.state.dt.contig.memh);
    ucp_request_complete(req, req->cb.send, UCS_OK);
}

static ucs_status_t
ucp_tag_send_start_req(ucp_ep_h ep, const void *buffer, size_t count,
                       ucp_datatype_t datatype, ucp_tag_t tag,
                       ucp_request_t *req)
{
    ucp_dt_generic_t *dt_gen;
    ucs_status_t status;
    size_t max_zcopy;
    size_t length;
    void *state;

    req->send.ep           = ep;
    req->send.buffer       = buffer;
    req->send.count        = count;
    req->send.datatype     = datatype;
    req->send.state.offset = 0;
    req->send.tag          = tag;

    switch (datatype & UCP_DATATYPE_CLASS_MASK) {
    case UCP_DATATYPE_CONTIG:
        /* TODO check for zero-copy */
        req->send.length = length = ucp_contig_dt_length(datatype, count);

        if (length <= ucp_ep_config(ep)->eager.max_short) {
            /* short */
            req->send.uct.func = ucp_tag_progress_eager_contig_short;
        } else if (length < ucp_ep_config(ep)->eager.zcopy_thresh) {
            /* bcopy */
            if (req->send.length <= ucp_ep_config(ep)->eager.max_bcopy) {
                req->send.uct.func = ucp_tag_progress_eager_contig_bcopy_single;
            } else {
                req->send.uct.func = ucp_tag_progress_eager_contig_bcopy_multi;
            }
        } else {
            /* zcopy */
            status = uct_pd_mem_reg(ucp_ep_pd(ep), (void*)buffer, length,
                                    &req->send.state.dt.contig.memh);
            if (status != UCS_OK) {
                ucs_error("failed to register user buffer: %s",
                          ucs_status_string(status));
                return status;
            }

            req->send.uct_comp.func = ucp_tag_zcopy_completion;

            max_zcopy = ucp_ep_config(ep)->eager.max_zcopy;
            if (req->send.length <= max_zcopy) {
                req->send.uct_comp.count = 1;
                req->send.uct.func = ucp_tag_progress_eager_contig_zcopy_single;
            } else {
                size_t first_hdr_extra =
                                sizeof(ucp_eager_first_hdr_t) - sizeof(ucp_eager_hdr_t);
                req->send.uct_comp.count =
                                (length - first_hdr_extra + max_zcopy - 1) / max_zcopy;
                req->send.uct.func = ucp_tag_progress_eager_contig_zcopy_multi;
            }
        }

        if (req->send.length <= ucp_ep_config(ep)->rndv_thresh) {
            return UCS_OK;
        }
        break;

    case UCP_DATATYPE_GENERIC:
        dt_gen = ucp_dt_generic(datatype);
        state = dt_gen->ops.start_pack(dt_gen->context, buffer, count);

        req->send.state.dt.generic.state = state;
        req->send.length = dt_gen->ops.packed_size(state);
        if (req->send.length <= ucp_ep_config(ep)->rndv_thresh) {
            req->send.uct.func = ucp_tag_progress_eager_generic;
            return UCS_OK;
        }
        break;

    default:
        return UCS_ERR_INVALID_PARAM;
    }

    return ucp_tag_send_start_rndv(req);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_tag_send_try(ucp_ep_h ep, const void *buffer, size_t count,
                 ucp_datatype_t datatype, ucp_tag_t tag)
{
    size_t length;

    if (ucs_likely((datatype & UCP_DATATYPE_CLASS_MASK) == UCP_DATATYPE_CONTIG)) {
        length = ucp_contig_dt_length(datatype, count);
        if (ucs_likely(length <= ucp_ep_config(ep)->eager.max_short)) {
            return ucp_tag_send_eager_short(ep, tag, buffer, length);
        }
    }

    return UCS_ERR_NO_RESOURCE; /* Fallback to slower progress */
}

static UCS_F_NOINLINE
ucs_status_ptr_t ucp_tag_send_slow(ucp_ep_h ep, const void *buffer, size_t count,
                                   uintptr_t datatype, ucp_tag_t tag,
                                   ucp_send_callback_t cb)
{
    ucp_request_t *req;
    ucs_status_t status;

    req = ucs_mpool_get_inline(&ep->worker->req_mp);
    if (req == NULL) {
        return UCS_STATUS_PTR(UCS_ERR_NO_MEMORY);
    }

    VALGRIND_MAKE_MEM_DEFINED(req + 1, ep->worker->context->config.request.size);

    req->flags   = 0;
    req->cb.send = cb;

    status = ucp_tag_send_start_req(ep, buffer, count, datatype, tag, req);
    if (status != UCS_OK) {
        return UCS_STATUS_PTR(status); /* UCS_OK also goes here */
    }

    if (!(req->flags & UCP_REQUEST_FLAG_COMPLETED)) {
        ucp_ep_add_pending(ep, ep->uct_ep, req, 1);
        ucp_worker_progress(ep->worker);
    }

    ucs_trace_req("send_nb returning request %p", req);
    return req + 1;
}

ucs_status_ptr_t ucp_tag_send_nb(ucp_ep_h ep, const void *buffer, size_t count,
                                 uintptr_t datatype, ucp_tag_t tag,
                                 ucp_send_callback_t cb)
{
    ucs_status_t status;

    ucs_trace_req("send_nb buffer %p count %zu tag %"PRIx64" to %s cb %p",
                  buffer, count, tag, ucp_ep_peer_name(ep), cb);

    status = ucp_tag_send_try(ep, buffer, count, datatype, tag);
    if (ucs_likely(status != UCS_ERR_NO_RESOURCE)) {
        return UCS_STATUS_PTR(status); /* UCS_OK also goes here */
    }

    return ucp_tag_send_slow(ep, buffer, count, datatype, tag, cb);
}
