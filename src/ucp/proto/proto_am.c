/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "proto.h"
#include "proto_am.inl"

static size_t ucp_proto_pack(void *dest, void *arg)
{
    ucp_request_t *req = arg;
    ucp_txn_ack_hdr_t *ack_hdr = dest;

    switch (req->send.proto.am_id) {
    case UCP_AM_ID_EAGER_SYNC_ACK:
        ack_hdr->tid    = req->send.proto.tid;
        ack_hdr->status = req->send.proto.status;
        return sizeof(*ack_hdr);
    case UCP_AM_ID_RNDV_ATS:
        ack_hdr->tid    = req->send.proto.tid;
        ack_hdr->status = req->send.proto.status;
        return sizeof(*ack_hdr);
    }

    ucs_bug("unexpected am_id");
    return 0;
}

ucs_status_t ucp_proto_progress_am_bcopy_single(uct_pending_req_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.uct);

    ucs_status_t status = ucp_do_am_bcopy_single(self, req->send.proto.am_id,
                                                 ucp_proto_pack);
    if (status == UCS_OK) {
        ucs_mpool_put(req);
    }
    return status;
}

