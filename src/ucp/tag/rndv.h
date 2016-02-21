/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_TAG_RNDV_H_
#define UCP_TAG_RNDV_H_

#include "match.h"

#include <ucp/api/ucp.h>
#include <ucp/core/ucp_request.h>
#include <ucp/proto/proto.h>


/**
 * Header for rndv rts
 */
typedef struct {
    ucp_tag_hdr_t             super;
    ucp_txn_hdr_t             txn;
    uint64_t                  address;
    size_t                    size;
    /* packed rkey follows */
} UCS_S_PACKED ucp_rndv_rts_hdr_t;



ucs_status_t ucp_tag_send_start_rndv(ucp_request_t *req, int has_txn);


void ucp_rndv_matched(ucp_worker_h worker, ucp_request_t *req,
                      ucp_rndv_rts_hdr_t *rndv_rts_hdr);


static inline size_t ucp_rndv_total_len(ucp_rndv_rts_hdr_t *hdr)
{
    return hdr->size;
}

#endif
