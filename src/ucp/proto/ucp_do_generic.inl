/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <ucp/core/ucp_context.h>


static UCS_F_ALWAYS_INLINE size_t
ucp_req_generic_dt_pack(ucp_request_t *req, void *dest, size_t length)
{
    ucp_dt_generic_t *dt = ucp_dt_generic(req->send.datatype);
    return dt->ops.pack(req->send.state.dt.generic.state,
                        req->send.state.offset, dest, length);
}

static UCS_F_ALWAYS_INLINE void
ucp_req_generic_dt_finish(ucp_request_t *req)
{
    ucp_dt_generic_t *dt = ucp_dt_generic(req->send.datatype);
    return dt->ops.finish(req->send.state.dt.generic.state);
}

