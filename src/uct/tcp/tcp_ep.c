/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "tcp.h"


static UCS_CLASS_INIT_FUNC(uct_tcp_ep_t, uct_iface_t *tl_iface,
                           const uct_device_addr_t *dev_addr,
                           const uct_iface_addr_t *iface_addr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    struct sockaddr_in dest_addr;
    ucs_status_t status;

    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super)

    // TODO dup2 if found

    status = uct_tcp_socket_create(&self->fd);
    if (status != UCS_OK) {
        return status;
    }

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port   = *(in_port_t*)iface_addr;
    dest_addr.sin_addr   = *(struct in_addr*)dev_addr;
    status = uct_tcp_socket_connect(self->fd, &dest_addr);
    if (status != UCS_OK) {
        return status;
    }

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_tcp_ep_t)
{
    ucs_trace_func("self=%p", self);
    close(self->fd);
    // TODO remove from hash
}

UCS_CLASS_DEFINE(uct_tcp_ep_t, uct_base_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_tcp_ep_t, uct_ep_t, uct_iface_t *,
                          const uct_device_addr_t *, const uct_iface_addr_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_tcp_ep_t, uct_ep_t);

ssize_t uct_tcp_ep_am_bcopy(uct_ep_h uct_ep, uint8_t am_id,
                            uct_pack_callback_t pack_cb, void *arg)
{
    uct_tcp_ep_t *ep = ucs_derived_of(uct_ep, uct_tcp_ep_t);
    uct_tcp_iface_t *iface = ucs_derived_of(uct_ep->iface, uct_tcp_iface_t);
    uct_tcp_desc_t *desc;
    size_t packed_length;
    ucs_status_t status;

    desc = ucs_mpool_get(&iface->mp);
    if (desc == NULL) {
        return UCS_ERR_NO_RESOURCE;
    }

    packed_length = pack_cb(desc + 1, arg);
    UCT_CHECK_LENGTH(packed_length, iface->config.max_bcopy, "am_bcopy");

    desc->am_id  = am_id;
    desc->length = packed_length;

    status = uct_tcp_send(ep->fd, desc, sizeof(*desc) + packed_length);
    ucs_mpool_put(desc);

    if (status < 0) {
        return status;
    }

    ucs_trace_data("SEND am_id %d", am_id); // TODO
    return packed_length;
}
