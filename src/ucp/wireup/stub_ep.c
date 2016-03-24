/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "stub_ep.h"
#include "wireup.h"

#include <ucp/core/ucp_worker.h>
#include <ucs/arch/atomic.h>
#include <ucs/datastruct/queue.h>
#include <ucs/type/class.h>

UCS_CLASS_DECLARE(ucp_stub_ep_t, ucp_ep_h, ucp_ep_op_t, unsigned,
                  const ucp_address_entry_t*);


static UCS_CLASS_DEFINE_DELETE_FUNC(ucp_stub_ep_t, uct_ep_t);

static ucs_status_t ucp_stub_ep_get_address(uct_ep_h uct_ep, uct_ep_addr_t *addr)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);
    return uct_ep_get_address(stub_ep->next_ep, addr);
}

static ucs_status_t ucp_stub_ep_connect_to_ep(uct_ep_h uct_ep,
                                              const uct_device_addr_t *dev_addr,
                                              const uct_ep_addr_t *ep_addr)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);
    return uct_ep_connect_to_ep(stub_ep->next_ep, dev_addr, ep_addr);
}

void ucp_stub_ep_progress(ucp_stub_ep_t *stub_ep)
{
    ucp_ep_h ep = stub_ep->ep;
    ucs_queue_head_t tmp_pending_queue;
    ucp_worker_h worker = ep->worker;
    uct_pending_req_t *req;
    ucs_status_t status;
    uct_ep_h uct_ep;
    ucp_ep_op_t optype;

    /*
     * We switch the endpoint in this function (instead in wireup code) since
     * this is guaranteed to run from the main thread.
     * Don't start using the transport before the wireup protocol finished
     * sending ack/reply.
     */
    sched_yield();
    ucs_async_check_miss(&ep->worker->async);

    /*
     * Check that we are ready to switch:
     * - Remote side must also be connected.
     * - We should have sent a wireup reply to remote side
     * - We should have sent all pending wireup operations (so we won't discard them)
     */
    if (!(stub_ep->state & UCP_STUB_EP_CONNECTED) ||
        (stub_ep->pending_count != 0))
    {
        return;
    }

    ucs_trace("switching stub_ep %p (ep %p) to ready state", stub_ep, ep);

    ucs_memory_cpu_fence();
    UCS_ASYNC_BLOCK(&worker->async);

    /* Take out next_ep */
    uct_ep = stub_ep->next_ep;
    stub_ep->next_ep = NULL;

    /* Move stub pending queue to temporary queue and remove references to
     * the stub progress function
     */
    ucs_queue_head_init(&tmp_pending_queue);
    ucs_queue_for_each_extract(req, &stub_ep->pending_q, priv, 1) {
        ucs_trace("move request %p to tmp pending queue", req);
        ucs_queue_push(&tmp_pending_queue, ucp_stub_ep_req_priv(req));
    }

    /* Switch to real transport */
    ep->uct_eps[stub_ep->optype] = uct_ep;
    for (optype = 0; optype < UCP_EP_OP_LAST; ++optype) {
        if (ucp_ep_config(ep)->dups[optype] == stub_ep->optype) {
            ep->uct_eps[optype] = uct_ep;
        }
    }

    ucp_worker_stub_ep_remove(stub_ep->ep->worker, stub_ep);

    /* Destroy stub endpoint (destroys aux_ep as well) */
    ucs_trace("destroying stub_ep %p", stub_ep);
    optype = stub_ep->optype;
    uct_ep_destroy(&stub_ep->super);
    stub_ep = NULL;
    ucs_trace("switched ep %p op %d to uct_ep %p", ep, optype, uct_ep);

    UCS_ASYNC_UNBLOCK(&worker->async);

    /* Replay pending requests */
    ucs_queue_for_each_extract(req, &tmp_pending_queue, priv, 1) {
        do {
            status = ucp_ep_add_pending_uct(ep, uct_ep, req);
        } while (status != UCS_OK);
        --ep->worker->stub_pend_count;
    }
}

static ucs_status_t ucp_stub_ep_send_func(uct_ep_h uct_ep)
{
    return UCS_ERR_NO_RESOURCE;
}

static ssize_t ucp_stub_ep_bcopy_send_func(uct_ep_h uct_ep)
{
    return UCS_ERR_NO_RESOURCE;
}

static uct_ep_h ucp_stub_ep_get_wireup_msg_ep(ucp_stub_ep_t *stub_ep)
{
    uct_ep_h wireup_msg_ep;

    if (stub_ep->state & UCP_STUB_EP_CONNECTED) {
        wireup_msg_ep = stub_ep->next_ep;
    } else {
        wireup_msg_ep = stub_ep->aux_ep;
    }
    ucs_assert(wireup_msg_ep != NULL);
    return wireup_msg_ep;
}

static ucs_status_t ucp_stub_pending_add(uct_ep_h uct_ep, uct_pending_req_t *req)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);
    uct_ep_h wireup_msg_ep;
    ucs_status_t status;
    ucp_ep_h ep;

    if (req->func == ucp_wireup_msg_progress) {
        wireup_msg_ep = ucp_stub_ep_get_wireup_msg_ep(stub_ep);
        ucs_trace("putting pending request %p on ep %p", req, wireup_msg_ep);
        status = uct_ep_pending_add(wireup_msg_ep, req);
        if (status == UCS_OK) {
//            ucs_atomic_add32(&stub_ep->pending_count, 1);
        }
        return status;
    }

    ep = stub_ep->ep;
    ucs_queue_push(&stub_ep->pending_q, ucp_stub_ep_req_priv(req));
    ++ep->worker->stub_pend_count;
    return UCS_OK;
}

static ssize_t ucp_stub_ep_am_bcopy(uct_ep_h uct_ep, uint8_t id,
                                    uct_pack_callback_t pack_cb, void *arg)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);

    if (id == UCP_AM_ID_WIREUP) {
        return uct_ep_am_bcopy(ucp_stub_ep_get_wireup_msg_ep(stub_ep),
                               UCP_AM_ID_WIREUP, pack_cb, arg);

    }

    return UCS_ERR_NO_RESOURCE;
}

static void ucp_stub_pending_purge(uct_ep_h uct_ep, uct_pending_callback_t cb)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);
    ucs_assert_always(ucs_queue_is_empty(&stub_ep->pending_q));
}

static uct_iface_t ucp_stub_iface = {
    .ops = {
        .ep_get_address       = ucp_stub_ep_get_address,
        .ep_connect_to_ep     = ucp_stub_ep_connect_to_ep,
        .ep_flush             = (void*)ucs_empty_function_return_inprogress,
        .ep_destroy           = UCS_CLASS_DELETE_FUNC_NAME(ucp_stub_ep_t),
        .ep_pending_add       = ucp_stub_pending_add,
        .ep_pending_purge     = ucp_stub_pending_purge,
        .ep_put_short         = (void*)ucp_stub_ep_send_func,
        .ep_put_bcopy         = (void*)ucp_stub_ep_bcopy_send_func,
        .ep_put_zcopy         = (void*)ucp_stub_ep_send_func,
        .ep_get_bcopy         = (void*)ucp_stub_ep_send_func,
        .ep_get_zcopy         = (void*)ucp_stub_ep_send_func,
        .ep_am_short          = (void*)ucp_stub_ep_send_func,
        .ep_am_bcopy          = ucp_stub_ep_am_bcopy,
        .ep_am_zcopy          = (void*)ucp_stub_ep_send_func,
        .ep_atomic_add64      = (void*)ucp_stub_ep_send_func,
        .ep_atomic_fadd64     = (void*)ucp_stub_ep_send_func,
        .ep_atomic_swap64     = (void*)ucp_stub_ep_send_func,
        .ep_atomic_cswap64    = (void*)ucp_stub_ep_send_func,
        .ep_atomic_add32      = (void*)ucp_stub_ep_send_func,
        .ep_atomic_fadd32     = (void*)ucp_stub_ep_send_func,
        .ep_atomic_swap32     = (void*)ucp_stub_ep_send_func,
        .ep_atomic_cswap32    = (void*)ucp_stub_ep_send_func
    }
};

UCS_CLASS_DEFINE_NAMED_NEW_FUNC(ucp_stub_ep_create, ucp_stub_ep_t, uct_ep_t,
                                ucp_ep_h, ucp_ep_op_t, unsigned,
                                const ucp_address_entry_t*);

static double ucp_wireup_aux_score_func(ucp_worker_h worker,
                                        uct_iface_attr_t *iface_attr,
                                        char *reason, size_t max)
{
    if (!(iface_attr->cap.flags & UCT_IFACE_FLAG_AM_BCOPY)) {
        strncpy(reason, "am_bcopy for wireup", max);
        return 0.0;
    }

    if (!(iface_attr->cap.flags & UCT_IFACE_FLAG_CONNECT_TO_IFACE)) {
        strncpy(reason, "connecting to iface", max);
        return 0.0;
    }

    if (!(iface_attr->cap.flags & UCT_IFACE_FLAG_CONNECT_TO_IFACE)) {
        strncpy(reason, "async am callback", max);
        return 0.0;
    }

    if (!(iface_attr->cap.flags & UCT_IFACE_FLAG_CONNECT_TO_IFACE)) {
        strncpy(reason, "pending", max);
        return 0.0;
    }

    return (1e-3 / iface_attr->latency) +
           (1e3 * ucs_max(iface_attr->cap.am.max_bcopy, iface_attr->cap.am.max_short));
}

static ucs_status_t
ucp_stub_ep_connect_aux(ucp_stub_ep_t *stub_ep, unsigned address_count,
                        const ucp_address_entry_t *address_list)
{
    ucp_ep_h ep            = stub_ep->ep;
    ucp_worker_h worker    = ep->worker;
    const ucp_address_entry_t *aux_addr;
    unsigned aux_addr_index;
    ucs_status_t status;

    /* select an auxiliary transport which would be used to pass connection
     * establishment messages.
     */
    status = ucp_select_transport(worker, ucp_ep_peer_name(ep), address_list,
                                  address_count, UCP_NULL_RESOURCE,
                                  &stub_ep->aux_rsc_index, &aux_addr_index,
                                  ucp_wireup_aux_score_func, "auxiliary");
    if (status != UCS_OK) {
        return status;
    }

    aux_addr = &address_list[aux_addr_index];

    /* create auxiliary endpoint connected to the remote iface. */
    ucs_assert(aux_addr->tl_addr_len > 0);
    status = uct_ep_create_connected(worker->ifaces[stub_ep->aux_rsc_index],
                                     aux_addr->dev_addr, aux_addr->iface_addr,
                                     &stub_ep->aux_ep);
    if (status != UCS_OK) {
        return status;
    }

    ucs_debug("created aux_ep %p to %s using " UCT_TL_RESOURCE_DESC_FMT,
              stub_ep->aux_ep, ucp_ep_peer_name(ep),
              UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[aux_addr_index].tl_rsc));
    return UCS_OK;
}

UCS_CLASS_INIT_FUNC(ucp_stub_ep_t, ucp_ep_h ep, ucp_ep_op_t optype,
                    unsigned address_count, const ucp_address_entry_t *address_list)
{
    ucs_status_t status;

    self->super.iface   = &ucp_stub_iface;
    self->ep            = ep;
    self->aux_ep        = NULL;
    self->next_ep       = NULL;
    self->optype        = optype;
    self->aux_rsc_index = UCP_NULL_RESOURCE;
    self->pending_count = 0;
    self->state         = 0;
    ucs_queue_head_init(&self->pending_q);

    if (ep->cfg_index != (uint8_t)-1) {
        status = ucp_stub_ep_connect(&self->super, address_count, address_list);
        if (status != UCS_OK) {
            return status;
        }
    }

    ucs_debug("created stub ep %p to %s for %s [next_ep %p aux_ep %p] ",
              self, ucp_ep_peer_name(ep), ucp_wireup_ep_ops[optype].title,
              self->next_ep, self->aux_ep);
    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(ucp_stub_ep_t)
{
    ucs_assert(ucs_queue_is_empty(&self->pending_q));
    if (self->aux_ep != NULL) {
        uct_ep_destroy(self->aux_ep);
    }
    if (self->next_ep != NULL) {
        uct_ep_destroy(self->next_ep);
    }
}

UCS_CLASS_DEFINE(ucp_stub_ep_t, void);

ucp_rsc_index_t ucp_stub_ep_get_aux_rsc_index(uct_ep_h uct_ep)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);

    if (uct_ep->iface != &ucp_stub_iface) {
        return UCP_NULL_RESOURCE;
    }

    ucs_assert(stub_ep->aux_ep != NULL);
    return stub_ep->aux_rsc_index;
}

ucs_status_t ucp_stub_ep_connect(uct_ep_h uct_ep, unsigned address_count,
                                 const ucp_address_entry_t *address_list)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);
    ucp_ep_h ep            = stub_ep->ep;
    ucp_worker_h worker    = ep->worker;
    ucp_rsc_index_t rsc_index;
    ucs_status_t status;

    rsc_index = ucp_ep_config(ep)->rscs[stub_ep->optype];
    status = uct_ep_create(worker->ifaces[rsc_index], &stub_ep->next_ep);
    if (status != UCS_OK) {
        goto err;
    }

    ucs_debug("created next_ep %p to %s using " UCT_TL_RESOURCE_DESC_FMT,
              stub_ep->next_ep, ucp_ep_peer_name(ep),
              UCT_TL_RESOURCE_DESC_ARG(&worker->context->tl_rscs[rsc_index].tl_rsc));

    /* we need to create an auxiliary transport only for active messages */
    if (stub_ep->optype == UCP_EP_OP_AM) {
        status = ucp_stub_ep_connect_aux(stub_ep, address_count, address_list);
        if (status != UCS_OK) {
            goto err_destroy_next_ep;
        }
    }

    return UCS_OK;

err_destroy_next_ep:
    uct_ep_destroy(stub_ep->next_ep);
err:
    return status;
}

void ucp_stub_ep_set_next_ep(uct_ep_h uct_ep, uct_ep_h next_ep)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);

    ucs_assert(uct_ep->iface == &ucp_stub_iface);
    ucs_assert(stub_ep->next_ep == NULL);
    stub_ep->next_ep = next_ep;
}

void ucp_stub_ep_remote_connected(uct_ep_h uct_ep)
{
    ucp_stub_ep_t *stub_ep = ucs_derived_of(uct_ep, ucp_stub_ep_t);

    ucs_assert(uct_ep->iface == &ucp_stub_iface);
    ucs_assert(stub_ep->next_ep != NULL);
    ucs_trace("stub ep %p is remote-connected", stub_ep);
    stub_ep->state |= UCP_STUB_EP_CONNECTED;
    ucp_worker_stub_ep_add(stub_ep->ep->worker, stub_ep);
}
