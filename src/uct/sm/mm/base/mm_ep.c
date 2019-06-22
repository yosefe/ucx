/**
* Copyright (C) UT-Battelle, LLC. 2015. ALL RIGHTS RESERVED.
* Copyright (C) Mellanox Technologies Ltd. 2001-2019.  ALL RIGHTS RESERVED.
* Copyright (C) ARM Ltd. 2016.  ALL RIGHTS RESERVED.
* See file LICENSE for terms.
*/

#include "mm_ep.h"

#include <ucs/arch/atomic.h>


static UCS_F_NOINLINE
void *uct_mm_ep_attach_remote_seg(uct_mm_ep_t *ep,
                                  const uct_mm_packed_rkey_t *packed_rkey)
{
    uct_mm_iface_t *iface = ucs_derived_of(ep->super.super.iface, uct_mm_iface_t);
    uct_mm_md_t *mm_md    = ucs_derived_of(iface->super.super.md, uct_mm_md_t);
    uct_mm_packed_rkey_t *full_rkey_buffer;
    uct_mm_remote_seg_t remote_seg;
    uct_rkey_t rkey;
    ucs_status_t status;
    khiter_t khiter;
    int khret;

    /* crrate a temporary remote key with extra md data, if we have such */
    full_rkey_buffer  = ucs_alloca(sizeof(uct_mm_packed_rkey_t) +
                                   mm_md->rkey_extra_size);
    *full_rkey_buffer = *packed_rkey;
    if (mm_md->rkey_extra_size > 0) {
        ucs_assert(ep->rkey_extra_data != NULL);
        memcpy(full_rkey_buffer + 1, ep->rkey_extra_data, mm_md->rkey_extra_size);
    }

    status = uct_rkey_unpack_internal(mm_md->super.component, full_rkey_buffer,
                                      &rkey, &remote_seg.cookie);
    if (status != UCS_OK) {
        ucs_fatal("Failed to attach to remote seg: %s",
                  ucs_status_string(status));
    }

    remote_seg.local_address = (void*)(packed_rkey->owner_ptr + (ptrdiff_t)rkey);

    khiter = kh_put(uct_mm_remote_seg, &ep->remote_segs, packed_rkey->owner_ptr,
                    &khret);
    ucs_assert_always((khret == 1) || (khret == 2));

    kh_val(&ep->remote_segs, khiter) = remote_seg;
    return remote_seg.local_address;
}

static UCS_F_ALWAYS_INLINE void *
uct_mm_ep_get_remote_seg(uct_mm_ep_t *ep,
                         const uct_mm_packed_rkey_t *packed_rkey)
{
    khiter_t khiter;

    khiter = kh_get(uct_mm_remote_seg, &ep->remote_segs, packed_rkey->owner_ptr);
    if (ucs_likely(khiter != kh_end(&ep->remote_segs))) {
        return kh_val(&ep->remote_segs, khiter).local_address;
    }

    return uct_mm_ep_attach_remote_seg(ep, packed_rkey);
}


/* send a signal to remote interface using Unix-domain socket */
static void uct_mm_ep_signal_remote(uct_mm_ep_t *ep)
{
    uct_mm_iface_t *iface = ucs_derived_of(ep->super.super.iface, uct_mm_iface_t);
    char dummy = 0;
    int ret;

    for (;;) {
        ret = sendto(iface->signal_fd, &dummy, sizeof(dummy), 0,
                     (const struct sockaddr*)&ep->signal.sockaddr,
                     ep->signal.addrlen);
        if (ucs_unlikely(ret < 0)) {
            if (errno == EINTR) {
                /* Interrupted system call - retry */
                continue;
            } if ((errno == EAGAIN) || (errno == ECONNREFUSED)) {
                /* If we failed to signal because buffer is full - ignore the error
                 * since it means the remote side would get a signal anyway.
                 * If the remote side is not there - ignore the error as well.
                 */
                ucs_trace("failed to send wakeup signal: %m");
                return;
            } else {
                ucs_warn("failed to send wakeup signal: %m");
                return;
            }
        } else {
            ucs_assert(ret == sizeof(dummy));
            ucs_trace("sent wakeup from socket %d to %p", iface->signal_fd,
                      (const struct sockaddr*)&ep->signal.sockaddr);
            return;
        }
    }
}

static UCS_CLASS_INIT_FUNC(uct_mm_ep_t, const uct_ep_params_t *params)
{
    uct_mm_iface_t            *iface = ucs_derived_of(params->iface, uct_mm_iface_t);
    uct_mm_md_t               *mm_md = ucs_derived_of(iface->super.super.md, uct_mm_md_t);
    const uct_mm_iface_addr_t *addr  = (const void *)params->iface_addr;
    uct_mm_packed_rkey_t rkey_buffer;
    void *fifo_ptr;

    UCT_EP_PARAMS_CHECK_DEV_IFACE_ADDRS(params);
    UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super.super);

    kh_init_inplace(uct_mm_remote_seg, &self->remote_segs);
    ucs_arbiter_group_init(&self->arb_group);

    if (mm_md->rkey_extra_size > 0) {
        self->rkey_extra_data = ucs_malloc(mm_md->rkey_extra_size, "mm_rkey_extra");
        if (self->rkey_extra_data == NULL) {
            return UCS_ERR_NO_MEMORY;
        }

        memcpy(self->rkey_extra_data, addr + 1, mm_md->rkey_extra_size);
    } else {
        self->rkey_extra_data = NULL;
    }

    /* Connect to the remote address (remote FIFO) */
    rkey_buffer.mmid      = addr->fifo_mmid;
    rkey_buffer.owner_ptr = addr->fifo_address;
    rkey_buffer.length    = UCT_MM_GET_FIFO_SIZE(iface);

    fifo_ptr = uct_mm_ep_get_remote_seg(self, &rkey_buffer);
    if (fifo_ptr == NULL) {
        ucs_error("failed to connect to remote peer with mm. remote mm_id: %zu",
                   addr->fifo_mmid);
        ucs_free(self->rkey_extra_data);
        return UCS_ERR_SHMEM_SEGMENT;
    }

    /* point the ep->fifo_ctl to the remote fifo.
      * it's an aligned pointer to the beginning of the ctl struct in the remote FIFO */
    uct_mm_iface_set_fifo_ptrs(fifo_ptr, &self->fifo_ctl, &self->fifo_elems);
    self->cached_tail     = self->fifo_ctl->tail;
    self->signal.addrlen  = self->fifo_ctl->signal_addrlen;
    self->signal.sockaddr = self->fifo_ctl->signal_sockaddr;

    /* Make sure the fifo ctrl is aligned */
    ucs_assert_always(((uintptr_t)self->fifo_ctl % UCS_SYS_CACHE_LINE_SIZE) == 0);

    ucs_debug("mm: ep connected: %p, to remote_shmid: %zu", self, addr->fifo_mmid);

    return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_mm_ep_t)
{
    uct_mm_iface_t  *iface     = ucs_derived_of(self->super.super.iface, uct_mm_iface_t);
    uct_component_t *component = iface->super.super.md->component;
    uct_mm_remote_seg_t remote_seg;

    uct_mm_ep_pending_purge(&self->super.super, NULL, NULL);

    kh_foreach_value(&self->remote_segs, remote_seg, {
        uct_rkey_release_internal(component, 0, remote_seg.cookie);
    })

    ucs_free(self->rkey_extra_data);
    kh_destroy_inplace(uct_mm_remote_seg, &self->remote_segs);
}

UCS_CLASS_DEFINE(uct_mm_ep_t, uct_base_ep_t)
UCS_CLASS_DEFINE_NEW_FUNC(uct_mm_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_mm_ep_t, uct_ep_t);


static inline ucs_status_t uct_mm_ep_get_remote_elem(uct_mm_ep_t *ep, uint64_t head,
                                                     uct_mm_fifo_element_t **elem)
{
    uct_mm_iface_t *iface = ucs_derived_of(ep->super.super.iface, uct_mm_iface_t);
    uint64_t elem_index;       /* the fifo elem's index in the fifo. */
                               /* must be smaller than fifo size */
    uint64_t returned_val;

    elem_index = ep->fifo_ctl->head & iface->fifo_mask;
    *elem      = UCT_MM_IFACE_GET_FIFO_ELEM(iface, ep->fifo_elems, elem_index);

    /* try to get ownership of the head element */
    returned_val = ucs_atomic_cswap64(ucs_unaligned_ptr(&ep->fifo_ctl->head), head, head+1);
    if (returned_val != head) {
        return UCS_ERR_NO_RESOURCE;
    }

    return UCS_OK;
}

static inline void uct_mm_ep_update_cached_tail(uct_mm_ep_t *ep)
{
    ucs_memory_cpu_load_fence();
    ep->cached_tail = ep->fifo_ctl->tail;
}

/* A common mm active message sending function.
 * The first parameter indicates the origin of the call.
 * is_short = 1 - perform AM short sending
 * is_short = 0 - perform AM bcopy sending
 */
static UCS_F_ALWAYS_INLINE ssize_t
uct_mm_ep_am_common_send(uct_mm_send_op_t send_op, uct_mm_ep_t *ep,
                         uct_mm_iface_t *iface, uint8_t am_id, size_t length,
                         uint64_t header, const void *payload,
                         uct_pack_callback_t pack_cb, void *arg,
                         unsigned flags)
{
    uct_mm_fifo_element_t *elem;
    ucs_status_t status;
    void *base_address;
    uint64_t head;

    UCT_CHECK_AM_ID(am_id);

retry:
    head = ep->fifo_ctl->head;
    /* check if there is room in the remote process's receive FIFO to write */
    if (!UCT_MM_EP_IS_ABLE_TO_SEND(head, ep->cached_tail, iface->config.fifo_size)) {
        if (!ucs_arbiter_group_is_empty(&ep->arb_group)) {
            /* pending isn't empty. don't send now to prevent out-of-order sending */
            UCS_STATS_UPDATE_COUNTER(ep->super.stats, UCT_EP_STAT_NO_RES, 1);
            return UCS_ERR_NO_RESOURCE;
        } else {
            /* pending is empty */
            /* update the local copy of the tail to its actual value on the remote peer */
            uct_mm_ep_update_cached_tail(ep);
            if (!UCT_MM_EP_IS_ABLE_TO_SEND(head, ep->cached_tail, iface->config.fifo_size)) {
                UCS_STATS_UPDATE_COUNTER(ep->super.stats, UCT_EP_STAT_NO_RES, 1);
                return UCS_ERR_NO_RESOURCE;
            }
        }
    }

    status = uct_mm_ep_get_remote_elem(ep, head, &elem);
    if (status != UCS_OK) {
        ucs_assert(status == UCS_ERR_NO_RESOURCE);
        ucs_trace_poll("couldn't get an available FIFO element. retrying");
        goto retry;
    }

    switch (send_op) {
    case UCT_MM_SEND_AM_SHORT:
        /* write to the remote FIFO */
        *(uint64_t*) (elem + 1) = header;
        memcpy((void*) (elem + 1) + sizeof(header), payload, length);

        elem->flags |= UCT_MM_FIFO_ELEM_FLAG_INLINE;
        elem->length = length + sizeof(header);

        uct_iface_trace_am(&iface->super.super, UCT_AM_TRACE_TYPE_SEND, am_id,
                           elem + 1, length + sizeof(header), "TX: AM_SHORT");
        UCT_TL_EP_STAT_OP(&ep->super, AM, SHORT, sizeof(header) + length);
        break;
    case UCT_MM_SEND_AM_BCOPY:
        /* write to the remote descriptor */
        /* get the base_address: local ptr to remote memory chunk after attaching to it */
        base_address = uct_mm_ep_get_remote_seg(ep, &elem->packed_rkey);
        length       = pack_cb(base_address + elem->desc_offset, arg);

        elem->flags &= ~UCT_MM_FIFO_ELEM_FLAG_INLINE;
        elem->length = length;

        uct_iface_trace_am(&iface->super.super, UCT_AM_TRACE_TYPE_SEND, am_id,
                           base_address + elem->desc_offset, length, "TX: AM_BCOPY");

        UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, length);
        break;
    default:
        return UCS_ERR_INVALID_PARAM;
    }

    elem->am_id = am_id;

    /* memory barrier - make sure that the memory is flushed before setting the
     * 'writing is complete' flag which the reader checks */
    ucs_memory_cpu_store_fence();

    /* change the owner bit to indicate that the writing is complete.
     * the owner bit flips after every FIFO wraparound */
    if (head & iface->config.fifo_size) {
        elem->flags |= UCT_MM_FIFO_ELEM_FLAG_OWNER;
    } else {
        elem->flags &= ~UCT_MM_FIFO_ELEM_FLAG_OWNER;
    }

    if (ucs_unlikely(flags & UCT_SEND_FLAG_SIGNALED)) {
        uct_mm_ep_signal_remote(ep);
    }

    switch (send_op) {
    case UCT_MM_SEND_AM_SHORT:
        return UCS_OK;
    case UCT_MM_SEND_AM_BCOPY:
        return length;
    default:
        return UCS_ERR_INVALID_PARAM;
    }
}

ucs_status_t uct_mm_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t header,
                                const void *payload, unsigned length)
{
    uct_mm_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_mm_iface_t);
    uct_mm_ep_t *ep = ucs_derived_of(tl_ep, uct_mm_ep_t);

    UCT_CHECK_LENGTH(length + sizeof(header), 0,
                     iface->config.fifo_elem_size - sizeof(uct_mm_fifo_element_t),
                     "am_short");

    return uct_mm_ep_am_common_send(UCT_MM_SEND_AM_SHORT, ep, iface, id, length,
                                    header, payload, NULL, NULL, 0);
}

ssize_t uct_mm_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id, uct_pack_callback_t pack_cb,
                           void *arg, unsigned flags)
{
    uct_mm_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_mm_iface_t);
    uct_mm_ep_t *ep = ucs_derived_of(tl_ep, uct_mm_ep_t);

    return uct_mm_ep_am_common_send(UCT_MM_SEND_AM_BCOPY, ep, iface, id, 0, 0,
                                    NULL, pack_cb, arg, flags);
}

static inline int uct_mm_ep_has_tx_resources(uct_mm_ep_t *ep)
{
    uct_mm_iface_t *iface = ucs_derived_of(ep->super.super.iface, uct_mm_iface_t);
    return UCT_MM_EP_IS_ABLE_TO_SEND(ep->fifo_ctl->head, ep->cached_tail,
                                     iface->config.fifo_size);
}

ucs_status_t uct_mm_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                   unsigned flags)
{
    uct_mm_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_mm_iface_t);
    uct_mm_ep_t *ep = ucs_derived_of(tl_ep, uct_mm_ep_t);

    /* check if resources became available */
    if (uct_mm_ep_has_tx_resources(ep)) {
        ucs_assert(ucs_arbiter_group_is_empty(&ep->arb_group));
        return UCS_ERR_BUSY;
    }

    UCS_STATIC_ASSERT(sizeof(uct_pending_req_priv_arb_t) <=
                      UCT_PENDING_REQ_PRIV_LEN);
    uct_pending_req_arb_group_push(&ep->arb_group, n);
    /* add the ep's group to the arbiter */
    ucs_arbiter_group_schedule(&iface->arbiter, &ep->arb_group);
    UCT_TL_EP_STAT_PEND(&ep->super);

    return UCS_OK;
}

ucs_arbiter_cb_result_t uct_mm_ep_process_pending(ucs_arbiter_t *arbiter,
                                                  ucs_arbiter_elem_t *elem,
                                                  void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    ucs_status_t status;
    uct_mm_ep_t *ep = ucs_container_of(ucs_arbiter_elem_group(elem), uct_mm_ep_t, arb_group);

    /* update the local tail with its actual value from the remote peer
     * making sure that the pending sends would use the real tail value */
    uct_mm_ep_update_cached_tail(ep);

    if (!uct_mm_ep_has_tx_resources(ep)) {
        return UCS_ARBITER_CB_RESULT_RESCHED_GROUP;
    }

    ucs_trace_data("progressing pending request %p", req);
    status = req->func(req);
    ucs_trace_data("status returned from progress pending: %s",
                   ucs_status_string(status));

    if (status == UCS_OK) {
        /* sent successfully. remove from the arbiter */
        return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
    } else if (status == UCS_INPROGRESS) {
        /* sent but not completed, keep in the arbiter */
        return UCS_ARBITER_CB_RESULT_NEXT_GROUP;
    } else {
        /* couldn't send. keep this request in the arbiter until the next time
         * this function is called */
        return UCS_ARBITER_CB_RESULT_RESCHED_GROUP;
    }
}

static ucs_arbiter_cb_result_t uct_mm_ep_abriter_purge_cb(ucs_arbiter_t *arbiter,
                                                          ucs_arbiter_elem_t *elem,
                                                          void *arg)
{
    uct_pending_req_t *req = ucs_container_of(elem, uct_pending_req_t, priv);
    uct_purge_cb_args_t *cb_args    = arg;
    uct_pending_purge_callback_t cb = cb_args->cb;
    uct_mm_ep_t *ep = ucs_container_of(ucs_arbiter_elem_group(elem),
                                       uct_mm_ep_t, arb_group);
    if (cb != NULL) {
        cb(req, cb_args->arg);
    } else {
        ucs_warn("ep=%p canceling user pending request %p", ep, req);
    }
    return UCS_ARBITER_CB_RESULT_REMOVE_ELEM;
}

void uct_mm_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                             void *arg)
{
    uct_mm_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_mm_iface_t);
    uct_mm_ep_t *ep = ucs_derived_of(tl_ep, uct_mm_ep_t);
    uct_purge_cb_args_t  args = {cb, arg};

    ucs_arbiter_group_purge(&iface->arbiter, &ep->arb_group,
                            uct_mm_ep_abriter_purge_cb, &args);
}

ucs_status_t uct_mm_ep_flush(uct_ep_h tl_ep, unsigned flags,
                             uct_completion_t *comp)
{
    uct_mm_ep_t *ep = ucs_derived_of(tl_ep, uct_mm_ep_t);

    if (!uct_mm_ep_has_tx_resources(ep)) {
        if (!ucs_arbiter_group_is_empty(&ep->arb_group)) {
            return UCS_ERR_NO_RESOURCE;
        } else {
            uct_mm_ep_update_cached_tail(ep);
            if (!uct_mm_ep_has_tx_resources(ep)) {
                return UCS_ERR_NO_RESOURCE;
            }
        }
    }

    ucs_memory_cpu_store_fence();
    UCT_TL_EP_STAT_FLUSH(&ep->super);
    return UCS_OK;
}
