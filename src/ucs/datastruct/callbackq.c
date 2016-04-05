/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2013.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <ucs/arch/atomic.h>
#include <ucs/debug/log.h>
#include <ucs/debug/debug.h>
#include <ucs/sys/sys.h>

#include "callbackq.h"


/*
 * Service callback is a special callback in the callback queue, which is always
 * in the first entry in the array. It is responsible for adding / removing items
 * to the callback queue on behalf of other threads, since it is guaranteed to
 * run from the "main" thread.
 */
static void ucs_callbackq_service_cb(void *arg)
{
    ucs_callbackq_t *cbq = arg;
    ucs_callbackq_cmd_t *cmd;

    ucs_spin_lock(&cbq->lock);

    ucs_debug("cbq %p: service callback", cbq);

    ucs_queue_for_each_extract(cmd, &cbq->cmdq, queue, 1) {
        switch (cmd->op) {
        case UCS_CALLBACKQ_CMD_ADD:
            ucs_callbackq_add_sync(cbq, cmd->cb, cmd->arg);
            break;
        case UCS_CALLBACKQ_CMD_REMOVE:
            ucs_callbackq_remove_sync(cbq, cmd->cb, cmd->arg);
            break;
        }
        ucs_free(cmd);
    }

    ++cbq->start;

    ucs_spin_unlock(&cbq->lock);
}

ucs_status_t ucs_callbackq_init(ucs_callbackq_t *cbq, size_t size)
{
    /* reserve a slot for the special service callback */
    ++size;

    cbq->ptr  = ucs_malloc(size * sizeof(*cbq->ptr), "callback queue");
    if (cbq->ptr == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    cbq->ptr->cb  = ucs_callbackq_service_cb;
    cbq->ptr->arg = cbq;
    cbq->size     = size;
    cbq->start    = cbq->ptr + 1;
    cbq->end      = cbq->start;
    ucs_spinlock_init(&cbq->lock);
    ucs_queue_head_init(&cbq->cmdq);
    return UCS_OK;
}

void ucs_callbackq_cleanup(ucs_callbackq_t *cbq)
{
    if (cbq->start != cbq->end) {
        ucs_warn("%zd callbacks still remain in callback queue",
                 cbq->end - cbq->start);
    }
    if (!ucs_queue_is_empty(&cbq->cmdq)) {
        ucs_callbackq_service_cb(cbq);
    }
    ucs_free(cbq->ptr);
}

static ucs_callbackq_elem_t* ucs_callbackq_find(ucs_callbackq_t *cbq,
                                                ucs_callback_t cb, void *arg)
{
    ucs_callbackq_elem_t *elem;
    ucs_callbackq_chain_for_each(elem, cbq) {
        if ((elem->cb == cb) && (elem->arg == arg)) {
            return elem;
        }
    }
    return NULL;
}

ucs_status_t ucs_callbackq_add_sync(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg)
{
    ucs_callbackq_elem_t *elem;
    char func_name[200];

    elem = ucs_callbackq_find(cbq, cb, arg);
    if (elem != NULL) {
        ucs_atomic_add32(&elem->refcount, 1);
        return UCS_OK;
    }

    ucs_assert(cbq->end < cbq->ptr + cbq->size);
    elem = cbq->end;

    ucs_trace("cbq %p: adding %p %s(arg=%p) [start:%p end:%p]", cbq, elem,
              ucs_debug_get_symbol_name(cb, func_name, sizeof(func_name)),
              arg, cbq->start, cbq->end);

    elem->cb       = cb;
    elem->arg      = arg;
    elem->refcount = 1;
    ++cbq->end;
    return UCS_OK;
}

ucs_status_t ucs_callbackq_remove_sync(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg)
{
    ucs_callbackq_elem_t *elem;
    char func_name[200];

    elem = ucs_callbackq_find(cbq, cb, arg);
    if (elem == NULL) {
        ucs_debug("callback not found in progress chain");
        return UCS_ERR_NO_ELEM;
    }

    if (ucs_atomic_fadd32(&elem->refcount, -1) != 1) {
        return UCS_OK;
    }

    ucs_trace("cbq %p: remove %p %s(arg=%p) [start:%p end:%p]", cbq, elem,
              ucs_debug_get_symbol_name(cb, func_name, sizeof(func_name)),
              arg, cbq->start, cbq->end);

    if (cbq->start >= cbq->end) {
        /* TODO support expanding the callback queue */
        ucs_fatal("callback queue %p is full, cannot add %s()", cbq,
                  ucs_debug_get_symbol_name(cb, func_name, sizeof(func_name)));
    }

    if (elem != cbq->end - 1) {
        *elem = *(cbq->end - 1);
    }
    --cbq->end;
    return UCS_OK;
}

static ucs_status_t
ucs_callbackq_do_async(ucs_callbackq_t *cbq, ucs_callbackq_cmd_op_t op,
                       ucs_callback_t cb, void *arg)
{
    ucs_callbackq_cmd_t *cmd;

    cmd = ucs_malloc(sizeof (*cmd), "callbackq cmd");
    if (cmd == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    cmd->op  = op;
    cmd->cb  = cb;
    cmd->arg = arg;

    ucs_spin_lock(&cbq->lock);
    ucs_queue_push(&cbq->cmdq, &cmd->queue);
    ucs_memory_cpu_store_fence(); /* Make sure main thread will see the new
                                     'start' only after it's ready */
    cbq->start = cbq->ptr;        /* Let the service callback run */
    ucs_spin_unlock(&cbq->lock);

    return UCS_OK;
}

ucs_status_t ucs_callbackq_add_async(ucs_callbackq_t *cbq, ucs_callback_t cb,
                                     void *arg)
{
    return ucs_callbackq_do_async(cbq, UCS_CALLBACKQ_CMD_ADD, cb, arg);
}

ucs_status_t ucs_callbackq_remove_async(ucs_callbackq_t *cbq, ucs_callback_t cb,
                                        void *arg)
{
    return ucs_callbackq_do_async(cbq, UCS_CALLBACKQ_CMD_REMOVE, cb, arg);
}

void ucs_callbackq_log_dispatch(ucs_callbackq_t *cbq, ucs_callbackq_elem_t *elem)
{
    char func_name[200];

    ucs_log(UCS_LOG_LEVEL_TRACE_FUNC, "cbq %p: call   %p %s(arg=%p) [start:%p end:%p]",
            cbq, elem, ucs_debug_get_symbol_name(elem->cb, func_name, sizeof(func_name)),
            elem->arg, cbq->start, cbq->end);
}
