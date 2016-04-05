/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCS_CALLBACKQ_H
#define UCS_CALLBACKQ_H

#include <ucs/arch/cpu.h>
#include <ucs/datastruct/queue.h>
#include <ucs/debug/log.h>
#include <ucs/type/spinlock.h>
#include <stdint.h>

/*
 *
 * Thread-safe callback queue:
 *  - only one thread can dispatch
 *  - any thread can add and remove
 *  - callbacks are reference-counted
 */


/*
 * Forward declarations
 */
typedef struct ucs_callbackq         ucs_callbackq_t;
typedef struct ucs_callbackq_cmd     ucs_callbackq_cmd_t;
typedef struct ucs_callbackq_elem    ucs_callbackq_elem_t;
typedef void                         (*ucs_callback_t)(void *arg);


/**
 * Internal - callback queue operation types.
 */
typedef enum {
    UCS_CALLBACKQ_CMD_ADD,
    UCS_CALLBACKQ_CMD_REMOVE
} ucs_callbackq_cmd_op_t;


/**
 * Internal - callback queue operation.
 */
struct ucs_callbackq_cmd {
    ucs_queue_elem_t                 queue;
    ucs_callbackq_cmd_op_t           op;
    ucs_callback_t                   cb;
    void                             *arg;
};


/**
 * Callback queue element.
 */
struct ucs_callbackq_elem {
    ucs_callback_t                   cb;       /**< Callback function */
    void                             *arg;     /**< Function argument */
    volatile uint32_t                refcount; /**< Reference count */
};


/**
 * A queue of callback to execute
 */
struct ucs_callbackq {
    ucs_callbackq_elem_t             *start;   /**< Iteration start pointer */
    ucs_callbackq_elem_t             *end;     /**< Iteration end pointer */

    ucs_spinlock_t                   lock;
    ucs_callbackq_elem_t             *ptr;
    size_t                           size;
    ucs_queue_head_t                 cmdq;
};


/**
 * Iterate over all elements in the notifier chain.
 * This should be done only from one thread at a time.
 */
#define ucs_callbackq_chain_for_each(_elem, _cbq) \
    for (_elem = (_cbq)->start, \
             ({ ucs_memory_cpu_load_fence(); 1; }); \
         _elem < (_cbq)->end; \
         ++_elem)


/**
 * Initialize the callback queue.
 *
 * @param  [in] cbq      Callback queue to initialize.
 * @param  [in] size     Callback queue size.
 *
 * @note The callback queue currently does not expand beyond the size defined
 *       during initialization time. More callbacks *cannot* be added.
 */
ucs_status_t ucs_callbackq_init(ucs_callbackq_t *cbq, size_t size);


/**
 * Clean up the callback queue and release associated memory.
 *
 * @param  [in] cbq      Callback queue to clean up.
 */
void ucs_callbackq_cleanup(ucs_callbackq_t *cbq);


/**
 * Add a callback to the queue.
 * This is *not* safe to call while another thread might be dispatching callbacks.
 * However, it can be used from the dispatch context (e.g a callback may use this
 * function to add reference to itself or add another callback).
 *
 * If the pair (cb, arg) already exists, it is not added, but its reference count
 * is incremented.
 *
 * @param  [in] cbq      Callback queue to add the callback to.
 * @param  [in] cb       Callback to add.
 * @param  [in] arg      User-defined argument for the callback.
 */
ucs_status_t ucs_callbackq_add_sync(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg);


/**
 * Remove a callback from the queue immediately.
 * This is *not* safe to call while another thread might be dispatching callbacks.
 * However, it can be used from the dispatch context (e.g a callback may use this
 * function to remove itself or another callback).
 *
 * If the pair (cb, arg) has a reference count > 1, the reference count is
 * decremented by 1, and the callback is not removed.
 *
 * @param  [in] cbq      Callback queue to remove the callback from.
 * @param  [in] cb       Callback to remove.
 * @param  [in] arg      User-defined argument for the callback.
 *
 * @return UCS_ERR_NO_ELEM if element does not exist.
 */
ucs_status_t ucs_callbackq_remove_sync(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg);


/**
 * Add a callback to the queue.
 * This can be used from any context and any thread, including but not limited to:
 * - A callback can add another callback.
 * - A thread can add a callback while another thread is dispatching callbacks.
 *
 * If the pair (cb, arg) already exists, it is not added, but its reference count
 * is incremented.
 *
 * @param  [in] cbq      Callback queue to add the callback to.
 * @param  [in] cb       Callback to add.
 * @param  [in] arg      User-defined argument for the callback.
 */
ucs_status_t ucs_callbackq_add_async(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg);


/**
 * Remove a callback from the queue in a lazy fashion. The callback will be
 * removed at some point in the near future.
 * This can be used from any context and any thread, including but not limited to:
 * - A callback can remove another callback or itself.
 * - A thread remove add a callback while another thread is dispatching callbacks.
 *
 * If the pair (cb, arg) has a reference count > 1, the reference count is
 * decremented by 1, and the callback is not removed.
 *
 * @param  [in] cbq      Callback queue to remove the callback from.
 * @param  [in] cb       Callback to remove.
 * @param  [in] arg      User-defined argument for the callback.
 */
ucs_status_t ucs_callbackq_remove_async(ucs_callbackq_t *cbq, ucs_callback_t cb, void *arg);


/**
 * Internal function - log an element being dispatched.
 */
void ucs_callbackq_log_dispatch(ucs_callbackq_t *cbq, ucs_callbackq_elem_t *elem);


/**
 * Call all callbacks on the queue.
 * This should be done only from one thread at a time.
 *
 * @param  [in] cbq      Callback queue whose elements to dispatch.
 */
static inline void ucs_callbackq_dispatch(ucs_callbackq_t *cbq)
{
    ucs_callbackq_elem_t *elem;

    ucs_callbackq_chain_for_each(elem, cbq) {
        if (ucs_log_enabled(UCS_LOG_LEVEL_TRACE_FUNC)) {
            ucs_callbackq_log_dispatch(cbq, elem);
        }
        elem->cb(elem->arg);
    }
}

#endif
