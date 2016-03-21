/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */


#ifndef UCP_WIREUP_H_
#define UCP_WIREUP_H_

#include "address.h"

#include <ucp/api/ucp.h>
#include <ucp/core/ucp_context.h>
#include <uct/api/uct.h>


/**
 * Wireup message types
 */
enum {
    UCP_WIREUP_MSG_REQUEST,
    UCP_WIREUP_MSG_REPLY,
    UCP_WIREUP_MSG_ACK,
    UCP_WIREUP_MSG_LAST
};


/**
 * Calculates a score of specific wireup.
 */
typedef double (*ucp_wireup_score_function_t)(ucp_worker_h worker,
                                              uct_iface_attr_t *iface_attr,
                                              char *reason, size_t max);


/**
 * Packet structure for wireup requests.
 */
typedef struct ucp_wireup_msg {
    uint8_t               type;        /* Message type */
    uint8_t               dst_pd_index;/* PD to select at destination */
    uint8_t               tl_index;    /* Index of runtime address */
    uint8_t               aux_index;   /* Index of auxiliary address */
    /* packed addresses follow */
} UCS_S_PACKED ucp_wireup_msg_t;


typedef struct ucp_wireup_ep_op {
    const char                  *title;
    uint64_t                    features;
    ucp_wireup_score_function_t score_func;
} ucp_wireup_ep_op_t;


extern ucp_wireup_ep_op_t ucp_wireup_ep_ops[];


ucs_status_t ucp_wireup_start(ucp_ep_h ep, ucp_address_entry_t *address_list,
                              unsigned address_count);

ucs_status_t ucp_wireup_connect_remote(ucp_ep_h ep);

ucs_status_t ucp_wireup_create_stub_ep(ucp_ep_h ep);

void ucp_wireup_stop(ucp_ep_h ep);

void ucp_wireup_progress(ucp_ep_h ep);

ucs_status_t ucp_wireup_msg_send(ucp_ep_h ep, uint8_t type,
                                 ucp_rsc_index_t aux_rsc_index);

ucs_status_t ucp_select_transport(ucp_worker_h worker, const char *peer_name,
                                  const ucp_address_entry_t *address_list,
                                  unsigned address_count, ucp_rsc_index_t pd_index,
                                  ucp_rsc_index_t *rsc_index_p,
                                  unsigned *dst_addr_index_p,
                                  ucp_wireup_score_function_t score_func,
                                  const char *title);

#endif
