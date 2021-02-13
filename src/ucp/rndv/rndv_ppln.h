/**
 * Copyright (C) Mellanox Technologies Ltd. 2021.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifndef UCP_RNDV_PPLN_H_
#define UCP_RNDV_PPLN_H_

#include "proto_rndv.inl"


typedef ucs_status_t (*ucp_proto_rndv_ppln_frag_init_cb_t)(ucp_request_t *req);


typedef ucs_status_t (*ucp_proto_rndv_ppln_frag_send_cb_t)(
        ucp_request_t *req, const ucp_proto_multi_lane_priv_t *lpriv,
        const uct_iov_t *iov, uct_completion_t *comp);


ucs_status_t ucp_proto_rndv_ppln_get_frag_md_map(ucp_worker_h worker,
                                                 ucp_md_map_t *md_map_p);


ucs_status_t
ucp_proto_rndv_ppln_send_progress(ucp_request_t *req,
                                  const ucp_proto_multi_priv_t *mpriv,
                                  size_t total_length,
                                  uct_completion_callback_t req_comp_func,
                                  ucp_proto_rndv_ppln_frag_init_cb_t frag_init,
                                  ucp_proto_rndv_ppln_frag_send_cb_t frag_send,
                                  ucp_proto_complete_cb_t sent_func);


void ucp_proto_rndv_ppln_frag_recv_completion(uct_completion_t *uct_comp);


int ucp_proto_rndv_ppln_is_supported(const ucp_proto_init_params_t *init_params);

#endif