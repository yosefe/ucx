/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */


#ifndef UCP_EP_INL_
#define UCP_EP_INL_

#include "ucp_ep.h"
#include "ucp_worker.h"

#include <ucs/arch/bitops.h>


static inline ucp_ep_config_t *ucp_ep_config(ucp_ep_h ep)
{
    return &ep->worker->ep_config[ep->cfg_index];
}

static inline ucp_lane_index_t ucp_ep_get_am_lane(ucp_ep_h ep)
{
    ucs_assert(ucp_ep_config(ep)->key.am_lane != UCP_NULL_RESOURCE);
    return ep->am_lane;
}

static inline ucp_lane_index_t ucp_ep_get_wireup_msg_lane(ucp_ep_h ep)
{
    return ucp_ep_config(ep)->key.wireup_msg_lane;
}

static inline ucp_lane_index_t ucp_ep_get_rndv_data_lane(ucp_ep_h ep)
{
    ucs_assert(ucp_ep_config(ep)->key.rndv_lane != UCP_NULL_RESOURCE);
    return ucp_ep_config(ep)->key.rndv_lane;
}

static inline uct_ep_h ucp_ep_get_am_uct_ep(ucp_ep_h ep)
{
    return ep->uct_eps[ucp_ep_get_am_lane(ep)];
}

static inline uct_ep_h ucp_ep_get_rndv_data_uct_ep(ucp_ep_h ep)
{
    return ep->uct_eps[ucp_ep_get_rndv_data_lane(ep)];
}

static inline ucp_rsc_index_t ucp_ep_get_rsc_index(ucp_ep_h ep, ucp_lane_index_t lane)
{
    return ucp_ep_config(ep)->key.lanes[lane];
}

static inline ucp_rsc_index_t ucp_ep_num_lanes(ucp_ep_h ep)
{
    return ucp_ep_config(ep)->key.num_lanes;
}

static inline ucp_rsc_index_t ucp_ep_pd_index(ucp_ep_h ep, ucp_lane_index_t lane)
{
    ucp_context_h context = ep->worker->context;
    ucp_rsc_index_t rsc_index = ucp_ep_get_rsc_index(ep, lane); 
    ucs_assert(rsc_index != UCP_NULL_RESOURCE);
    return context->tl_rscs[ucp_ep_get_rsc_index(ep, lane)].pd_index;
}

static inline uct_pd_h ucp_ep_pd(ucp_ep_h ep, ucp_lane_index_t lane)
{
    ucp_context_h context = ep->worker->context;
    return context->pds[ucp_ep_pd_index(ep, lane)];
}

static inline const uct_pd_attr_t* ucp_ep_pd_attr(ucp_ep_h ep, ucp_lane_index_t lane)
{
    ucp_context_h context = ep->worker->context;
    return &context->pd_attrs[ucp_ep_pd_index(ep, lane)];
}

static inline const char* ucp_ep_peer_name(ucp_ep_h ep)
{
#if ENABLE_DEBUG_DATA
    return ep->peer_name;
#else
    return "??";
#endif
}

/*
 * Calculate the rkey index inside the compact array. This is actually the
 * number of PDs in the map with index less-than ours. So mask pd_map to get
 * only the less-than indices, and then count them using popcount operation.
 * TODO save the mask in ep->uct, to avoid the shift operation.
 */

#define UCP_EP_RESOLVE_RKEY(_ep, _rkey, _name, _uct_ep, _uct_rkey) \
    { \
        uint16_t dest_pds    = (_ep)->dest_##_name##_pds; \
        uint16_t rkey_pd_map = (_rkey)->pd_map; \
        ucp_rsc_index_t dst_pd_index, rkey_index, op_index; \
        ucp_lane_index_t lane; \
        uint16_t mask; \
        \
        if (ENABLE_PARAMS_CHECK && !((_rkey)->pd_map & dest_pds)) { \
            ucs_fatal("Remote key does not support current transport(s) " \
                       "(remote pds: 0x%x rkey map: 0x%x)", \
                       dest_pds, rkey_pd_map); \
            return UCS_ERR_UNREACHABLE; \
        } \
        \
        dst_pd_index = ucs_ffs64(rkey_pd_map & dest_pds); \
        mask         = UCS_MASK(dst_pd_index); \
        rkey_index   = ucs_count_one_bits(rkey_pd_map & mask); \
        op_index     = ucs_count_one_bits(dest_pds    & mask); \
        lane         = ucp_ep_config(ep)->_name##_lanes[op_index]; \
        \
        _uct_rkey    = (_rkey)->uct[rkey_index].rkey; \
        _uct_ep      = (_ep)->uct_eps[lane]; \
    }

#endif
