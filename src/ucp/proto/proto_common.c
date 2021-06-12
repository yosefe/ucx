/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "proto_common.inl"


static ucp_rsc_index_t
ucp_proto_common_get_rsc_index(const ucp_proto_init_params_t *params,
                               ucp_lane_index_t lane)
{
    ucp_rsc_index_t rsc_index;

    ucs_assert(lane < UCP_MAX_LANES);

    rsc_index = params->ep_config_key->lanes[lane].rsc_index;
    ucs_assert(rsc_index < UCP_MAX_RESOURCES);

    return rsc_index;
}

void ucp_proto_common_lane_priv_init(const ucp_proto_common_init_params_t *params,
                                     ucp_md_map_t md_map, ucp_lane_index_t lane,
                                     ucp_proto_common_lane_priv_t *lane_priv)
{
    const ucp_rkey_config_key_t *rkey_config_key = params->super.rkey_config_key;
    ucp_md_index_t md_index, dst_md_index;

    md_index     = ucp_proto_common_get_md_index(&params->super, lane);
    dst_md_index = params->super.ep_config_key->lanes[lane].dst_md_index;

    lane_priv->lane = lane;

    /* Local key index */
    if (md_map & UCS_BIT(md_index)) {
        lane_priv->memh_index = ucs_bitmap2idx(md_map, md_index);
    } else {
        lane_priv->memh_index = UCP_NULL_RESOURCE;
    }

    /* Remote key index */
    if ((rkey_config_key != NULL) &&
        (rkey_config_key->md_map & UCS_BIT(dst_md_index))) {
        lane_priv->rkey_index = ucs_bitmap2idx(rkey_config_key->md_map,
                                               dst_md_index);
    } else {
        lane_priv->rkey_index = UCP_NULL_RESOURCE;
    }
}

void ucp_proto_common_lane_priv_str(const ucp_proto_common_lane_priv_t *lpriv,
                                    ucs_string_buffer_t *strb)
{
    ucs_string_buffer_appendf(strb, "ln:%d", lpriv->lane);
    if (lpriv->memh_index != UCP_NULL_RESOURCE) {
        ucs_string_buffer_appendf(strb, ",mh%d", lpriv->memh_index);
    }
    if (lpriv->rkey_index != UCP_NULL_RESOURCE) {
        ucs_string_buffer_appendf(strb, ",rk%d", lpriv->rkey_index);
    }
}

ucp_md_index_t
ucp_proto_common_get_md_index(const ucp_proto_init_params_t *params,
                              ucp_lane_index_t lane)
{
    ucp_rsc_index_t rsc_index = ucp_proto_common_get_rsc_index(params, lane);
    return params->worker->context->tl_rscs[rsc_index].md_index;
}

ucs_sys_device_t
ucp_proto_common_get_sys_dev(const ucp_proto_init_params_t *params,
                             ucp_lane_index_t lane)
{
    ucp_rsc_index_t rsc_index = ucp_proto_common_get_rsc_index(params, lane);
    return params->worker->context->tl_rscs[rsc_index].tl_rsc.sys_device;
}

void ucp_proto_common_get_lane_distance(const ucp_proto_init_params_t *params,
                                        ucp_lane_index_t lane,
                                        ucs_sys_device_t sys_dev,
                                        ucs_sys_dev_distance_t *distance)
{
    ucp_context_h context       = params->worker->context;
    ucp_rsc_index_t rsc_index   = ucp_proto_common_get_rsc_index(params, lane);
    ucs_sys_device_t tl_sys_dev = context->tl_rscs[rsc_index].tl_rsc.sys_device;
    ucs_status_t status;

    status = ucs_topo_get_distance(sys_dev, tl_sys_dev, distance);
    ucs_assertv_always(status == UCS_OK, "sys_dev=%d tl_sys_dev=%d", sys_dev,
                       tl_sys_dev);
}

const uct_iface_attr_t *
ucp_proto_common_get_iface_attr(const ucp_proto_init_params_t *params,
                                ucp_lane_index_t lane)
{
    return ucp_worker_iface_get_attr(params->worker,
                                     ucp_proto_common_get_rsc_index(params, lane));
}

size_t ucp_proto_common_get_iface_attr_field(const uct_iface_attr_t *iface_attr,
                                             ptrdiff_t field_offset,
                                             size_t dfl_value)
{
    if (field_offset == UCP_PROTO_COMMON_OFFSET_INVALID) {
        return dfl_value;
    }

    return *(const size_t*)UCS_PTR_BYTE_OFFSET(iface_attr, field_offset);
}

size_t
ucp_proto_common_get_max_frag(const ucp_proto_common_init_params_t *params,
                              const uct_iface_attr_t *iface_attr)
{
    return ucp_proto_common_get_iface_attr_field(iface_attr,
                                                 params->max_frag_offs,
                                                 SIZE_MAX);
}

static void ucp_proto_common_update_lane_perf_by_distance(
        ucp_proto_common_tl_perf_t *perf,
        const ucs_sys_dev_distance_t *distance)
{
    perf->bandwidth    = ucs_min(perf->bandwidth, distance->bandwidth);
    perf->sys_latency += distance->latency;
}

void ucp_proto_common_get_lane_perf(const ucp_proto_common_init_params_t *params,
                                    ucp_lane_index_t lane,
                                    ucp_proto_common_tl_perf_t *perf)
{
    const uct_iface_attr_t *iface_attr =
            ucp_proto_common_get_iface_attr(&params->super, lane);
    ucp_worker_h worker   = params->super.worker;
    ucp_context_h context = worker->context;
    const ucp_rkey_config_t *rkey_config;
    ucs_sys_dev_distance_t distance;
    uct_tl_resource_desc_t *rsc;
    ucp_rsc_index_t rsc_index;
    char buf[128];

    perf->overhead   = iface_attr->overhead + params->overhead;
    perf->bandwidth  = ucp_tl_iface_bandwidth(context, &iface_attr->bandwidth);
    perf->latency    = ucp_tl_iface_latency(context, &iface_attr->latency) +
                       params->latency;
    perf->sys_latency = 0;
    perf->min_frag    = ucp_proto_common_get_iface_attr_field(
            iface_attr, params->min_frag_offs, 0);
    perf->max_frag   = ucp_proto_common_get_iface_attr_field(
            iface_attr, params->max_frag_offs, SIZE_MAX);
    rsc_index        = ucp_proto_common_get_rsc_index(&params->super, lane);
    rsc              = &context->tl_rscs[rsc_index].tl_rsc;

    ucs_trace("get_lane_perf [%d] " UCT_TL_RESOURCE_DESC_FMT, lane,
              UCT_TL_RESOURCE_DESC_ARG(rsc));

    ucs_log_indent(1);

    /* For zero copy send, consider local system topology distance */
    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY) {
        ucp_proto_common_get_lane_distance(&params->super, lane,
                                           params->super.select_param->sys_dev,
                                           &distance);
        ucp_proto_common_update_lane_perf_by_distance(perf, &distance);
        ucs_trace("local sys %s",
                  ucs_topo_distance_str(&distance, buf, sizeof(buf)));
    }

    /* For remote memory access, consider remote system topology distance */
    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS) {
        ucs_assert(params->super.rkey_cfg_index != UCP_WORKER_CFG_INDEX_NULL);
        rkey_config = &worker->rkey_config[params->super.rkey_cfg_index];
        distance    = rkey_config->lanes_distance[lane];
        ucp_proto_common_update_lane_perf_by_distance(perf, &distance);
        ucs_trace("remote sys %s dev %d",
                  ucs_topo_distance_str(&distance, buf, sizeof(buf)),
                  rkey_config->key.sys_dev);
    }

    ucs_trace("ovh %.1f ns, lat %.1f ns, syslat %.1f ns, bw %.3f MBs min %zu",
              perf->overhead * 1e9, perf->latency * 1e9,
              perf->sys_latency * 1e9, perf->bandwidth / UCS_MBYTE,
              perf->max_frag);
    ucs_log_indent(-1);
}

static ucp_lane_index_t
ucp_proto_common_find_lanes_internal(const ucp_proto_init_params_t *params,
                                     unsigned flags, ucp_lane_type_t lane_type,
                                     uint64_t tl_cap_flags,
                                     ucp_lane_index_t max_lanes,
                                     ucp_lane_map_t exclude_map,
                                     ucp_lane_index_t *lanes)
{
    UCS_STRING_BUFFER_ONSTACK(sel_param_strb, UCP_PROTO_SELECT_PARAM_STR_MAX);
    ucp_context_h context                        = params->worker->context;
    const ucp_ep_config_key_t *ep_config_key     = params->ep_config_key;
    const ucp_rkey_config_key_t *rkey_config_key = params->rkey_config_key;
    const ucp_proto_select_param_t *select_param = params->select_param;
    const uct_iface_attr_t *iface_attr;
    ucp_lane_index_t lane, num_lanes;
    const uct_md_attr_t *md_attr;
    ucp_rsc_index_t rsc_index;
    ucp_md_index_t md_index;
    ucp_lane_map_t lane_map;
    char lane_desc[64];

    num_lanes = 0;

    ucp_proto_select_param_str(select_param, &sel_param_strb);
    if (rkey_config_key != NULL) {
        ucs_string_buffer_appendf(&sel_param_strb, "->");
        ucp_rkey_config_dump_brief(rkey_config_key, &sel_param_strb);
    }
    ucs_trace("selecting up to %d/%d lanes for %s %s", max_lanes,
              ep_config_key->num_lanes, params->proto_name,
              ucs_string_buffer_cstr(&sel_param_strb));
    ucs_log_indent(1);

    if (flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY) {
        if ((select_param->dt_class == UCP_DATATYPE_GENERIC) ||
            (select_param->dt_class == UCP_DATATYPE_IOV)) {
            /* Generic/IOV datatype cannot be used with zero-copy send */
            /* TODO support IOV registration */
            ucs_trace("datatype %s cannot be used with zcopy",
                      ucp_datatype_class_names[select_param->dt_class]);
            goto out;
        }
    } else if (!(flags & UCP_PROTO_COMMON_INIT_FLAG_MEM_TYPE) &&
               (select_param->dt_class != UCP_DATATYPE_GENERIC) &&
               !UCP_MEM_IS_ACCESSIBLE_FROM_CPU(select_param->mem_type)) {
        /* If zero-copy is off, the memory must be host-accessible for
         * non-generic type (for generic type there is no buffer to access) */
        ucs_trace("memory type %s with datatype %s is not supported",
                  ucs_memory_type_names[select_param->mem_type],
                  ucp_datatype_class_names[select_param->dt_class]);
        goto out;
    }

    lane_map      = UCS_MASK(ep_config_key->num_lanes) & ~exclude_map;
    ucs_for_each_bit(lane, lane_map) {
        if (num_lanes >= max_lanes) {
            break;
        }

        ucs_assert(lane < UCP_MAX_LANES);
        rsc_index = ep_config_key->lanes[lane].rsc_index;
        if (rsc_index == UCP_NULL_RESOURCE) {
            continue;
        }

        snprintf(lane_desc, sizeof(lane_desc),
                 "lane[%d] " UCT_TL_RESOURCE_DESC_FMT, lane,
                 UCT_TL_RESOURCE_DESC_ARG(&context->tl_rscs[rsc_index].tl_rsc));

        /* Check if lane type matches */
        ucs_assert(lane < UCP_MAX_LANES);
        if (!(ep_config_key->lanes[lane].lane_types & UCS_BIT(lane_type))) {
            ucs_trace("%s: no %s in lane types", lane_desc,
                      ucp_lane_type_info[lane_type].short_name);
            continue;
        }

        /* Check iface capabilities */
        iface_attr = ucp_proto_common_get_iface_attr(params, lane);
        if (!ucs_test_all_flags(iface_attr->cap.flags, tl_cap_flags)) {
            ucs_trace("%s: no cap 0x%" PRIx64, lane_desc, tl_cap_flags);
            continue;
        }

        md_index = context->tl_rscs[rsc_index].md_index;
        md_attr  = &context->tl_mds[md_index].attr;

        /* Check memory registration capabilities for zero-copy case */
        if (flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY) {
            if (md_attr->cap.flags & UCT_MD_FLAG_NEED_MEMH) {
                /* Memory domain must support registration on the relevant
                 * memory type */
                if (!(md_attr->cap.flags & UCT_MD_FLAG_REG) ||
                    !(md_attr->cap.reg_mem_types & UCS_BIT(select_param->mem_type))) {
                    ucs_trace("%s: no reg of mem type %s", lane_desc,
                              ucs_memory_type_names[select_param->mem_type]);
                    continue;
                }
            } else if (!(md_attr->cap.access_mem_types &
                         UCS_BIT(select_param->mem_type))) {
                /*
                 * Memory domain which does not require a registration for zero
                 * copy operation must be able to access the relevant memory type
                 */
                ucs_trace("%s: no access to mem type %s", lane_desc,
                          ucs_memory_type_names[select_param->mem_type]);
                continue;
            }
        }

        /* Check remote access capabilities */
        if (flags & UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS) {
            if (rkey_config_key == NULL) {
                ucs_trace("protocol requires remote access but remote key is "
                          "not present");
                goto out;
            }

            if (md_attr->cap.flags & UCT_MD_FLAG_NEED_RKEY) {
                if (!(rkey_config_key->md_map &
                    UCS_BIT(ep_config_key->lanes[lane].dst_md_index))) {
                    ucs_trace("%s: no support of dst md map 0x%" PRIx64,
                              lane_desc, rkey_config_key->md_map);
                    continue;
                }
            } else if (!(md_attr->cap.access_mem_types &
                         UCS_BIT(rkey_config_key->mem_type))) {
                ucs_trace("%s: no access to remote mem type %s", lane_desc,
                          ucs_memory_type_names[rkey_config_key->mem_type]);
                continue;
            }
        }

        lanes[num_lanes++] = lane;
    }

out:
    ucs_trace("selected %d lanes", num_lanes);
    ucs_log_indent(-1);
    return num_lanes;
}

ucp_md_map_t
ucp_proto_common_reg_md_map(const ucp_proto_common_init_params_t *params,
                            ucp_lane_map_t lane_map)
{
    ucp_context_h context                        = params->super.worker->context;
    const ucp_proto_select_param_t *select_param = params->super.select_param;
    const uct_md_attr_t *md_attr;
    ucp_md_index_t md_index;
    ucp_md_map_t reg_md_map;
    ucp_lane_index_t lane;

    /* Register memory only for zero-copy send operations */
    if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY)) {
        return 0;
    }

    reg_md_map = 0;
    ucs_for_each_bit(lane, lane_map) {
        md_index = ucp_proto_common_get_md_index(&params->super, lane);
        md_attr  = &context->tl_mds[md_index].attr;

        /* Register if the memory domain support registration for the relevant
           memory type, and needs a local memory handle for zero-copy
           communication */
        if (ucs_test_all_flags(md_attr->cap.flags,
                               UCT_MD_FLAG_NEED_MEMH | UCT_MD_FLAG_REG) &&
            (md_attr->cap.reg_mem_types & UCS_BIT(select_param->mem_type))) {
            reg_md_map |= UCS_BIT(md_index);
        }
    }

    return reg_md_map;
}

ucp_lane_index_t
ucp_proto_common_find_lanes(const ucp_proto_common_init_params_t *params,
                            ucp_lane_type_t lane_type, uint64_t tl_cap_flags,
                            ucp_lane_index_t max_lanes,
                            ucp_lane_map_t exclude_map, ucp_lane_index_t *lanes)
{
    ucp_lane_index_t lane_index, lane, num_lanes, num_valid_lanes;
    const uct_iface_attr_t *iface_attr;
    size_t frag_size;

    num_lanes = ucp_proto_common_find_lanes_internal(&params->super,
                                                     params->flags, lane_type,
                                                     tl_cap_flags, max_lanes,
                                                     exclude_map, lanes);

    num_valid_lanes = 0;
    for (lane_index = 0; lane_index < num_lanes; ++lane_index) {
        lane       = lanes[lane_index];
        iface_attr = ucp_proto_common_get_iface_attr(&params->super, lane);
        frag_size  = ucp_proto_common_get_max_frag(params, iface_attr);
        /* Max fragment size should be larger than header size */
        if (frag_size <= params->hdr_size) {
            ucs_trace("lane[%d]: max fragment is too small %zu, need > %zu",
                      lane, frag_size, params->hdr_size);
            continue;
        }

        lanes[num_valid_lanes++] = lane;
    }

    if (num_valid_lanes != num_lanes) {
        ucs_assert(num_valid_lanes < num_lanes);
        ucs_trace("selected %d/%d valid lanes", num_valid_lanes, num_lanes);
    }

    return num_valid_lanes;
}

ucp_lane_index_t
ucp_proto_common_find_am_bcopy_lane(const ucp_proto_init_params_t *params)
{
    ucp_lane_index_t lane = UCP_NULL_LANE;
    ucp_lane_index_t num_lanes;

    num_lanes = ucp_proto_common_find_lanes_internal(
            params, UCP_PROTO_COMMON_INIT_FLAG_MEM_TYPE, UCP_LANE_TYPE_AM,
            UCT_IFACE_FLAG_AM_BCOPY, 1, 0, &lane);
    if (num_lanes == 0) {
        ucs_debug("no active message lane for %s", params->proto_name);
        return UCP_NULL_LANE;
    }

    ucs_assert(num_lanes == 1);

    return lane;
}

static ucs_linear_func_t
ucp_proto_common_recv_time(const ucp_proto_common_init_params_t *params,
                           double tl_overhead, ucs_linear_func_t unpack_time)
{
    ucs_linear_func_t recv_time = ucs_linear_func_make(0, 0);

    if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS)) {
        /* latency measure: add remote-side processing time */
        recv_time.c = tl_overhead;
    }

    if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY)) {
        ucs_linear_func_add_inplace(&recv_time, unpack_time);
    }

    return recv_time;
}

static void ucp_proto_common_add_perf(const ucp_proto_init_params_t *params,
                                      ucs_linear_func_t func)
{
    ucp_proto_caps_t *caps = params->caps;
    unsigned i;

    for (i = 0; i < caps->num_ranges; ++i) {
        ucs_linear_func_add_inplace(&caps->ranges[i].perf, func);
    }
}

static ucs_linear_func_t
ucp_proto_common_get_reg_cost(const ucp_proto_common_init_params_t *params,
                              ucp_md_map_t reg_md_map)
{
    ucp_context_h context      = params->super.worker->context;
    ucs_linear_func_t reg_cost = ucs_linear_func_make(0, 0);
    const uct_md_attr_t *md_attr;
    ucp_md_index_t md_index;

    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY) {
        /* Go over all memory domains */
        ucs_for_each_bit(md_index, reg_md_map) {
            md_attr = &context->tl_mds[md_index].attr;
            ucs_linear_func_add_inplace(&reg_cost, md_attr->reg_cost);
        }
    }

    return reg_cost;
}

static void
ucp_proto_common_calc_completion(const ucp_proto_common_init_params_t *params,
                                 size_t frag_size, ucs_linear_func_t uct_time,
                                 ucs_linear_func_t pack_time)
{
    ucp_proto_perf_range_t *range =
            &params->super.caps->ranges[params->super.caps->num_ranges++];

    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_MAX_FRAG) {
        range->max_length = frag_size;
    } else {
        range->max_length = SIZE_MAX;
    }

    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY) {
        range->perf    = uct_time; /* Time to send data */
        range->perf.c += uct_time.c; /* Time to receive an ACK back, which is
                                        needed to release the send buffer */
    } else {
        range->perf    = pack_time; /* Time to pack the data */
    }
}

static void
ucp_proto_common_calc_latency(const ucp_proto_common_init_params_t *params,
                              size_t frag_size, uint32_t op_attr_mask,
                              ucs_linear_func_t uct_time,
                              ucs_linear_func_t pack_time,
                              ucs_linear_func_t recv_time)
{
    ucs_linear_func_t piped_size, piped_send_cost;
    ucp_proto_perf_range_t *range;
    double m;

    /* Performance for 0...frag_size */
    range             = &params->super.caps->ranges[params->super.caps->num_ranges++];
    range->max_length = ucs_min(frag_size, params->max_length);
    range->perf       = ucs_linear_func_add(uct_time, recv_time);
    if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY)) {
        if ((op_attr_mask & UCP_OP_ATTR_FLAG_MULTI_SEND) ||
            (params->flags & UCP_PROTO_COMMON_INIT_FLAG_ASYNC_COPY)) {
            range->perf.m = ucs_max(range->perf.m, pack_time.m);
            range->perf.c += pack_time.c;
        } else {
            ucs_linear_func_add_inplace(&range->perf, pack_time);
        }
    }

    /* If the 1st range already covers up to max_length, or the protocol should
     * be limited by single fragment - no more ranges are created
     */
    if ((range->max_length >= params->max_length) ||
        (params->flags & UCP_PROTO_COMMON_INIT_FLAG_MAX_FRAG)) {
        return;
    }

    /* Performance for frag_size+1...MAX */
    range             = &params->super.caps->ranges[params->super.caps->num_ranges++];
    range->max_length = params->max_length;
    range->perf       = ucs_linear_func_make(0, 0);

    if (ucs_test_all_flags(params->flags, UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY |
                                          UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY)) {
        ucs_linear_func_add_inplace(&range->perf, uct_time);
    } else if (op_attr_mask & UCP_OP_ATTR_FLAG_MULTI_SEND) {
        m               = ucs_max(pack_time.m, recv_time.m);
        piped_send_cost = ucs_linear_func_make(0, ucs_max(m, uct_time.m));
        ucs_linear_func_add_inplace(&range->perf, piped_send_cost);
    } else {
        m               = ucs_max(pack_time.m, recv_time.m);
        piped_send_cost = ucs_linear_func_make(0, ucs_max(m, uct_time.m));
        piped_size      = ucs_linear_func_make(-1.0 * frag_size, 1);

        /* Copy first fragment */
        if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_SEND_ZCOPY)) {
            ucs_linear_func_add_value_at(&range->perf, pack_time, frag_size);
        }

        /* Reach the point where we can start sending the last fragment */
        ucs_linear_func_add_inplace(&range->perf,
                                    ucs_linear_func_compose(piped_send_cost,
                                                            piped_size));

        /* Send last fragment */
        ucs_linear_func_add_value_at(&range->perf, uct_time, frag_size);
    }

    /* Receive last fragment */
    ucs_linear_func_add_value_at(&range->perf, recv_time, frag_size);
}

ucs_linear_func_t
ucp_proto_common_get_pack_time(ucp_worker_h worker, ucs_memory_type_t mem_type,
                               size_t frag_size, uint32_t op_attr_mask,
                               int is_sync, const char *title)
{
    ucp_context_h context            = worker->context;
    ucp_ep_h memtype_ep              = worker->mem_type_ep[mem_type];
    ucs_linear_func_t frag_time, pack_time;
    const uct_iface_attr_t *iface_attr;
    const ucp_ep_config_t *ep_config;
    ucp_rsc_index_t rsc_index;
    ucp_lane_index_t lane;

    if (memtype_ep == NULL) {
        return ucs_linear_func_make(0, 1.0 / context->config.ext.bcopy_bw);
    }

    /* Get memory type endpoint properties */
    ep_config  = ucp_ep_config(memtype_ep);
    lane       = is_sync ? ep_config->key.rma_lanes[0] :
                                 ep_config->key.rma_bw_lanes[0];
    rsc_index  = ep_config->key.lanes[lane].rsc_index;
    iface_attr = ucp_worker_iface_get_attr(worker, rsc_index);

    /* Calculate single fragment data transfer time for memtype copy */
    if (op_attr_mask & UCP_OP_ATTR_FLAG_MULTI_SEND) {
        frag_time.c = 0;
    } else  {
        frag_time.c = ucp_tl_iface_latency(context, &iface_attr->latency);
    }
    frag_time.m = 1.0 / ucp_tl_iface_bandwidth(context, &iface_attr->bandwidth);

    /* Calculate multi-fragment pack time */
    pack_time.m = frag_time.m + (frag_time.c / frag_size);
    if (is_sync) {
        /* Synchronous packing: overhead is added to each fragment's time */
        pack_time.c = frag_time.c + iface_attr->overhead;
        pack_time.m = frag_time.m + (pack_time.c / frag_size);
    } else {
        /* Asynchronous packing: take the maximum of fragment's overhead and its
           packing time */
        pack_time.c = ucs_max(frag_time.c, iface_attr->overhead);
        pack_time.m = ucs_max(frag_time.m, iface_attr->overhead / frag_size);
    }

    ucs_debug("%s %s on " UCT_TL_RESOURCE_DESC_FMT ", %s memory, "
              "frag_size %zu: " UCP_PROTO_PERF_FUNC_FMT " raw bw: %.2f MB/s",
              is_sync ? "sync" : "async", title,
              UCT_TL_RESOURCE_DESC_ARG(&context->tl_rscs[rsc_index].tl_rsc),
              ucs_memory_type_names[mem_type], frag_size,
              UCP_PROTO_PERF_FUNC_ARG(&pack_time),
              ucp_tl_iface_bandwidth(context, &iface_attr->bandwidth) /
                      UCS_MBYTE);
    return pack_time;
}

void ucp_proto_common_init_caps(const ucp_proto_common_init_params_t *params,
                                const ucp_proto_common_tl_perf_t *perf,
                                ucp_md_map_t reg_md_map)
{
    ucp_proto_caps_t *caps                       = params->super.caps;
    const ucp_proto_select_param_t *select_param = params->super.select_param;
    ucs_linear_func_t uct_time, recv_time;
    ucs_linear_func_t pack_time, unpack_time;
    ucs_memory_type_t recv_mem_type;
    ucs_linear_func_t extra_time;
    uint32_t op_attr_mask;
    int is_sync_pack;
    size_t frag_size;

    /* Remote access implies zero copy on receiver */
    if (params->flags & UCP_PROTO_COMMON_INIT_FLAG_REMOTE_ACCESS) {
        ucs_assert(params->flags & UCP_PROTO_COMMON_INIT_FLAG_RECV_ZCOPY);
    }

    /* Initialize capabilities */
    caps->cfg_thresh   = params->cfg_thresh;
    caps->cfg_priority = params->cfg_priority;
    caps->min_length   = ucs_max(perf->min_frag, params->min_length);
    caps->num_ranges   = 0;

    /* Take fragment size from first lane */
    frag_size = perf->max_frag;
    if (!(params->flags & UCP_PROTO_COMMON_INIT_FLAG_RESPONSE)) {
        /* if the data returns as a response, no need to subtract header size */
        frag_size -= params->hdr_size;
    }

    op_attr_mask  = ucp_proto_select_op_attr_from_flags(select_param->op_flags);
    uct_time      = ucs_linear_func_make(perf->latency + perf->sys_latency,
                                         1.0 / perf->bandwidth);
    is_sync_pack  = !(params->flags & UCP_PROTO_COMMON_INIT_FLAG_ASYNC_COPY);
    pack_time     = ucp_proto_common_get_pack_time(params->super.worker,
                                                   select_param->mem_type,
                                                   frag_size, op_attr_mask,
                                                   is_sync_pack, "pack");
    extra_time    = ucp_proto_common_get_reg_cost(params, reg_md_map);
    extra_time.c += perf->overhead;

    if ((op_attr_mask & UCP_OP_ATTR_FLAG_FAST_CMPL) &&
        !(params->flags & UCP_PROTO_COMMON_INIT_FLAG_RESPONSE)) {
        /* Calculate time to complete the send operation locally */
        ucp_proto_common_calc_completion(params, frag_size, uct_time,
                                         pack_time);
    } else {
        /* Calculate the time for message data transfer */
        if (params->super.rkey_config_key == NULL) {
            /* Assume same mem type as sender */
            recv_mem_type = select_param->mem_type;
        } else {
            recv_mem_type = params->super.rkey_config_key->mem_type;
        }
        unpack_time = ucp_proto_common_get_pack_time(params->super.worker,
                                                     recv_mem_type, frag_size,
                                                     op_attr_mask, is_sync_pack,
                                                     "unpack");
        recv_time   = ucp_proto_common_recv_time(params, perf->overhead,
                                                 unpack_time);
        ucs_trace("unpack_time: " UCP_PROTO_PERF_FUNC_FMT
                  " recv_time: " UCP_PROTO_PERF_FUNC_FMT
                  " uct_time: " UCP_PROTO_PERF_FUNC_FMT,
                  UCP_PROTO_PERF_FUNC_ARG(&unpack_time),
                  UCP_PROTO_PERF_FUNC_ARG(&recv_time),
                  UCP_PROTO_PERF_FUNC_ARG(&uct_time));
        ucp_proto_common_calc_latency(params, frag_size, op_attr_mask, uct_time,
                                      pack_time, recv_time);

        /* If we wait for response, add latency of sending the request */
        if ((params->flags & UCP_PROTO_COMMON_INIT_FLAG_RESPONSE) &&
            !(op_attr_mask & UCP_OP_ATTR_FLAG_MULTI_SEND)) {
            extra_time.c += perf->latency;
        }
    }

    ucp_proto_common_add_perf(&params->super, extra_time);

    if (0 && op_attr_mask & UCP_OP_ATTR_FLAG_MULTI_SEND) {
        ucp_proto_perf_range_t *range;
        int i;

        for (i = 0; i < params->super.caps->num_ranges; ++i) {
            range = &params->super.caps->ranges[i];
            range->perf.m = ucs_max(range->perf.m, range->perf.c / frag_size);
            range->perf.c = 0;
        }
    }

}

void ucp_proto_request_zcopy_completion(uct_completion_t *self)
{
    ucp_request_t *req = ucs_container_of(self, ucp_request_t, send.state.uct_comp);

    /* request should NOT be on pending queue because when we decrement the last
     * refcount the request is not on the pending queue any more
     */
    ucp_proto_request_zcopy_cleanup(req);
    ucp_request_complete_send(req, req->send.state.uct_comp.status);
}

void ucp_proto_trace_selected(ucp_request_t *req, size_t msg_length)
{
    UCS_STRING_BUFFER_ONSTACK(sel_param_strb, UCP_PROTO_SELECT_PARAM_STR_MAX);
    UCS_STRING_BUFFER_ONSTACK(proto_config_strb, UCP_PROTO_CONFIG_STR_MAX);
    const ucp_proto_config_t *proto_config = req->send.proto_config;

    ucp_proto_select_param_str(&proto_config->select_param, &sel_param_strb);
    proto_config->proto->config_str(msg_length, msg_length, proto_config->priv,
                                    &proto_config_strb);
    ucp_trace_req(req, "%s length %zu using %s{%s}",
                  ucs_string_buffer_cstr(&sel_param_strb), msg_length,
                  proto_config->proto->name,
                  ucs_string_buffer_cstr(&proto_config_strb));
}

void ucp_proto_request_select_error(ucp_request_t *req,
                                    ucp_proto_select_t *proto_select,
                                    ucp_worker_cfg_index_t rkey_cfg_index,
                                    const ucp_proto_select_param_t *sel_param,
                                    size_t msg_length)
{
    UCS_STRING_BUFFER_ONSTACK(sel_param_strb, UCP_PROTO_SELECT_PARAM_STR_MAX);
    UCS_STRING_BUFFER_ONSTACK(proto_select_strb, UCP_PROTO_CONFIG_STR_MAX);
    ucp_ep_h ep = req->send.ep;

    ucp_proto_select_param_str(sel_param, &sel_param_strb);
    ucp_proto_select_dump(ep->worker, ep->cfg_index, rkey_cfg_index,
                          proto_select, &proto_select_strb);
    ucs_fatal("req %p on ep %p to %s: could not find a protocol for %s "
              "length %zu\navailable protocols:\n%s\n",
              req, ep, ucp_ep_peer_name(ep),
              ucs_string_buffer_cstr(&sel_param_strb), msg_length,
              ucs_string_buffer_cstr(&proto_select_strb));
}

void ucp_proto_request_abort(ucp_request_t *req, ucs_status_t status)
{
    ucs_assert(UCS_STATUS_IS_ERR(status));
    /*
     * TODO add a method to ucp_proto_t to abort a request (which is currently
     * not scheduled to a pending queue). The method should wait for UCT
     * completions and release associated resources, such as memory handles,
     * remote keys, request ID, etc.
     */
    ucs_fatal("abort request %p proto %s status %s: unimplemented", req,
              req->send.proto_config->proto->name, ucs_status_string(status));
}

void ucp_proto_set_wjh(ucp_request_t *req,
                       const ucp_proto_select_elem_t *select_elem,
                       size_t length)
{
    ucs_string_buffer_t *strb              = ucp_wjh_buffer();
    const ucp_proto_config_t *proto_config = req->send.proto_config;
    const ucp_proto_select_range_t *range;

    ucp_proto_select_param_str(&proto_config->select_param, strb);
    ucs_string_buffer_appendf(strb, ": %s ", proto_config->proto->name);

    proto_config->proto->config_str(length, length, proto_config->priv, strb);

    range = select_elem->ranges;
    do {
        if (length <= range->super.max_length) {
            double latency = ucs_linear_func_apply(range->super.perf, length);
            double bw      = length / latency;
            ucs_string_buffer_appendf(strb, "  %.2f MBs / %.2f us",
                                      bw / UCS_MBYTE,
                                      latency * UCS_USEC_PER_SEC);
            break;
        }
    } while ((range++)->super.max_length < SIZE_MAX);
}
