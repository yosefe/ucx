/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "ucx_info.h"

#include <ucs/config/parser.h>
#include <ucs/config/global_opts.h>
#include <ucm/api/ucm.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <ucp/core/ucp_context.h>
#include <ucp/proto/proto_select.inl>
#include <ucs/datastruct/array.inl>


// TODO move to ucs/string.h
static int __find_string_in_list(const char *str, const char * const *table,
                                 size_t length)
{
    size_t i;

    for (i = 0; i < length; ++i) {
        if ((table[i] != NULL) && (strcasecmp(table[i], str) == 0)) {
            return i;
        }
    }

    return -1;
}

static char* __print_table_values(const char * const *table, size_t length,
                                  char *buf, size_t max)
{
    char *ptr = buf, *end = buf + max;
    size_t i;

    for (i = 0; i < length; ++i) {
        if (table[i] == NULL) {
            continue;
        }
        snprintf(ptr, end - ptr, "|%s", table[i]);
        ptr += strlen(ptr);
    }

    snprintf(ptr, end - ptr, ">");
    *buf = '<';

    return buf;
}

static void usage() {
    char buf[128];

    printf("Usage: ucx_info [options]\n");
    printf("At least one of the following options has to be set:\n");

    printf("  -v                         Show version information\n");
    printf("  -d                         Show devices and transports\n");
    printf("  -b                         Show build configuration\n");
    printf("  -y                         Show type and structures information\n");
    printf("  -s                         Show system information\n");
    printf("  -c                         Show UCX configuration\n");
    printf("  -C                         Comment-out default configuration values\n");
    printf("  -a                         Show also hidden configuration\n");
    printf("  -f                         Display fully decorated output\n");
    printf("\nUCP information            (-u is required):\n");
    printf("  -p                         Show UCP context information\n");
    printf("  -w                         Show UCP worker information\n");
    printf("  -e                         Show UCP endpoint configuration\n");
    printf("  -m <size>                  Show UCP memory allocation method for a given size\n");
    printf("  -u <features>              UCP context features to use.\n");
    printf("                    'a' : atomic operations\n");
    printf("                    'r' : remote memory access\n");
    printf("                    't' : tag matching \n");
    printf("                    'm' : active messages \n");
    printf("                    'w' : wakeup\n");
    printf("                    'e' : error handling\n");
    printf("\nOther settings:\n");
    printf("  -t <name>                  Filter devices information using specified transport (requires -d)\n");
    printf("  -n <count>                 Estimated UCP endpoint count (for ucp_init)\n");
    printf("  -N <count>                 Estimated UCP endpoint count per node (for ucp_init)\n");
    printf("  -D <type>                  Set which device types to use when creating UCP context:\n");
    printf("                               'all'  : all possible devices (default)\n");
    printf("                               'shm'  : shared memory devices only\n");
    printf("                               'net'  : network devices only\n");
    printf("                               'self' : self transport only\n");
    printf("  -P <type>                   Set peer process placement for printing UCP endpoint configuration:\n");
    printf("                    'self'  : same process (default)\n");
    printf("                    'intra' : same node\n");
    printf("                    'inter' : different node\n");
    printf("\n");
    printf("  -S <op>[,<dt>[,<mem>]]     Initialize protocols for given select params\n");
    //TODO
    printf("                    <op>  :  %s[:f]\n",
           __print_table_values(ucp_operation_names, UCP_OP_ID_LAST, buf,
                                sizeof(buf)));
    printf("                      'f' :  fast completion\n");
    printf("                    <dt>  :  %s[:<sg-count>] (default: contig)\n",
           __print_table_values(ucp_datatype_class_names,
                                UCS_BIT(UCP_DATATYPE_SHIFT), buf, sizeof(buf)));
    printf("                    <mem> :  %s[:<sys-dev-bdf>] (default: host)\n",
           __print_table_values(ucs_memory_type_names, UCS_MEMORY_TYPE_LAST,
                                buf, sizeof(buf)));
    printf("\n");
    printf("\n");
    /* TODO: add IPv6 support */
    printf("  -A <ipv4>                  Local IPv4 device address to use for creating\n"
           "                             endpoint in client/server mode");
    printf("  -h                         Show this help message\n");
    printf("\n");
}

UCS_ARRAY_IMPL(select_param, unsigned, ucp_proto_select_param_t, static);

static int parse_selparam_op(ucp_proto_select_param_t *select_param,
                             char *op_spec)
{
    char *p, *saveptr;
    int ret;

    p   = strtok_r(op_spec, ":", &saveptr);
    ret = __find_string_in_list(p, ucp_operation_names, UCP_OP_ID_LAST);
    if (ret < 0) {
        fprintf(stderr, "invalid operation name '%s'\n", p);
        return ret;
    }

    select_param->op_id = ret;

    /* flags */
    p = strtok_r(NULL, ":", &saveptr);
    if (p == NULL) {
        return 0;
    }

    select_param->op_flags = 0;
    while (*p != '\0') {
        switch (*p) {
        case 'f':
            select_param->op_flags |=
                    ucp_proto_select_op_attr_to_flags(UCP_OP_ATTR_FLAG_FAST_CMPL);
            break;
        default:
            fprintf(stderr, "invalid operation flag '%c'\n", *p);
            return -1;
        }
        ++p;
    }

    return 0;
}

static int parse_datatype_op(ucp_proto_select_param_t *select_param,
                             char *datatype_spec)
{
    char *p, *saveptr, *tailptr;
    int ret;

    p   = strtok_r(datatype_spec, ":", &saveptr);
    ret = __find_string_in_list(p, ucp_datatype_class_names,
                                UCS_BIT(UCP_DATATYPE_SHIFT));
    if (ret < 0) {
        fprintf(stderr, "invalid datatype name '%s'\n", p);
        return ret;
    }

    select_param->dt_class = ret;

    /* sg_count */
    p = strtok_r(NULL, ":", &saveptr);
    if (p == NULL) {
        return 0;
    }

    select_param->sg_count = strtol(p, &tailptr, 0);
    if (*tailptr != '\0') {
        fprintf(stderr, "invalid sg_count '%s'\n", p);
        return -1;
    }

    return 0;
}


static int parse_memtype_op(ucp_proto_select_param_t *select_param,
                            char *memtype_spec)
{
    ucs_status_t status;
    char *p, *saveptr;
    int ret;

    p   = strtok_r(memtype_spec, ":", &saveptr);
    ret = __find_string_in_list(p, ucs_memory_type_names, UCS_MEMORY_TYPE_LAST);
    if (ret < 0) {
        fprintf(stderr, "invalid memory type '%s'\n", p);
        return ret;
    }

    select_param->mem_type = ret;

    /* sys_dev  */
    p = strtok_r(NULL, "", &saveptr);
    if (p == NULL) {
        return 0;
    }

    status = ucs_topo_find_device_by_bdf_name(p, &select_param->sys_dev);
    if (status != UCS_OK) {
        fprintf(stderr, "could not find sys device '%s'\n", p);
        return -1;
    }

    return 0;
}

static int append_select_param(ucs_array_t(select_param) *select_params,
                               char *spec)
{
    ucp_proto_select_param_t select_param;
    ucp_memory_info_t mem_info;
    char *p, *saveptr;
    int ret;

    mem_info.type    = UCS_MEMORY_TYPE_HOST;
    mem_info.sys_dev = UCS_SYS_DEVICE_ID_UNKNOWN;
    ucp_proto_select_param_init(&select_param, UCP_OP_ID_LAST, 0,
                                UCP_DATATYPE_CONTIG, &mem_info, 1);

    p   = strtok_r(spec, ",", &saveptr);
    ret = parse_selparam_op(&select_param, p);
    if (ret < 0) {
        return ret;
    }

    p = strtok_r(NULL, ",", &saveptr);
    if (p == NULL) {
        goto out; /* no datatype */
    }

    ret = parse_datatype_op(&select_param, p);
    if (ret < 0) {
        return ret;
    }

    p = strtok_r(NULL, ",", &saveptr);
    if (p == NULL) {
        goto out; /* no memtype */
    }

    ret = parse_memtype_op(&select_param, p);
    if (ret < 0) {
        return ret;
    }

out:
    ucs_array_append(select_param, select_params); //TODO check retval
    *ucs_array_last(select_params) = select_param;
    return 0;
}

int main(int argc, char **argv)
{
    ucs_array_t(select_param) select_params;
    ucs_config_print_flags_t print_flags;
    ucp_ep_params_t ucp_ep_params;
    unsigned dev_type_bitmap;
    process_placement_t proc_placement;
    uint64_t ucp_features;
    size_t ucp_num_eps;
    size_t ucp_num_ppn;
    unsigned print_opts;
    char *tl_name, *mem_size;
    char *ip_addr;
    const char *f;
    int c, ret;

    print_opts               = 0;
    print_flags              = (ucs_config_print_flags_t)0;
    tl_name                  = NULL;
    ucp_features             = 0;
    ucp_num_eps              = 1;
    ucp_num_ppn              = 1;
    mem_size                 = NULL;
    dev_type_bitmap          = UINT_MAX;
    proc_placement           = PROCESS_PLACEMENT_SELF;
    ucp_ep_params.field_mask = 0;
    ip_addr                  = NULL;

    ucs_array_init_dynamic(&select_params);
    while ((c = getopt(argc, argv, "fahvcydbswpeCt:n:u:D:P:m:N:S:WA:")) != -1) {
        switch (c) {
        case 'f':
            print_flags |= UCS_CONFIG_PRINT_CONFIG | UCS_CONFIG_PRINT_HEADER | UCS_CONFIG_PRINT_DOC;
            break;
        case 'a':
            print_flags |= UCS_CONFIG_PRINT_HIDDEN;
            break;
        case 'c':
            print_flags |= UCS_CONFIG_PRINT_CONFIG;
            break;
        case 'C':
            print_flags |= UCS_CONFIG_PRINT_COMMENT_DEFAULT;
            break;
        case 'v':
            print_opts |= PRINT_VERSION;
            break;
        case 'd':
            print_opts |= PRINT_DEVICES;
            break;
        case 'b':
            print_opts |= PRINT_BUILD_CONFIG;
            break;
        case 'y':
            print_opts |= PRINT_TYPES;
            break;
        case 's':
            print_opts |= PRINT_SYS_INFO;
            break;
        case 'p':
            print_opts |= PRINT_UCP_CONTEXT;
            break;
        case 'w':
            print_opts |= PRINT_UCP_WORKER;
            break;
        case 'e':
            print_opts |= PRINT_UCP_EP;
            break;
        case 'm':
            print_opts |= PRINT_MEM_MAP;
            mem_size = optarg;
            break;
        case 't':
            tl_name = optarg;
            break;
        case 'n':
            ucp_num_eps = atol(optarg);
            break;
        case 'N':
            ucp_num_ppn = atol(optarg);
            break;
        case 'W':
            print_opts |= PRINT_WAIT;
            break;
        case 'u':
            for (f = optarg; *f; ++f) {
                switch (*f) {
                case 'a':
                    ucp_features |= UCP_FEATURE_AMO32|UCP_FEATURE_AMO64;
                    break;
                case 'r':
                    ucp_features |= UCP_FEATURE_RMA;
                    break;
                case 't':
                    ucp_features |= UCP_FEATURE_TAG;
                    break;
                case 'w':
                    ucp_features |= UCP_FEATURE_WAKEUP;
                    break;
                case 'm':
                    ucp_features |= UCP_FEATURE_AM;
                    break;
                case 'e':
                    ucp_ep_params.field_mask |= UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE;
                    ucp_ep_params.err_mode    = UCP_ERR_HANDLING_MODE_PEER;
                    break;
                default:
                    usage();
                    ret = -1;
                    goto out;
                }
            }
            break;
        case 'D':
            if (!strcasecmp(optarg, "net")) {
                dev_type_bitmap = UCS_BIT(UCT_DEVICE_TYPE_NET);
            } else if (!strcasecmp(optarg, "shm")) {
                dev_type_bitmap = UCS_BIT(UCT_DEVICE_TYPE_SHM);
            } else if (!strcasecmp(optarg, "self")) {
                dev_type_bitmap = (UCS_BIT(UCT_DEVICE_TYPE_SELF) |
                                   UCS_BIT(UCT_DEVICE_TYPE_ACC));
            } else if (strcasecmp(optarg, "all")) {
                usage();
                return -1;
            }
            break;
        case 'P':
            if (!strcasecmp(optarg, "intra")) {
                /* Only Network and SHM devices are allowed for processes on the
                 * same node */
                proc_placement = PROCESS_PLACEMENT_INTRA;
            } else if (!strcasecmp(optarg, "inter")) {
                /* Only Network devices are allowed for processes on the
                 * different node */
                proc_placement = PROCESS_PLACEMENT_INTER;
            } else if (strcasecmp(optarg, "self")) {
                usage();
                return -1;
            }
            break;
        case 'A':
            ip_addr = optarg;
            break;
        case 'S':
            ret = append_select_param(&select_params, optarg);
            if (ret < 0) {
                usage();
                goto out;
            }
            break;
        case 'h':
            usage();
            ret = 0;
            goto out;
        default:
            usage();
            ret = -1;
            goto out;
        }
    }

    if ((print_opts == 0) && (print_flags == 0)) {
        usage();
        return -2;
    }

    if (print_opts & PRINT_VERSION) {
        print_version();
    }

    if (print_opts & PRINT_SYS_INFO) {
        print_sys_info();
    }

    if (print_opts & PRINT_BUILD_CONFIG) {
        print_build_config();
    }

    if (print_opts & PRINT_TYPES) {
        print_type_info(tl_name);
    }

    if ((print_opts & PRINT_DEVICES) || (print_flags & UCS_CONFIG_PRINT_CONFIG)) {
        /* if UCS_CONFIG_PRINT_CONFIG is ON, trigger loading UCT modules by
         * calling print_uct_info()->uct_component_query()
         */
        print_uct_info(print_opts, print_flags, tl_name);
    }

    if (print_flags & UCS_CONFIG_PRINT_CONFIG) {
        ucs_config_parser_print_all_opts(stdout, UCS_DEFAULT_ENV_PREFIX,
                                         print_flags, &ucs_config_global_list);
    }

    if (print_opts & (PRINT_UCP_CONTEXT|PRINT_UCP_WORKER|PRINT_UCP_EP|PRINT_MEM_MAP)) {
        if (ucp_features == 0) {
            printf("Please select UCP features using -u switch: a|r|t|m|w\n");
            usage();
            ret = -1;
            goto out;
        }

        return print_ucp_info(print_opts, print_flags, ucp_features,
                              &ucp_ep_params, ucp_num_eps, ucp_num_ppn,
                              dev_type_bitmap, proc_placement, mem_size,
                              ip_addr, &select_params);
    }

    ret = 0;

out:
    ucs_array_cleanup_dynamic(&select_params);
    return ret;
}
