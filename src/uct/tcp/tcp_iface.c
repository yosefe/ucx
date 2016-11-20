/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include "tcp.h"

#include <ucs/async/async.h>
#include <sys/socket.h>
#include <sys/poll.h>


static ucs_config_field_t uct_tcp_iface_config_table[] = {
    {"", "", NULL,
     ucs_offsetof(uct_tcp_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"PREFER_DEFAULT", "y",
     "Give higher priority to the default network interface on the host",
     ucs_offsetof(uct_tcp_iface_config_t, prefer_default), UCS_CONFIG_TYPE_BOOL},

    {"BACKLOG", "100",
     "Backlog size of incoming connections",
     ucs_offsetof(uct_tcp_iface_config_t, backlog), UCS_CONFIG_TYPE_UINT},

    {"NONBLOCKING", "n",
     "Use non-blocking mode",
     ucs_offsetof(uct_tcp_iface_config_t, nonblocking), UCS_CONFIG_TYPE_BOOL},

    {"SNDBUF", "auto",
     "If != auto, override default setting of TCP send buffer size",
     ucs_offsetof(uct_tcp_iface_config_t, sndbuf), UCS_CONFIG_TYPE_MEMUNITS},

    {"RCVBUF", "auto",
     "If != auto, override default setting of TCP receive buffer size",
     ucs_offsetof(uct_tcp_iface_config_t, rcvbuf), UCS_CONFIG_TYPE_MEMUNITS},

    {NULL}
};

static ucs_status_t uct_tcp_iface_get_device_address(uct_iface_h tl_iface,
                                                     uct_device_addr_t *addr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    struct sockaddr_in if_addr;
    ucs_status_t status;

    status = uct_tcp_netif_inaddr(iface->if_name, &if_addr);
    if (status != UCS_OK) {
        return status;
    }

    *(struct in_addr*)addr = if_addr.sin_addr;
    return UCS_OK;
}

static ucs_status_t uct_tcp_iface_get_address(uct_iface_h tl_iface, uct_iface_addr_t *addr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    struct sockaddr_in saddr;
    socklen_t addrlen;
    int ret;

    addrlen = sizeof(saddr);
    getsockname(iface->listen_fd, (struct sockaddr*)&saddr, &addrlen);
    ret = getsockname(iface->listen_fd, (struct sockaddr*)&saddr, &addrlen);
    if (ret < 0) {
        ucs_error("getsockname() failed: %m");
        return UCS_ERR_INVALID_ADDR;
    }

    ucs_assert(saddr.sin_family == AF_INET);
    *(in_port_t*)addr = saddr.sin_port;
    return UCS_OK;
}

static int uct_tcp_iface_is_reachable(const uct_iface_h iface,
                                      const uct_device_addr_t *dev_addr,
                                      const uct_iface_addr_t *iface_addr)
{
    // TODO check addr/netmask
    return 1;
}

static ucs_status_t uct_tcp_iface_query(uct_iface_h tl_iface, uct_iface_attr_t *attr)
{
    uct_tcp_iface_t *iface = ucs_derived_of(tl_iface, uct_tcp_iface_t);
    ucs_status_t status;
    int is_default;

    memset(attr, 0, sizeof(*attr));
    attr->iface_addr_len   = sizeof(in_port_t);
    attr->device_addr_len  = sizeof(struct in_addr);
    attr->ep_addr_len      = 0;
    attr->cap.flags        = UCT_IFACE_FLAG_CONNECT_TO_IFACE |
                             UCT_IFACE_FLAG_AM_BCOPY         |
                             UCT_IFACE_FLAG_PENDING          |
                             UCT_IFACE_FLAG_AM_CB_SYNC       |
                             UCT_IFACE_FLAG_AM_CB_ASYNC      |
                             UCT_IFACE_FLAG_WAKEUP;

    attr->cap.am.max_short = 0;
    attr->cap.am.max_bcopy = iface->config.max_bcopy;
    attr->cap.am.max_zcopy = 0;
    attr->cap.am.max_hdr   = 0;
    attr->cap.am.max_iov   = 1;

    status = uct_tcp_netif_caps(iface->if_name, &attr->latency, &attr->bandwidth);
    if (status != UCS_OK) {
        return status;
    }

    attr->overhead  = 10e-6;  /* 10 usec */

    if (iface->config.prefer_default) {
        status = uct_tcp_netif_is_default(iface->if_name, &is_default);
        if (status != UCS_OK) {
             return status;
        }

        attr->priority = is_default ? 0 : 1;
    } else {
        attr->priority = 0;
    }

    return UCS_OK;
}

static void uct_tcp_iface_release_am_desc(uct_iface_t *tl_iface, void *desc)
{
    uct_am_recv_desc_t *tcp_desc = (uct_am_recv_desc_t *)desc - 1;

    ucs_trace_func("iface=%p, desc=%p", tl_iface, tcp_desc); // TODO
    ucs_mpool_put(tcp_desc);
}

/* Handles incoming messages */
static void uct_tcp_iface_recv_handler(void *arg)
{
    uct_tcp_iface_t *iface = arg;
    uct_tcp_desc_t *desc;
    ucs_status_t status;
    int fd = -1; // TODO

    desc = ucs_mpool_get(&iface->mp);
    if (desc == NULL) {
        return;
    }

    uct_tcp_recv(fd, desc, sizeof(*desc));
    uct_tcp_recv(fd, desc + 1, desc->length);
    ucs_trace_data("RECV am_id %d", desc->am_id);


    // TODO if AM flag is sync, invoke slowpath progress

    status = uct_iface_invoke_am(&iface->super, desc->am_id, desc + 1,
                                 desc->length, desc);
    if (status == UCS_OK) {
        ucs_mpool_put(desc);
    }
}

/* Handles connection events on server side */
static void uct_tcp_iface_connect_handler(void *arg)
{
    uct_tcp_iface_t *iface = arg;
    uct_worker_h worker = iface->super.worker;
    struct sockaddr_storage client_addr;
    socklen_t client_addrlen;
    ucs_status_t status;
    int sockfd;

    sockfd = accept(iface->listen_fd, (struct sockaddr*)&client_addr,
                    &client_addrlen);
    if (sockfd < 0) {
        ucs_error("accept() failed: %m");
        return;
    }

    // TODO if socket already exists - dup2 to close to socket with lower checksum
//    khash_add(&iface->fd_hash, sockfd);

    status = ucs_async_set_event_handler(worker->async->mode, sockfd, POLLIN,
                                         uct_tcp_iface_recv_handler, iface,
                                         worker->async);
    if (status != UCS_OK) {
        return;
    }
}

static UCS_CLASS_DEFINE_DELETE_FUNC(uct_tcp_iface_t, uct_iface_t);

static uct_iface_ops_t uct_tcp_iface_ops = {
    .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_tcp_iface_t),
    .iface_get_device_address = uct_tcp_iface_get_device_address,
    .iface_get_address        = uct_tcp_iface_get_address,
    .iface_query              = uct_tcp_iface_query,
    .iface_is_reachable       = uct_tcp_iface_is_reachable,
    .iface_release_am_desc    = uct_tcp_iface_release_am_desc,
    .ep_create_connected      = UCS_CLASS_NEW_FUNC_NAME(uct_tcp_ep_t),
    .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_tcp_ep_t),
    .ep_am_bcopy              = uct_tcp_ep_am_bcopy,
    .ep_pending_add           = ucs_empty_function_return_busy,
    .ep_pending_purge         = ucs_empty_function,
};

static ucs_mpool_ops_t uct_tcp_mpool_ops = {
    .chunk_alloc   = ucs_mpool_chunk_mmap,
    .chunk_release = ucs_mpool_chunk_munmap,
    .obj_init      = NULL,
    .obj_cleanup   = NULL
};

static UCS_CLASS_INIT_FUNC(uct_tcp_iface_t, uct_md_h md, uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config)
{
    uct_tcp_iface_config_t *config = ucs_derived_of(tl_config, uct_tcp_iface_config_t);
    struct sockaddr_in bind_addr;
    ucs_status_t status;
    int ret;

    UCS_CLASS_CALL_SUPER_INIT(uct_base_iface_t, &uct_tcp_iface_ops, md, worker,
                              tl_config UCS_STATS_ARG(NULL));

    strncpy(self->if_name, params->dev_name, sizeof(self->if_name));
    self->config.max_bcopy      = config->super.max_bcopy;
    self->config.prefer_default = config->prefer_default;

   //        khash_init(tcp->fds_hash);

    status = uct_tcp_netif_inaddr(self->if_name, &bind_addr);
    if (status != UCS_OK) {
        goto err;
    }

    status = ucs_mpool_init(&self->mp, 0,
                            params->rx_headroom + sizeof(uct_tcp_desc_t) +
                            self->config.max_bcopy,
                            0,                        /* alignment offset */
                            UCS_SYS_CACHE_LINE_SIZE,  /* alignment */
                            32,                       /* grow */
                            -1,                       /* max buffers */
                            &uct_tcp_mpool_ops,
                            "tcp_desc");
    if (status != UCS_OK) {
        goto err;
    }


    status = uct_tcp_socket_create(&self->listen_fd);
    if (status != UCS_OK) {
        goto err_mpool_cleanup;
    }

    if (config->nonblocking) {
        status = ucs_sys_fcntl_modfl(self->listen_fd, O_NONBLOCK, 0);
        if (status != UCS_OK) {
            goto err_close_sock;
        }
    }

    bind_addr.sin_port = 0; /* auto-select port */
    ret = bind(self->listen_fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr));
    if (ret < 0) {
        ucs_error("bind() failed: %m");
        goto err_close_sock;
    }

    ret = listen(self->listen_fd, config->backlog);
    if (ret < 0) {
        ucs_error("listen(backlog=%d)", config->backlog);
        status = UCS_ERR_IO_ERROR;
        goto err_close_sock;
    }

    status = ucs_async_set_event_handler(worker->async->mode, self->listen_fd,
                                         POLLIN|POLLERR,
                                         uct_tcp_iface_connect_handler, self,
                                         worker->async);
    if (status != UCS_OK) {
        goto err_close_sock;
    }

    return UCS_OK;

err_close_sock:
    close(self->listen_fd);
err_mpool_cleanup:
    ucs_mpool_cleanup(&self->mp, 0);
err:
    return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_tcp_iface_t)
{
//    khash_for_each() {
//        close(iter->fd); // close all open file descriptors
//    }
    ucs_async_unset_event_handler(self->listen_fd);
    close(self->listen_fd);
//    khash_cleanup(self->fds_hash);
}

UCS_CLASS_DEFINE(uct_tcp_iface_t, uct_base_iface_t);
static UCS_CLASS_DEFINE_NEW_FUNC(uct_tcp_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t*,
                                 const uct_iface_config_t*);

static ucs_status_t uct_tcp_query_tl_resources(uct_md_h md,
                                               uct_tl_resource_desc_t **resource_p,
                                               unsigned *num_resources_p)
{
    uct_tl_resource_desc_t *resources, *tmp, *resource;
    unsigned num_resources;
    struct if_nameindex *ifs, *netif;
    ucs_status_t status;

    ifs = if_nameindex();
    if (ifs == NULL) {
        ucs_error("if_nameindex() failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto out;
    }

    resources     = NULL;
    num_resources = 0;

    for (netif = ifs; netif->if_name != NULL; ++netif) {
        if (!uct_tcp_netif_check(netif->if_name)) {
            continue;
        }

        tmp = ucs_realloc(resources, sizeof(*resources) * (num_resources + 1),
                          "resource desc");
        if (tmp == NULL) {
            ucs_error("failed to allocate memory");
            ucs_free(resources);
            status = UCS_ERR_NO_MEMORY;
            goto out_free_ifaddrs;
        }

        resources = tmp;

        resource = &resources[num_resources++];
        ucs_snprintf_zero(resource->tl_name, sizeof(resource->tl_name),
                          "%s", UCT_TCP_NAME);
        ucs_snprintf_zero(resource->dev_name, sizeof(resource->dev_name),
                          "%s", netif->if_name);
        resource->dev_type = UCT_DEVICE_TYPE_NET;
    }

    *num_resources_p = num_resources;
    *resource_p      = resources;
    status           = UCS_OK;

out_free_ifaddrs:
    if_freenameindex(ifs);
out:
    return status;
}

UCT_TL_COMPONENT_DEFINE(uct_tcp_tl, uct_tcp_query_tl_resources, uct_tcp_iface_t,
                        UCT_TCP_NAME, "TCP_", uct_tcp_iface_config_table,
                        uct_tcp_iface_config_t);
UCT_MD_REGISTER_TL(&uct_tcp_md, &uct_tcp_tl);
