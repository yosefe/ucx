/**
 * Copyright (C) Mellanox Technologies Ltd. 2001-2016.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "tcp.h"

#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <netdb.h>


ucs_status_t uct_tcp_socket_create(int *fd_p)
{
    int fd;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        ucs_error("socket create failed: %m");
        return UCS_ERR_IO_ERROR;
    }

    *fd_p = fd;
    return UCS_OK;
}

ucs_status_t uct_tcp_socket_connect(int fd, const struct sockaddr_in *dest_addr)
{
    int ret;

    ret = connect(fd, (struct sockaddr*)dest_addr, sizeof(*dest_addr));
    if (ret < 0) {
        ucs_error("connect() failed: %m"); // TODO print address
        return UCS_ERR_UNREACHABLE;
    }

    return UCS_OK;
}

static ucs_status_t uct_tcp_netif_ioctl(const char *if_name, unsigned long request,
                                        struct ifreq *if_req)
{
    ucs_status_t status;
    int fd, ret;

    strncpy(if_req->ifr_name, if_name, sizeof(if_req->ifr_name));

    status = uct_tcp_socket_create(&fd);
    if (status != UCS_OK) {
        goto out;
    }

    ret = ioctl(fd, request, if_req);
    if (ret < 0) {
        ucs_error("ioctl(req=%lu, ifr_name=%s) failed: %m", request, if_name);
        status = UCS_ERR_IO_ERROR;
        goto out_close_fd;
    }

    status = UCS_OK;

out_close_fd:
    close(fd);
out:
    return status;
}

int uct_tcp_netif_check(const char *if_name)
{
    ucs_status_t status;
    struct ifreq ifr;

    status = uct_tcp_netif_ioctl(if_name, SIOCGIFFLAGS, &ifr);
    if (status != UCS_OK) {
        return 0;
    }

    return (ifr.ifr_flags & IFF_UP) &&
           (ifr.ifr_flags & IFF_RUNNING) &&
           !(ifr.ifr_flags & IFF_LOOPBACK);
}

ucs_status_t uct_tcp_netif_caps(const char *if_name, double *latency_p,
                                double *bandwidth_p)
{
    struct ethtool_cmd edata;
    uint32_t speed_mbps;
    ucs_status_t status;
    struct ifreq ifr;
    size_t mtu, ll_headers;
    short ether_type;

    edata.cmd    = ETHTOOL_GSET;
    ifr.ifr_data = (void*)&edata;
    status = uct_tcp_netif_ioctl(if_name, SIOCETHTOOL, &ifr);
    if (status != UCS_OK) {
        return status;
    }

    speed_mbps = ethtool_cmd_speed(&edata);
    if (speed_mbps == SPEED_UNKNOWN) {
        ucs_error("speed of %s is UNKNOWN", if_name);
        return UCS_ERR_NO_DEVICE;
    }

    status = uct_tcp_netif_ioctl(if_name, SIOCGIFHWADDR, &ifr);
    if (status != UCS_OK) {
        return status;
    }
    ether_type = ifr.ifr_addr.sa_family;

    status = uct_tcp_netif_ioctl(if_name, SIOCGIFMTU, &ifr);
    if (status != UCS_OK) {
        return status;
    }
    mtu = ifr.ifr_mtu;

    switch (ether_type) {
    case ARPHRD_ETHER:
        /* https://en.wikipedia.org/wiki/Ethernet_frame */
        ll_headers = 7 + /* preamble */
                     1 + /* start-of-frame */
                     ETH_HLEN + /* src MAC + dst MAC + ethertype */
                     ETH_FCS_LEN + /* CRC */
                     12; /* inter-packet gap */
        break;
    default:
        ll_headers = 0;
        break;
    }

    /* https://w3.siemens.com/mcms/industrial-communication/en/rugged-communication/Documents/AN8.pdf */
    *latency_p   = 576.0 / (speed_mbps * 1e6) + 5.2e-6;
    *bandwidth_p = (speed_mbps * 1e6) / 8 *
                   (mtu - 40) / (mtu + ll_headers); /* TCP/IP header is 40 bytes */

    return UCS_OK;
}

ucs_status_t uct_tcp_netif_inaddr(const char *if_name, struct sockaddr_in *addr)
{
    ucs_status_t status;
    struct ifreq ifr;

    status = uct_tcp_netif_ioctl(if_name, SIOCGIFADDR, &ifr);
    if (status != UCS_OK) {
        return status;
    }

    if (ifr.ifr_addr.sa_family != AF_INET) {
        ucs_error("%s address is not INET", if_name);
        return UCS_ERR_INVALID_ADDR;
    }

    memcpy(addr, (struct sockaddr_in*)&ifr.ifr_addr, sizeof(*addr));
    return UCS_OK;
}

ucs_status_t uct_tcp_netif_is_default(const char *if_name, int *result_p)
{
    struct hostent hbuf, *result;
    struct sockaddr_in ifaddr;
    ucs_status_t status;
    void *buffer, *tmp;
    size_t length;
    int ret, herr;
    char **addr_p;

    status = uct_tcp_netif_inaddr(if_name, &ifaddr);
    if (status != UCS_OK) {
        goto out;
    }

    length = 32;
    buffer = NULL;
    do {
        length = length * 2;
        tmp = ucs_realloc(buffer, length, "hostname buffer");
        if (tmp == NULL) {
            ucs_error("failed to allocate buffer of %zu bytes", length);
            status = UCS_ERR_NO_MEMORY;
            goto out_free_buffer;
        }

        buffer = tmp;
        /* use gethostbyname_r to ensure thread safety */
        ret = gethostbyname_r(ucs_get_host_name(), &hbuf, buffer, length,
                              &result, &herr);
    } while (ret == ERANGE);
    if (ret != 0) {
        ucs_error("gethostbyname_r() failed: %m");
        status = UCS_ERR_IO_ERROR;
        goto out_free_buffer;
    }

    *result_p = 0;
    if ((result != NULL) && (result->h_addrtype == ifaddr.sin_family)) {
        for (addr_p = result->h_addr_list; *addr_p != NULL; ++addr_p) {
            if (!memcmp(*addr_p, &ifaddr.sin_addr, sizeof(ifaddr.sin_addr))) {
                *result_p = 1;
                break;
            }
        }
    }
    status = UCS_OK;

out_free_buffer:
    ucs_free(buffer);
out:
    return status;
}

ucs_status_t uct_tcp_send(int fd, const void *data, size_t length)
{
    ssize_t ret;

    for (;;) {
        ret = send(fd, data, length, 0);
        if (ret == length) {
            return UCS_OK;
        } else if (ret < 0) {
            ucs_error("sendto() failed: %m"); // TODO: handle nonblocking
            return UCS_ERR_IO_ERROR;
        } else {
            data   += ret;
            length -= ret;
        }
    }
}

ucs_status_t uct_tcp_recv(int fd, void *data, size_t length)
{
    ssize_t ret;

    for (;;) {
        ret = recv(fd, data, length, 0);
        if (ret == length) {
            return UCS_OK;
        } else if (ret < 0) {
            ucs_error("recvfrom() failed: %m"); // TODO: handle nonblocking
            return UCS_ERR_IO_ERROR;
        } else {
            data   += ret;
            length -= ret;
        }
    }
}

static int uct_tcp_sockaddr_hash(int fd)
{
    return 0;
}

static int uct_tcp_sockaddr_equal(int fd1, int fd2)
{
    return 0;
}

__KHASH_IMPL(uct_tcp_fd_hash, , int, char, 0, uct_tcp_sockaddr_hash,
           uct_tcp_sockaddr_equal)
