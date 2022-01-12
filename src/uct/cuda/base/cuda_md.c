/**
 * Copyright (C) Mellanox Technologies Ltd. 2018.  ALL RIGHTS RESERVED.
 * Copyright (c) 2019, NVIDIA CORPORATION. All rights reserved.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "cuda_md.h"
#include "cuda_iface.h"

#include <ucs/sys/module.h>
#include <ucs/sys/string.h>
#include <ucs/type/spinlock.h>
#include <ucs/profile/profile.h>
#include <ucs/debug/log.h>
#include <cuda_runtime.h>

#define UCT_CUDA_DEV_NAME_MAX_LEN 64
#define UCT_CUDA_MAX_DEVICES      32


ucs_status_t uct_cuda_base_get_sys_dev(CUdevice cuda_device,
                                       ucs_sys_device_t *sys_dev_p)
{
    ucs_sys_bus_id_t bus_id;
    CUresult cu_err;
    int attrib;

    /* PCI domain id */
    cu_err = cuDeviceGetAttribute(&attrib, CU_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID,
                                  cuda_device);
    if (cu_err != CUDA_SUCCESS) {
         return UCS_ERR_IO_ERROR;
    }
    bus_id.domain = (uint16_t)attrib;

    /* PCI bus id */
    cu_err = cuDeviceGetAttribute(&attrib, CU_DEVICE_ATTRIBUTE_PCI_BUS_ID,
                                  cuda_device);
    if (cu_err != CUDA_SUCCESS) {
         return UCS_ERR_IO_ERROR;
    }
    bus_id.bus = (uint8_t)attrib;

    /* PCI slot id */
    cu_err = cuDeviceGetAttribute(&attrib, CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID,
                                  cuda_device);
    if (cu_err != CUDA_SUCCESS) {
         return UCS_ERR_IO_ERROR;
    }
    bus_id.slot = (uint8_t)attrib;

    /* Function - always 0 */
    bus_id.function = 0;

    return ucs_topo_find_device_by_bus_id(&bus_id, sys_dev_p);
}

size_t uct_cuda_base_get_total_device_mem(CUdevice cuda_device)
{
    static size_t total_bytes[UCT_CUDA_MAX_DEVICES];
    char dev_name[UCT_CUDA_DEV_NAME_MAX_LEN];
    const char *cu_err_str;
    size_t total_mem;
    CUresult cu_err;

    ucs_assert(cuda_device < UCT_CUDA_MAX_DEVICES);

    total_mem = total_bytes[cuda_device];
    if (total_mem > 0) {
        return total_mem;
    }

    cu_err = cuDeviceGetName(dev_name, sizeof(dev_name), cuda_device);
    if (cu_err != CUDA_SUCCESS) {
        cuGetErrorString(cu_err, &cu_err_str);
        ucs_warn("cuDeviceGetName(device=%d) failed: %s", cuda_device,
                 cu_err_str);
        total_mem = 1;
        goto out;
    }

    if (!strncmp(dev_name, "T4", 2)) {
        /* Ensure that whole alloc registration is not used for t4 */
        total_mem = 1;
    } else {
        cu_err = cuDeviceTotalMem(&total_mem, cuda_device);
        if (cu_err != CUDA_SUCCESS) {
            cuGetErrorString(cu_err, &cu_err_str);
            ucs_warn("cuDeviceTotalMem(device=%d) failed: %s", cuda_device,
                     cu_err_str);
            total_mem = 1;
            goto out;
        }
    }

out:
    total_bytes[cuda_device] = total_mem;
    return total_mem;
}

ucs_status_t
uct_cuda_base_query_md_resources(uct_component_t *component,
                                 uct_md_resource_desc_t **resources_p,
                                 unsigned *num_resources_p)
{
    ucs_sys_device_t sys_dev;
    CUdevice cuda_device;
    cudaError_t cudaErr;
    ucs_status_t status;
    char device_name[10];
    int num_gpus;

    cudaErr = cudaGetDeviceCount(&num_gpus);
    if ((cudaErr != cudaSuccess) || (num_gpus == 0)) {
        return uct_md_query_empty_md_resource(resources_p, num_resources_p);
    }

    for (cuda_device = 0; cuda_device < num_gpus; ++cuda_device) {
        status = uct_cuda_base_get_sys_dev(cuda_device, &sys_dev);
        if (status == UCS_OK) {
            ucs_snprintf_safe(device_name, sizeof(device_name), "GPU%d",
                              cuda_device);
            status = ucs_topo_sys_device_set_name(sys_dev, device_name);
            ucs_assert_always(status == UCS_OK);
        }
    }

    return uct_md_query_single_md_resource(component, resources_p,
                                           num_resources_p);
}

UCS_MODULE_INIT() {
    /* TODO make gdrcopy independent of cuda */
    UCS_MODULE_FRAMEWORK_DECLARE(uct_cuda);
    UCS_MODULE_FRAMEWORK_LOAD(uct_cuda, 0);
    return UCS_OK;
}
