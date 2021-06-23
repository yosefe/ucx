/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
* Copyright (C) Shanghai Zhaoxin Semiconductor Co., Ltd. 2020. ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include "ucx_info.h"

#include <ucs/sys/sys.h>
#include <ucs/sys/math.h>
#include <ucs/time/time.h>
#include <ucs/config/parser.h>
#include <ucs/config/global_opts.h>
#include <sys/mman.h>
#include <string.h>

#ifdef HAVE_CUDA
#include <cuda.h>
#include <cuda_runtime.h>
#endif


static const char* cpu_model_names[] = {
    [UCS_CPU_MODEL_UNKNOWN]            = "unknown",
    [UCS_CPU_MODEL_INTEL_IVYBRIDGE]    = "IvyBridge",
    [UCS_CPU_MODEL_INTEL_SANDYBRIDGE]  = "SandyBridge",
    [UCS_CPU_MODEL_INTEL_NEHALEM]      = "Nehalem",
    [UCS_CPU_MODEL_INTEL_WESTMERE]     = "Westmere",
    [UCS_CPU_MODEL_INTEL_HASWELL]      = "Haswell",
    [UCS_CPU_MODEL_INTEL_BROADWELL]    = "Broadwell",
    [UCS_CPU_MODEL_INTEL_SKYLAKE]      = "Skylake",
    [UCS_CPU_MODEL_ARM_AARCH64]        = "ARM 64-bit",
    [UCS_CPU_MODEL_AMD_NAPLES]         = "Naples",
    [UCS_CPU_MODEL_AMD_ROME]           = "Rome",
    [UCS_CPU_MODEL_ZHAOXIN_ZHANGJIANG] = "Zhangjiang",
    [UCS_CPU_MODEL_ZHAOXIN_WUDAOKOU]   = "Wudaokou",
    [UCS_CPU_MODEL_ZHAOXIN_LUJIAZUI]   = "Lujiazui"
};

static const char* cpu_vendor_names[] = {
    [UCS_CPU_VENDOR_UNKNOWN]          = "unknown",
    [UCS_CPU_VENDOR_INTEL]            = "Intel",
    [UCS_CPU_VENDOR_AMD]              = "AMD",
    [UCS_CPU_VENDOR_GENERIC_ARM]      = "Generic ARM",
    [UCS_CPU_VENDOR_GENERIC_PPC]      = "Generic PPC",
    [UCS_CPU_VENDOR_FUJITSU_ARM]      = "Fujitsu ARM",
    [UCS_CPU_VENDOR_ZHAOXIN]          = "Zhaoxin"
};

#ifdef HAVE_CUDA
static cudaStream_t g_cuda_stream;
static cudaEvent_t g_cuda_event;
#endif

static void *mem_alloc(ucs_memory_type_t mem_type, size_t size)
{
#ifdef HAVE_CUDA
    unsigned sync_atr_value = 1;
    cudaError_t cu_err;
#endif
    void *ptr;
    int ret;

    switch (mem_type) {
    case UCS_MEMORY_TYPE_HOST:
        size = ucs_align_up_pow2(size, ucs_get_huge_page_size());
        // ptr  = mmap(NULL, size, PROT_READ | PROT_WRITE,
        //             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ptr = NULL;
        ret  = posix_memalign(&ptr, ucs_get_huge_page_size(), size);
        if (ret != 0) {
            return NULL;
        }
        madvise(ptr, size, MADV_HUGEPAGE);
        memset(ptr, 'h', size);
#ifdef HAVE_CUDA
        cu_err = cudaHostRegister(ptr, size, cudaHostRegisterPortable);
        if (cu_err != cudaSuccess) {
            fprintf(stderr, "cudaHostRegister failed: %d\n", cu_err);
        }
#endif
        return ptr;
#ifdef HAVE_CUDA
    case UCS_MEMORY_TYPE_CUDA:
        cu_err = cudaMalloc(&ptr, size);
        if (cu_err != cudaSuccess) {
            return NULL;
        }

        cuPointerSetAttribute(&sync_atr_value, CU_POINTER_ATTRIBUTE_SYNC_MEMOPS,
                              (uintptr_t)ptr);
        cudaMemset(ptr, 'c', size);
        return ptr;
#endif
    default:
        return NULL;
    }
}

static void mem_free(ucs_memory_type_t mem_type, void *ptr, size_t size)
{
    if (ptr == NULL) {
        return;
    }

    switch (mem_type) {
    case UCS_MEMORY_TYPE_HOST:
        size = ucs_align_up_pow2(size, ucs_get_page_size());
#ifdef HAVE_CUDA
        cudaHostUnregister(ptr);
#endif
        munmap(ptr, size);
        break;
#ifdef HAVE_CUDA
    case UCS_MEMORY_TYPE_CUDA:
        cudaFree(ptr);
        break;
#endif
    default:
        break;
    }
}

static int is_mem_type_supported(ucs_memory_type_t mem_type)
{
    void *ptr;

    ptr = mem_alloc(mem_type, 1);
    if (ptr == NULL) {
        return 0;
    }

    mem_free(mem_type, ptr, 1);
    return 1;
}

#ifdef HAVE_CUDA
static void
cuda_mem_copy(void *dst, const void *src, size_t size, enum cudaMemcpyKind kind)
{
    const int n_par = 4;
    cudaError_t cu_err;
    size_t start, end;
    int i;

    if (0) {
        cudaMemcpy(dst, src, size, kind);
        cudaDeviceSynchronize();
    } else {
        for (i = 0; i < n_par; ++i) {
            start = (i * size) / n_par;
            end   = ((i + 1) * size) / n_par;
            cu_err = cudaMemcpyAsync(dst + start, src + start, end - start,
                                     kind, g_cuda_stream);
            if (cu_err != cudaSuccess) {
                fprintf(stderr, "cuda copy failed status %d\n", cu_err);
                return;
            }
        }
        cudaEventRecord(g_cuda_event, g_cuda_stream);
        while (cudaEventQuery(g_cuda_event) != cudaSuccess)
            ;
    }
}
#endif

static void mem_copy(void *dst, ucs_memory_type_t dst_mem_type,
                     const void *src, ucs_memory_type_t src_mem_type,
                     size_t size)
{
    if ((dst_mem_type == UCS_MEMORY_TYPE_HOST) &&
        (src_mem_type == UCS_MEMORY_TYPE_HOST)) {
        ucs_memcpy_relaxed(dst, src, size);
        return;
    }
#ifdef HAVE_CUDA
    if ((dst_mem_type == UCS_MEMORY_TYPE_CUDA) &&
        (src_mem_type == UCS_MEMORY_TYPE_HOST)) {
        cuda_mem_copy(dst, src, size, cudaMemcpyHostToDevice);
        return;
    }
    if ((dst_mem_type == UCS_MEMORY_TYPE_HOST) &&
        (src_mem_type == UCS_MEMORY_TYPE_CUDA)) {
        cuda_mem_copy(dst, src, size, cudaMemcpyDeviceToHost);
        return;
    }
    if ((dst_mem_type == UCS_MEMORY_TYPE_CUDA) &&
        (src_mem_type == UCS_MEMORY_TYPE_CUDA)) {
        cuda_mem_copy(dst, src, size, cudaMemcpyDeviceToDevice);
        return;
    }
#endif
}

static double measure_memcpy_time(ucs_memory_type_t src_mem_type,
                                  ucs_memory_type_t dst_mem_type,
                                  size_t size)
{
    ucs_time_t start_time, end_time;
    void *src, *dst;
    double result = 0.0;
    double st;
    int iter;

    src = mem_alloc(src_mem_type, size);
    if (src == NULL) {
        goto out;
    }

    dst = mem_alloc(dst_mem_type, size);
    if (dst == NULL) {
        goto out_free_src;
    }

    /* warmup */
    mem_copy(dst, dst_mem_type, src, src_mem_type, size);

    iter = 0;
    start_time = ucs_get_time();
    st = ucs_get_accurate_time();
    do {
        mem_copy(dst, dst_mem_type, src, src_mem_type, size);
        end_time = ucs_get_time();
        ++iter;
    } while (end_time < start_time + ucs_time_from_sec(0.5));
    // result = ucs_time_to_sec(end_time - start_time) / iter;
    result = (ucs_get_accurate_time() - st) / iter;

    mem_free(dst_mem_type, dst, size);
out_free_src:
    mem_free(src_mem_type, src, size);
out:
    return result;
}

static void print_memcpy_performance(ucs_memory_type_t src_mem_type,
                                     ucs_memory_type_t dst_mem_type,
                                     size_t max_size)
{
    double time, bw_mbps;
    size_t size;

    printf("# Memcpy %s -> %s:\n",
           ucs_memory_type_names[src_mem_type],
           ucs_memory_type_names[dst_mem_type]);
    printf("%13s %16s %16s\n", "SIZE", "TIME (sec)", "BANDWIDTH (MB/s)");

    for (size = 4096; size <= max_size; size *= 2) {
        time    = measure_memcpy_time(src_mem_type, dst_mem_type, size);
        bw_mbps = (size / time) / UCS_MBYTE;
        printf("%13zu %16e %16.3f\n", size, time, bw_mbps);
    }

    printf("\n");
}

void print_sys_info()
{
#if HAVE_CUDA
    cudaStreamCreateWithFlags(&g_cuda_stream, cudaStreamNonBlocking);
    cudaEventCreateWithFlags(&g_cuda_event, cudaEventDisableTiming);
#endif
    printf("# Timer frequency: %.3f MHz\n", ucs_get_cpu_clocks_per_sec() / 1e6);
    printf("# CPU vendor: %s\n", cpu_vendor_names[ucs_arch_get_cpu_vendor()]);
    printf("# CPU model: %s\n", cpu_model_names[ucs_arch_get_cpu_model()]);
    ucs_arch_print_memcpy_limits(&ucs_global_opts.arch);

    // print_memcpy_performance(UCS_MEMORY_TYPE_HOST, UCS_MEMORY_TYPE_HOST,
    //                          256 * UCS_MBYTE);
    if (is_mem_type_supported(UCS_MEMORY_TYPE_CUDA)) {
        print_memcpy_performance(UCS_MEMORY_TYPE_HOST, UCS_MEMORY_TYPE_CUDA,
                                 256 * UCS_MBYTE);
        print_memcpy_performance(UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_HOST,
                                 256 * UCS_MBYTE);
        // print_memcpy_performance(UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_CUDA,
        //                          4 * UCS_GBYTE);
    }
}
