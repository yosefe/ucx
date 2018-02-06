/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ucp/api/ucp.h>
#include <infiniband/verbs.h>
#include <infiniband/verbs_exp.h>
#include <sys/mman.h>
#ifdef SHMEM
#include <shmem.h>
#else
#define shmem_my_pe() getpid()
#endif

enum {
    MODE_SHMEM,
    MODE_UCX,
    MODE_VERBS,
    MODE_MEM
};

int main(int argc, char **argv)
{
    int mode = MODE_UCX;

    ucp_mem_advise_params_t madv_params;
    ucp_mem_map_params_t mem_params;
    ucp_mem_attr_t mem_attr;
    ucp_config_t *ucp_config;
    ucp_params_t ucp_params;
    ucs_status_t status;
    ucp_context_h ucph;
    ucp_mem_h ucp_memh;

    void *buffer = NULL;
    size_t size  = 4ul * 1024 * 1024 * 1024;  /* 6 GBytes */
    int iter = 1000;
    int i, ret, j;
    size_t offset;

    const char ibv_device_name[] = "mlx5_0";
    struct ibv_exp_reg_mr_in ibv_mr_in;
    struct ibv_exp_prefetch_attr ibv_pf_in;
    struct ibv_device **ibv_device_list;
    struct ibv_context *ibv_context = NULL;
    struct ibv_pd *ibv_pd = NULL;
    struct ibv_mr *ibv_mr;
    int ibv_num_devices;
    int odp = 1;
    int rand_mem = 0;

    void *ptr;

#ifdef SHMEM
    start_pes(0);
#endif

    if (argc >= 2) {
        if (!strcmp(argv[1], "shmem")) {
            mode = MODE_SHMEM;
        } else if (!strcmp(argv[1], "ucx")) {
            mode = MODE_UCX;
        } else if (!strcmp(argv[1], "verbs")) {
            mode = MODE_VERBS;
        } else if (!strcmp(argv[1], "verbs_pin")) {
            mode = MODE_VERBS;
            odp  = 0;
        } else if (!strcmp(argv[1], "mem")) {
            mode = MODE_MEM;
        } else if (!strcmp(argv[1], "mem_rand")) {
            mode = MODE_MEM;
            rand_mem = 1;
        } else {
            printf("invalid mode '%s'\n", argv[1]);
            return -1;
        }

        if (argc >= 3) {
            iter = atoi(argv[2]);
        }
    }

    if (mode == MODE_SHMEM) {
#ifdef SHMEM
        printf("PE %d allocating with SHMEM\n", shmem_my_pe());
#endif
    } else if (mode == MODE_UCX) {
        status = ucp_config_read(NULL,  NULL, &ucp_config);
        if (status != UCS_OK) {
            printf("ucp_config_read() failed\n");
            return -1;
        }

        /* disable shared memory/sysv allocation */
        ucp_config_modify(ucp_config, "TLS", "dc_x");

        ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES;
        ucp_params.features   = UCP_FEATURE_RMA;
        status = ucp_init(&ucp_params, ucp_config, &ucph);
        if (status != UCS_OK) {
            printf("ucp_init() failed\n");
            return -1;
        }

        ucp_config_release(ucp_config);
    } else if (mode == MODE_VERBS) {
        printf("PE %d allocating with Verbs\n", shmem_my_pe());

        ibv_device_list = ibv_get_device_list(&ibv_num_devices);
        if (ibv_device_list == NULL || ibv_num_devices == 0) {
            printf("ibv_get_device_list() failed: %m\n");
            return -1;
        }

        ibv_context = NULL;
        for (i = 0; i < ibv_num_devices; ++i) {
            if (!strcmp(ibv_device_list[i]->name, ibv_device_name)) {
                ibv_context = ibv_open_device(ibv_device_list[i]);
                if (ibv_context == NULL) {
                    printf("ibv_open_device() failed: %m\n");
                    return -1;
                }
                break;
            }
        }
        ibv_free_device_list(ibv_device_list);
        if (ibv_context == NULL) {
            printf("could not find '%s'\n", ibv_device_name);
            return -1;
        }

        ibv_pd = ibv_alloc_pd(ibv_context);
        if (ibv_pd == NULL) {
            printf("ibv_alloc_pd() failed: %m\n");
            return -1;
        }
    }

    for (i = 0; i < iter; ++i) {
        if (mode == MODE_SHMEM) {
    #ifdef SHMEM
            buffer = shmalloc(size);
    #endif
        } else if (mode == MODE_UCX) {
            printf("PE %d allocating with UCX\n", shmem_my_pe());

            mem_params.field_mask = UCP_MEM_MAP_PARAM_FIELD_FLAGS |
                                    UCP_MEM_MAP_PARAM_FIELD_LENGTH;
            mem_params.flags      = UCP_MEM_MAP_NONBLOCK |
                                    UCP_MEM_MAP_ALLOCATE;
            mem_params.length     = size;

            status = ucp_mem_map(ucph, &mem_params, &ucp_memh);
            if (status != UCS_OK) {
                printf("ucp_mem_map() failed\n");
                return -1;
            }

            mem_attr.field_mask = UCP_MEM_ATTR_FIELD_ADDRESS;
            status = ucp_mem_query(ucp_memh, &mem_attr);
            if (status != UCS_OK) {
                printf("ucp_mem_query() failed\n");
                return -1;
            }

            buffer = mem_attr.address;

            /* Start non-blocking prefetch */
            printf("PE %d prefetching\n", shmem_my_pe());
            madv_params.field_mask = UCP_MEM_ADVISE_PARAM_FIELD_ADDRESS |
                                     UCP_MEM_ADVISE_PARAM_FIELD_LENGTH |
                                     UCP_MEM_ADVISE_PARAM_FIELD_ADVICE;
            madv_params.address = buffer;
            madv_params.length  = size;
            madv_params.advice  = UCP_MADV_WILLNEED;
            status = ucp_mem_advise(ucph, ucp_memh, &madv_params);
            if (status != UCS_OK) {
                printf("ucp_mem_advise() failed\n");
                return -1;
            }
        } else if (mode == MODE_VERBS) {
            buffer = mmap(NULL, size, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (buffer == MAP_FAILED) {
                printf("mmap() failed: %m\n");
                return -1;
            }

            memset(&ibv_mr_in, 0, sizeof(ibv_mr_in));
            ibv_mr_in.pd           = ibv_pd;
            ibv_mr_in.addr         = buffer;
            ibv_mr_in.length       = size;
            ibv_mr_in.exp_access   = IBV_EXP_ACCESS_LOCAL_WRITE |
                                     IBV_EXP_ACCESS_REMOTE_WRITE |
                                     IBV_EXP_ACCESS_REMOTE_READ |
                                     IBV_EXP_ACCESS_REMOTE_ATOMIC;
            if (odp) {
                ibv_mr_in.exp_access |= IBV_EXP_ACCESS_ON_DEMAND;
            }
            ibv_mr_in.comp_mask    = 0;
            ibv_mr_in.create_flags = 0;

            ibv_mr = ibv_exp_reg_mr(&ibv_mr_in);
            if (ibv_mr == NULL) {
                printf("ibv_exp_reg_mr() failed: %m\n");
                return -1;
            }

            if (odp) {
                printf("PE %d prefetching\n", shmem_my_pe());
                ibv_pf_in.flags     = IBV_EXP_PREFETCH_WRITE_ACCESS;
                ibv_pf_in.addr      = buffer;
                ibv_pf_in.length    = size;
                ibv_pf_in.comp_mask = 0;
                ret = ibv_exp_prefetch_mr(ibv_mr, &ibv_pf_in);
                if (ret) {
                    printf("ibv_exp_prefetch_mr() returned %d: %m\n", ret);
                    return -1;
                }
            }
        } else if (mode == MODE_MEM) {
            buffer = mmap(NULL, size, PROT_READ|PROT_WRITE,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            if (buffer == MAP_FAILED) {
                printf("mmap() failed: %m\n");
                return -1;
            }

            if (rand_mem) {
                memset(buffer, 0, size);
                printf("PE %d random memory access\n", shmem_my_pe());
                for (j = 0; j < size * iter; ++j) {
                    offset = (rand() * size) / RAND_MAX;
                    if (offset >= size) {
                        offset = 0;
                    }
                    ptr = buffer + offset;
                    *(volatile char*)ptr = 'a';
                }
            } else {
                printf("PE %d page-offset access\n", shmem_my_pe());
                ptr = buffer;
                while (ptr < buffer + size) {
                    *(char*)ptr = 'a';
                    ptr += 4096;
                }
            }
        }

        printf("PE %d iteration %i allocated %zu bytes at %p\n", shmem_my_pe(),
               i, size, buffer);

        if (mode == MODE_SHMEM) {
    #ifdef SHMEM
            shfree(buffer);
    #endif
        } else if (mode == MODE_UCX) {
            ucp_mem_unmap(ucph, ucp_memh);
        } else if (mode == MODE_VERBS) {
            ibv_dereg_mr(ibv_mr);
            munmap(buffer, size);
        } else if (mode == MODE_MEM) {
            munmap(buffer, size);
        }
    }

    sleep(5);

    printf("PE %d cleaning up\n", shmem_my_pe());
    if (mode == MODE_UCX) {
        ucp_cleanup(ucph);
    } else if (mode == MODE_VERBS) {
        ibv_dealloc_pd(ibv_pd);
        ibv_close_device(ibv_context);
    }

#ifdef SHMEM
    shmem_finalize();
#endif
    return 0;
}
