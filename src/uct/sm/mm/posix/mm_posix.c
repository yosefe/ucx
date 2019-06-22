/**
 * Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 * Copyright (C) ARM Ltd. 2016.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#include <uct/sm/mm/base/mm_md.h>
#include <uct/sm/mm/base/mm_iface.h>
#include <ucs/debug/memtrack.h>
#include <ucs/debug/log.h>
#include <sys/mman.h>
#include <ucs/sys/sys.h>


#define UCT_MM_POSIX_SHM_OPEN_MODE  (0666)
#define UCT_MM_POSIX_CREATE_FLAGS   (O_CREAT | O_EXCL)
#define UCT_MM_POSIX_MMAP_PROT      (PROT_READ | PROT_WRITE)
#define UCT_MM_POSIX_HUGETLB        UCS_BIT(0)
#define UCT_MM_POSIX_SHM_OPEN       UCS_BIT(1)
#define UCT_MM_POSIX_PROC_LINK      UCS_BIT(2)
#define UCT_MM_POSIX_CTRL_BITS      3
#define UCT_MM_POSIX_FD_BITS        29
#define UCT_MM_POSIX_PID_BITS       32
#define UCT_MM_POSIX_SHM_OPEN_DIR   "/dev/shm"

typedef struct uct_posix_md_config {
    uct_mm_md_config_t      super;
    char                    *path;
    int                     use_proc_link;
} uct_posix_md_config_t;

typedef struct uct_mm_posix_seg {
    uct_mm_seg_t            super;
    char                    path[0];
} uct_mm_posix_seg_t;

typedef struct uct_mm_posix_packed_rkey {
    uct_mm_packed_rkey_t    super;
    char                    path[0];
} uct_mm_posix_packed_rkey_t;

typedef struct uct_posix_remote_seg {
    void                    *attach_address;
    size_t                  length;
} uct_posix_remote_seg_t;


static ucs_config_field_t uct_posix_md_config_table[] = {
  {"MM_", "", NULL,
   ucs_offsetof(uct_posix_md_config_t, super), UCS_CONFIG_TYPE_TABLE(uct_mm_md_config_table)},

  {"DIR", UCT_MM_POSIX_SHM_OPEN_DIR,
   "The path to the backing file. If it's equal to " UCT_MM_POSIX_SHM_OPEN_DIR " then \n"
   "shm_open() is used. Otherwise, open() is used.",
   ucs_offsetof(uct_posix_md_config_t, path), UCS_CONFIG_TYPE_STRING},

  {"USE_PROC_LINK", "y", "Use /proc/<pid>/fd/<fd> to share posix file.\n"
   " y   - Use /proc/<pid>/fd/<fd> to share posix file.\n"
   " n   - Use original file path to share posix file.\n",
   ucs_offsetof(uct_posix_md_config_t, use_proc_link), UCS_CONFIG_TYPE_BOOL},

  {NULL}
};

static int uct_posix_use_shm_open(const uct_posix_md_config_t *posix_config)
{
    return !strcmp(posix_config->path, UCT_MM_POSIX_SHM_OPEN_DIR);
}

static ucs_status_t uct_posix_md_query(uct_md_h md, uct_md_attr_t *md_attr)
{
    uct_mm_md_query(md, md_attr, 1);
    return UCS_OK;
}

static ucs_status_t uct_posix_test_mem(int shm_fd, size_t length)
{
    const size_t chunk_size = 16 * 1024;
    size_t size_to_write, remaining;
    ssize_t single_write;
    ucs_status_t status;
    int *buf;

    buf = ucs_malloc(chunk_size, "write buffer");
    if (buf == NULL) {
        ucs_error("Failed to allocate memory for testing space for backing file.");
        status = UCS_ERR_NO_MEMORY;
        goto out;
    }

    memset(buf, 0, chunk_size);
    if (lseek(shm_fd, 0, SEEK_SET) < 0) {
        ucs_error("lseek failed. %m");
        status = UCS_ERR_IO_ERROR;
        goto out_free_buf;
    }

    remaining = length;
    while (remaining > 0) {
        size_to_write = ucs_min(remaining, chunk_size);
        single_write = write(shm_fd, buf, size_to_write);

        if (single_write < 0) {
            switch(errno) {
            case ENOSPC:
                ucs_error("Not enough memory to write total of %zu bytes. "
                          "Please check that /dev/shm or the directory you specified has "
                          "more available memory.", length);
                status = UCS_ERR_NO_MEMORY;
                break;
            default:
                ucs_error("Failed to write %zu bytes. %m", size_to_write);
                status = UCS_ERR_IO_ERROR;
            }
            goto out_free_buf;
        }

        remaining -= single_write;
    }

    status = UCS_OK;

out_free_buf:
    ucs_free(buf);
out:
    return status;
}

static ucs_status_t
uct_posix_make_file_path(const char *path, const char *file_name,
                         char **file_path_p)
{
    char *file_path;
    size_t path_len;

    ucs_assert(file_name[0] == '/');

    path_len  = strlen(path) + strlen(file_name) + 1;
    file_path = ucs_malloc(path_len, "posix_path");
    if (file_path == NULL) {
        return UCS_ERR_NO_MEMORY;
    }

    snprintf(file_path, path_len, "%s%s", path, file_name);
    *file_path_p = file_path;
    return UCS_OK;
}

static ucs_status_t uct_posix_shm_open(const char *file_name, int flags,
                                       int *shm_fd_p)
{
    int fd = shm_open(file_name, flags | O_RDWR, UCT_MM_POSIX_SHM_OPEN_MODE);
    if (fd < 0) {
        ucs_error("shared memory shm_open(file_name=%s) failed: %m", file_name);
        return UCS_ERR_SHMEM_SEGMENT;
    }

    *shm_fd_p = fd;
    return UCS_OK;
}

static ucs_status_t uct_posix_path_open(const char *path, const char *file_name,
                                        int flags, int *shm_fd_p)
{
    ucs_status_t status;
    char *file_path;
    int fd;

    status = uct_posix_make_file_path(path, file_name, &file_path);
    if (status != UCS_OK) {
        return status;
    }

    fd = open(file_path, flags | O_RDWR, UCT_MM_POSIX_SHM_OPEN_MODE);
    if (fd < 0) {
        ucs_error("shared memory open(file_path=%s) failed: %m", file_path);
        status = UCS_ERR_SHMEM_SEGMENT;
    } else {
        *shm_fd_p = fd;
        status    = UCS_OK;
    }

    ucs_free(file_path);
    return status;
}

static ucs_status_t uct_posix_unlink(const char *path, const char *file_name)
{
    ucs_status_t status = UCS_OK;
    char *file_path;
    int ret;

    if (path == NULL) {
        ret = shm_unlink(file_name);
        if (ret < 0) {
            ucs_error("shm_unlink(file_name=%s) failed: %m", file_name);
            status = UCS_ERR_SHMEM_SEGMENT;
        }
    } else {
        status = uct_posix_make_file_path(path, file_name, &file_path);
        if (status != UCS_OK) {
            goto out;
        }

        ret = unlink(file_path);
        if (ret < 0) {
            ucs_error("unlink(file_name=%s) failed: %m", file_path);
            status = UCS_ERR_SHMEM_SEGMENT;
        }

        ucs_free(file_path);
    }

out:
    return status;
}

static void uct_posix_get_file_name(char *file_name, size_t max,
                                       uint64_t uuid)
{
    snprintf(file_name, max, "/ucx_posix_mm_%s_%s_%016lx", ucs_get_user_name(),
             ucs_get_host_name(), uuid);
}

static ucs_status_t uct_posix_mmap(void *address, size_t length, int flags,
                                   int fd, const char *alloc_name, int show_err,
                                   void **address_p)
{
    void *result;

    result = ucs_mmap(address, length, UCT_MM_POSIX_MMAP_PROT,
                      MAP_SHARED | flags, fd, 0 UCS_MEMTRACK_VAL);
    if (result == MAP_FAILED) {
       ucs_log(show_err ? UCS_LOG_LEVEL_ERROR : UCS_LOG_LEVEL_DEBUG,
               "shared memory mmap(addr=%p, length=%zu, flags=%s%s, fd=%d) failed: %m",
               address, length,
               (flags & MAP_FIXED)   ? " FIXED"   : "",
#ifdef MAP_HUGETLB
               (flags & MAP_HUGETLB) ? " HUGETLB" : "",
#else
               "",
#endif
               fd);
       return UCS_ERR_SHMEM_SEGMENT;
    }

    *address_p = result;
    return UCS_OK;
}

static ucs_status_t uct_posix_munmap(void *address, size_t length)
{
    int ret;

    ret = ucs_munmap(address, length);
    if (ret != 0) {
        ucs_warn("shared memory munmap(address=%p, length=%zu) failed: %m",
                 address, length);
        return UCS_ERR_SHMEM_SEGMENT;
    }

    return UCS_OK;
}

static ucs_status_t
uct_posix_mem_alloc(uct_md_h md, size_t *length_p, void **address_p,
                    unsigned flags, const char *alloc_name, uct_mem_h *memh_p)
{
    uct_mm_md_t *mm_md                  = ucs_derived_of(md, uct_mm_md_t);
    uct_posix_md_config_t *posix_config = ucs_derived_of(mm_md->config,
                                                         uct_posix_md_config_t);
    uint64_t file_uuid, mmid, mmid_uuid, mmid_flags;
    void *mmap_address, *address;
    char file_name[NAME_MAX];
    uct_mm_posix_seg_t *seg;
    ucs_status_t status;
    int force_hugetlb;
    size_t path_size;
    int mmap_flags;
    int shm_fd;
    char *path;

    if (0 == *length_p) {
        ucs_error("invalid length %zu", *length_p);
        status = UCS_ERR_INVALID_PARAM;
        goto err;
    }

    /* Generate a 64 bit uuid.
     * use 61 bits of it for creating the file_name of the backing file.
     * other 2 bits:
     * 1 bit is for indicating whether or not hugepages were used.
     * 1 bit is for indicating whether or not shm_open() was used.
     * 1 bit is for indicating whether or not /proc/<pid>/fd/<fd> was used. */
    mmid_flags = 0;
    file_uuid  = ucs_generate_uuid(0);

    uct_posix_get_file_name(file_name, sizeof(file_name) - 1, file_uuid);

    if (uct_posix_use_shm_open(posix_config)) {
        status = uct_posix_shm_open(file_name, UCT_MM_POSIX_CREATE_FLAGS,
                                    &shm_fd);
        if (status != UCS_OK) {
            /* shm_open was requested, and failed */
            goto err;
        }

        mmid_flags |= UCT_MM_POSIX_SHM_OPEN;
        path        = NULL;
        path_size   = 0;
    } else {
        status = uct_posix_path_open(posix_config->path, file_name,
                                UCT_MM_POSIX_CREATE_FLAGS, &shm_fd);
        if (status != UCS_OK) {
            goto err;
        }

        path       = posix_config->path;
        path_size  = strlen(posix_config->path + 1);
    }

    /* Remove the original file, to use the symlink in procfs  */
    if (posix_config->use_proc_link) {
        status = uct_posix_unlink(path, file_name);
        if (status != UCS_OK) {
            goto err_close;
        }

        /* Here we encoded fd into uuid using 29 bits, which
         * is less than 32 bits (one integer), so there are
         * 3 bits lost. We make sure here the encoded fd equals
         * to the original fd. If they are not equal, which means
         * 29 bits is not enough for fd, we need proper solutions
         * to deal with it. */
        mmid_uuid   = ((uint64_t)getpid() << UCT_MM_POSIX_FD_BITS) | shm_fd;
        mmid_flags |= UCT_MM_POSIX_PROC_LINK;
    } else {
        mmid_uuid   = file_uuid;
    }

    /* Check is the location of the backing file has enough memory for the
     * needed size by trying to write there before calling mmap */
    status = uct_posix_test_mem(shm_fd, *length_p);
    if (status != UCS_OK) {
        goto err_close;
    }

    /* mmap the shared memory segment that was created by shm_open */

    if (flags & UCT_MD_MEM_FLAG_FIXED) {
        mmap_address = *address_p;
        mmap_flags   = MAP_FIXED;
    } else {
        mmap_address = NULL;
        mmap_flags   = 0;
    }

    /* try HUGETLB mmap */
    address = MAP_FAILED;
    if (posix_config->super.hugetlb_mode != UCS_NO) {
        force_hugetlb = (posix_config->super.hugetlb_mode == UCS_YES);
#ifdef MAP_HUGETLB
        status = uct_posix_mmap(mmap_address, *length_p, mmap_flags | MAP_HUGETLB,
                                shm_fd, alloc_name, force_hugetlb, &address);
#else
        status = UCS_ERR_SHMEM_SEGMENT;
        if (force_hugetlb) {
            ucs_error("shared memory allocation failed: "
                      "MAP_HUGETLB is not supported on the system");
        }
#endif
        if ((status != UCS_OK) && force_hugetlb) {
            goto err_close;
        } else if (status == UCS_OK) {
           mmid_flags |= UCT_MM_POSIX_HUGETLB;
       }
    }

    /* fallback to regular mmap */
    if (address == MAP_FAILED) {
        ucs_assert(posix_config->super.hugetlb_mode != UCS_YES);
        status = uct_posix_mmap(mmap_address, *length_p, mmap_flags, shm_fd,
                                alloc_name, 1, &address);
        if (status != UCS_OK) {
            goto err_close;
        }
    }

    if (flags & UCT_MD_MEM_FLAG_FIXED) {
        ucs_assert(address == *address_p);
    }

    /* create new memory segment */
    mmid   = mmid_flags | (mmid_uuid << UCT_MM_POSIX_CTRL_BITS);
    status = uct_mm_md_mem_seg_new(sizeof(*seg) + path_size, mmid, address,
                                   *length_p, (uct_mm_seg_t**)&seg);
    if (status != UCS_OK) {
        goto err_munmap;
    }

    ucs_debug("allocated posix shared memory at %p length %zu", address,
              *length_p);

    memcpy(seg->path, path, path_size);
    *address_p = address;
    *memh_p    = seg;

    if (!posix_config->use_proc_link) {
        close(shm_fd); /* closing the shm_fd here won't unmap the mem region*/
    }

    return UCS_OK;

err_munmap:
    uct_posix_munmap(address, *length_p);
err_close:
    close(shm_fd);
    if (!posix_config->use_proc_link) {
        uct_posix_unlink(path, file_name);
    }
err:
    return status;
}

static ucs_status_t uct_posix_mem_free(uct_md_h md, uct_mem_h memh)
{
    uct_mm_posix_seg_t *seg  = memh;
    uct_mm_id_t         mmid = seg->super.mmid;
    ucs_status_t status;
    char file_name[NAME_MAX];
    int fd;

    status = uct_posix_munmap(seg->super.address, seg->super.length);
    if (status != UCS_OK) {
        return status;
    }

    if (mmid & UCT_MM_POSIX_PROC_LINK) {
        fd = (mmid >> UCT_MM_POSIX_CTRL_BITS) & UCS_MASK(UCT_MM_POSIX_FD_BITS);
        close(fd);
    } else {
        uct_posix_get_file_name(file_name, sizeof(file_name) - 1,
                                   mmid >> UCT_MM_POSIX_CTRL_BITS);
        status = uct_posix_unlink(seg->path, file_name);
        if (status != UCS_OK) {
            return status;
        }
    }

    ucs_free(seg);
    return UCS_OK;
}

static ucs_status_t
uct_posix_rkey_unpack(uct_component_t *component, const void *rkey_buffer,
                      uct_rkey_t *rkey_p, void **handle_p)
{
    const uct_mm_posix_packed_rkey_t *packed_rkey = rkey_buffer;
    uct_mm_id_t                       mmid        = packed_rkey->super.mmid;
    uint64_t                          mmid_uuid   = mmid >> UCT_MM_POSIX_CTRL_BITS;
    uct_posix_remote_seg_t *rseg;
    char file_name[NAME_MAX];
    ucs_status_t status;
    int mmap_flags;
    int shm_fd;

    rseg = ucs_malloc(sizeof(*rseg), "posix_remote_seg");
    if (rseg == NULL) {
        ucs_error("failed to allocate posix remote segment descriptor");
        status = UCS_ERR_NO_MEMORY;
        goto err;
    }

    mmid_uuid = mmid >> UCT_MM_POSIX_CTRL_BITS;
    if (mmid & UCT_MM_POSIX_PROC_LINK) {
        snprintf(file_name, sizeof(file_name), "/%ld/fd/%ld",
                 /* pid */ mmid_uuid >> UCT_MM_POSIX_FD_BITS,
                 /* fd  */ mmid_uuid &  UCS_MASK(UCT_MM_POSIX_FD_BITS));
        status = uct_posix_path_open("/proc", file_name, 0, &shm_fd);
    } else {
        uct_posix_get_file_name(file_name, sizeof(file_name), mmid_uuid);
        if (mmid & UCT_MM_POSIX_SHM_OPEN) {
            status = uct_posix_shm_open(file_name, 0, &shm_fd);
        } else {
            status = uct_posix_path_open(packed_rkey->path, file_name, 0,
                                         &shm_fd);
        }
    }
    if (status != UCS_OK) {
        goto err_free_rseg;
    }

#ifdef MAP_HUGETLB
    mmap_flags = (mmid & UCT_MM_POSIX_HUGETLB) ? MAP_HUGETLB : 0;
#else
    mmap_flags = 0;
#endif
    status = uct_posix_mmap(NULL, packed_rkey->super.length, mmap_flags, shm_fd,
                            "posix_attach", 1, &rseg->attach_address);
    if (status != UCS_OK) {
        goto err_close_fd;
    }

    ucs_trace("attached remote segment '%s' remote_address 0x%lx at address %p",
              file_name, packed_rkey->super.owner_ptr, rseg->attach_address);

    uct_mm_md_make_rkey(rseg->attach_address, packed_rkey->super.owner_ptr,
                        rkey_p);
    rseg->length = packed_rkey->super.length;
    *handle_p    = rseg;
    close(shm_fd); /* closing the fd here won't unmap the mem region */
    return UCS_OK;

err_close_fd:
    close(shm_fd);
err_free_rseg:
    ucs_free(rseg);
err:
    return status;
}

static void
uct_posix_rkey_release(uct_component_t *component, uct_rkey_t rkey, void *handle)
{
    uct_posix_remote_seg_t *rseg = handle;
    ucs_status_t status;

    status = uct_posix_munmap(rseg->attach_address, rseg->length);
    if (status != UCS_OK) {
        return;
    }

    ucs_free(rseg);
}

static ucs_status_t
uct_posix_mkey_pack(uct_md_h md, uct_mem_h memh, void *rkey_buffer)
{
    uct_mm_posix_packed_rkey_t *packed_rkey = rkey_buffer;
    uct_mm_posix_seg_t *seg = memh;

    (void)uct_mm_mkey_pack(md, memh, rkey_buffer); // TODO base function
    if (seg->path) {
        strcpy(packed_rkey->path, seg->path);
    }

    return UCS_OK;
}

static size_t uct_posix_rkey_extra_size(const uct_mm_md_config_t *config)
{
    const uct_posix_md_config_t *posix_config =
                    ucs_derived_of(config, uct_posix_md_config_t);

    /* if shm_open is requested, the path to the backing file is /dev/shm
     * by default. however, if shm_open isn't used, the size of the path to the
     * requested backing file is needed so that the user would know how much
     * space to allocated for the rkey.
     */
    return uct_posix_use_shm_open(posix_config) ? 0 :
           strlen(posix_config->path) + 1;
}

static uct_mm_md_ops_t uct_posix_md_ops = {
   .super = {
        .close                  = uct_mm_md_close,
        .query                  = uct_posix_md_query,
        .mem_alloc              = uct_posix_mem_alloc,
        .mem_free               = uct_posix_mem_free,
        .mem_advise             = (void*)ucs_empty_function_return_unsupported,
        .mem_reg                = (void*)ucs_empty_function_return_unsupported,
        .mem_dereg              = (void*)ucs_empty_function_return_unsupported,
        .mkey_pack              = uct_posix_mkey_pack,
        .is_sockaddr_accessible = (void*)ucs_empty_function_return_zero,
        .detect_memory_type     = (void*)ucs_empty_function_return_unsupported
    },
   .is_supported                = ucs_empty_function_return_one,
   .rkey_extra_size             = uct_posix_rkey_extra_size,
};

UCT_MM_TL_DEFINE(posix, &uct_posix_md_ops, uct_posix_rkey_unpack,
                 uct_posix_rkey_release, "POSIX_")
