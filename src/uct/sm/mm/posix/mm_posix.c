/**
 * Copyright (c) UT-Battelle, LLC. 2014-2015. ALL RIGHTS RESERVED.
 * Copyright (C) Mellanox Technologies Ltd. 2001-2015.  ALL RIGHTS RESERVED.
 * Copyright (C) ARM Ltd. 2016.  ALL RIGHTS RESERVED.
 * See file LICENSE for terms.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <uct/sm/mm/base/mm_md.h>
#include <uct/sm/mm/base/mm_iface.h>
#include <ucs/debug/memtrack.h>
#include <ucs/debug/log.h>
#include <ucs/sys/sys.h>
#include <ucs/sys/string.h>
#include <sys/mman.h>


/* file open flags */
#define UCT_POSIX_SHM_CREATE_FLAGS      (O_CREAT | O_EXCL | O_RDWR) /* shm create flags */
#define UCT_POSIX_SHM_OPEN_MODE         0600           /* shm open/create mode */

/* memory mapping parameters */
#define UCT_POSIX_MMAP_PROT             (PROT_READ | PROT_WRITE)
#define UCT_POSIX_MEM_LOG_ALIGN         12  /* address and size must be aligned to this order */

/* segment flags */
#define UCT_POSIX_FLAG_HUGETLB          UCS_BIT(0) /* use MAP_HUGETLB */
#define UCT_POSIX_FLAG_SHM_OPEN         UCS_BIT(1) /* use shm_open() rather than open() */
#define UCT_POSIX_FLAG_PROCFS           UCS_BIT(2) /* use procfs mode: mmid encodes an
                                                      open fd symlink from procfs */

/* packing mmid for procfs mode */
#define UCT_POSIX_PROCFS_MMID_FD_BITS   20  /* how many bits for file descriptror */
#define UCT_POSIX_PROCFS_MMID_PID_BITS  20  /* how many bits for pid */

/* packing information for uct_posix_packed_seg_t */
#define UCT_POSIX_SEG_FLAGS_BITS        4   /* how many bits for flags */
#define UCT_POSIX_SEG_MMID_BITS         40  /* how many bits for shared memory id */
#define UCT_POSIX_SEG_LENGTH_HI_BITS    (UCT_POSIX_SEG_MMID_BITS + \
                                         UCT_POSIX_SEG_FLAGS_BITS - \
                                         UCT_POSIX_MEM_LOG_ALIGN)
#define UCT_POSIX_SEG_LENGTH_LO_BITS    ((sizeof(uint64_t) * 8) - \
                                         UCT_POSIX_SEG_LENGTH_HI_BITS)

/* filesystem paths */
#define UCT_POSIX_SHM_OPEN_DIR          "/dev/shm"       /* directory path for shm_open() */
#define UCT_POSIX_FILE_FMT              "/ucx_shm_posix_%"PRIx64
#define UCT_POSIX_PROCFS_FILE_FMT       "/proc/%d/fd/%d" /* file pattern for procfs mode */


typedef struct uct_posix_md_config {
    uct_mm_md_config_t        super;
    char                      *dir;
    int                       use_proc_link;
} uct_posix_md_config_t;

typedef struct uct_posix_packed_seg {
    uint64_t                  seg_id;     /* flags + mmid + length.lo */
    uint32_t                  length_hi;  /* length.hi */
} UCS_S_PACKED uct_posix_packed_seg_t;

typedef struct uct_posix_packed_rkey {
    uct_posix_packed_seg_t    seg;
    uintptr_t                 address;
} UCS_S_PACKED uct_posix_packed_rkey_t;


static ucs_config_field_t uct_posix_md_config_table[] = {
  {"MM_", "", NULL,
   ucs_offsetof(uct_posix_md_config_t, super), UCS_CONFIG_TYPE_TABLE(uct_mm_md_config_table)},

  {"DIR", UCT_POSIX_SHM_OPEN_DIR,
   "The path to the backing file. If it's equal to " UCT_POSIX_SHM_OPEN_DIR " then \n"
   "shm_open() is used. Otherwise, open() is used.",
   ucs_offsetof(uct_posix_md_config_t, dir), UCS_CONFIG_TYPE_STRING},

  {"USE_PROC_LINK", "y", "Use /proc/<pid>/fd/<fd> to share posix file.\n"
   " y   - Use /proc/<pid>/fd/<fd> to share posix file.\n"
   " n   - Use original file path to share posix file.\n",
   ucs_offsetof(uct_posix_md_config_t, use_proc_link), UCS_CONFIG_TYPE_BOOL},

  {NULL}
};

static int uct_posix_use_shm_open(const uct_posix_md_config_t *posix_config)
{
    return !strcmp(posix_config->dir, UCT_POSIX_SHM_OPEN_DIR);
}

static size_t uct_posix_iface_addr_length(uct_mm_md_t *md)
{
    const uct_posix_md_config_t *posix_config =
                    ucs_derived_of(md->config, uct_posix_md_config_t);

    /* if shm_open is requested, the path to the backing file is /dev/shm
     * by default. however, if shm_open isn't used, the size of the path to the
     * requested backing file is needed so that the user would know how much
     * space to allocated for the rkey.
     */
    return uct_posix_use_shm_open(posix_config) ? 0 :
           (strlen(posix_config->dir) + 1);
}

static void uct_posix_iface_addr_pack(uct_mm_md_t *md, void *buffer)
{
    const uct_posix_md_config_t *posix_config =
                     ucs_derived_of(md->config, uct_posix_md_config_t);

    if (!uct_posix_use_shm_open(posix_config)) {
        memcpy(buffer, posix_config->dir, strlen(posix_config->dir) + 1);
    }
}

/* pack mmid+flags */
static uct_mm_seg_id_t
uct_posix_pack_seg_id(uint64_t mmid, int flags, size_t length)
{
    /* check range for mmid and flags  */
    ucs_assert(mmid  <= UCS_MASK(UCT_POSIX_SEG_MMID_BITS));
    ucs_assert(flags <= UCS_MASK(UCT_POSIX_SEG_FLAGS_BITS));
    ucs_assert(!(length & UCS_MASK(UCT_POSIX_MEM_LOG_ALIGN)));

    return flags |
           (mmid   << UCT_POSIX_SEG_FLAGS_BITS) |
           (length << UCT_POSIX_SEG_LENGTH_HI_BITS);
}

static uint32_t uct_posix_pack_length_hi(size_t length)
{
    return length >> UCT_POSIX_SEG_LENGTH_LO_BITS;
}

static void uct_posix_unpack_seg(const uct_posix_packed_seg_t *packed_seg,
                                 uint64_t *mmid_p, int *flags_p, size_t *length_p)
{
    /*
     * +---------------------------+-----------+
     * |          segid            | length_hi |
     * +-------+-------+-----------+-----------+
     * | 0   3 | 4  43 | 44    63  | 0     32  |
     * +-------+-------+-----------+-----------+
     * | flags | mmid  | length.lo | length.hi |
     * +-------+-------+-----------+-----------+
     */

    /* make sure the bit widths make sense */
    UCS_STATIC_ASSERT((UCT_POSIX_SEG_FLAGS_BITS + UCT_POSIX_SEG_MMID_BITS +
                       (sizeof(*length_p) * 8) - UCT_POSIX_MEM_LOG_ALIGN) ==
                      ((sizeof(packed_seg->seg_id) * 8) +
                       (sizeof(packed_seg->length_hi) * 8)));

   *flags_p  = packed_seg->seg_id & UCS_MASK(UCT_POSIX_SEG_FLAGS_BITS);
    *mmid_p   = (packed_seg->seg_id >> UCT_POSIX_SEG_FLAGS_BITS) &
                UCS_MASK(UCT_POSIX_SEG_MMID_BITS);
    *length_p = ((packed_seg->seg_id >> UCT_POSIX_SEG_LENGTH_LO_BITS) |
                 ((uint64_t)packed_seg->length_hi << UCT_POSIX_SEG_LENGTH_HI_BITS)) &
                ~UCS_MASK(UCT_POSIX_MEM_LOG_ALIGN);
}

static uint64_t uct_posix_mmid_procfs_pack(int fd)
{
    /*
     * +----------------------+
     * |        mmid          |
     * +----------+-----------+
     * | 0     20 | 21     40 |
     * +----------+-----------+
     * | pid      | fd        |
     * +----------+-----------+
     */
    pid_t pid = getpid();

    UCS_STATIC_ASSERT((UCT_POSIX_PROCFS_MMID_PID_BITS +
                       UCT_POSIX_PROCFS_MMID_FD_BITS) ==
                      UCT_POSIX_SEG_MMID_BITS);

    ucs_assert(pid <= UCS_MASK(UCT_POSIX_PROCFS_MMID_PID_BITS));
    ucs_assert(fd  <= UCS_MASK(UCT_POSIX_PROCFS_MMID_FD_BITS));
    return pid | (fd << UCT_POSIX_PROCFS_MMID_PID_BITS);
}

static void uct_posix_mmid_procfs_unpack(uint64_t mmid, int *pid_p, int *fd_p)
{
    *fd_p  = mmid >> UCT_POSIX_PROCFS_MMID_PID_BITS;
    *pid_p = mmid & UCS_MASK(UCT_POSIX_PROCFS_MMID_PID_BITS);
}

static ucs_status_t uct_posix_test_mem(int shm_fd, size_t length)
{
    const size_t chunk_size = 64 * UCS_KBYTE;
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

ucs_status_t uct_posix_open_check_result(const char *func, const char *file_name,
                                         int ret, int *fd_p)
{
    if (ret >= 0) {
        *fd_p = ret;
        return UCS_OK;
    } else if (errno == EEXIST) {
        return UCS_ERR_ALREADY_EXISTS;
    } else {
        ucs_error("%s(file_name=%s) failed: %m", func, file_name);
        return UCS_ERR_SHMEM_SEGMENT;
    }
}

static ucs_status_t uct_posix_shm_open(uint64_t mmid, int open_flags, int *fd_p)
{
    char file_name[NAME_MAX];
    int ret;

    ucs_snprintf_safe(file_name, sizeof(file_name), UCT_POSIX_FILE_FMT, mmid);
    ret = shm_open(file_name, open_flags | O_RDWR, UCT_POSIX_SHM_OPEN_MODE);
    return uct_posix_open_check_result("shm_open", file_name, ret, fd_p);
}

static ucs_status_t uct_posix_file_open(const char *dir, uint64_t mmid,
                                        int open_flags, int* fd_p)
{
    char file_path[PATH_MAX];
    int ret;

    ucs_snprintf_safe(file_path, sizeof(file_path), "%s" UCT_POSIX_FILE_FMT,
                      dir, mmid);
    ret = open(file_path, open_flags | O_RDWR, UCT_POSIX_SHM_OPEN_MODE);
    return uct_posix_open_check_result("open", file_path, ret, fd_p);
}

static ucs_status_t uct_posix_procfs_open(const char *dir, int pid, int peer_fd,
                                          int* fd_p)
{
    char file_path[PATH_MAX];
    int ret;

    ucs_snprintf_safe(file_path, sizeof(file_path), UCT_POSIX_PROCFS_FILE_FMT,
                      pid, peer_fd);
    ret = open(file_path, O_RDWR, UCT_POSIX_SHM_OPEN_MODE);
    return uct_posix_open_check_result("open", file_path, ret, fd_p);
}

static ucs_status_t uct_posix_unlink(uct_mm_md_t *md, uint64_t mmid, int flags)
{
    uct_posix_md_config_t *posix_config = ucs_derived_of(md->config,
                                                         uct_posix_md_config_t);
    char file_path[PATH_MAX];
    int ret;

    if (flags & UCT_POSIX_FLAG_SHM_OPEN) {
        ucs_snprintf_safe(file_path, sizeof(file_path), UCT_POSIX_FILE_FMT, mmid);
        ret = shm_unlink(file_path);
        if (ret < 0) {
            ucs_error("shm_unlink(%s) failed: %m", file_path);
            return UCS_ERR_SHMEM_SEGMENT;
        }
    } else {
        ucs_snprintf_safe(file_path, sizeof(file_path), "%s" UCT_POSIX_FILE_FMT,
                          posix_config->dir, mmid);
        ret = unlink(file_path);
        if (ret < 0) {
            ucs_error("unlink(%s) failed: %m", file_path);
            return UCS_ERR_SHMEM_SEGMENT;
        }
    }

    return UCS_OK;
}

static ucs_status_t uct_posix_mmap(void *address, size_t length, int flags,
                                   int fd, const char *alloc_name, int show_err,
                                   void **address_p)
{
    void *result;

    result = ucs_mmap(address, length, UCT_POSIX_MMAP_PROT,
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
uct_posix_mem_attach_common(const uct_posix_packed_seg_t *packed_seg,
                            const char *dir, uct_mm_remote_seg_t *rseg)
{
    int flags, mmap_flags;
    uct_mm_seg_id_t mmid;
    int pid, peer_fd, fd;
    ucs_status_t status;
    size_t length;

    uct_posix_unpack_seg(packed_seg, &mmid, &flags, &length);
    ucs_assert(length > 0);
    rseg->cookie = (void*)length;

    if (flags & UCT_POSIX_FLAG_PROCFS) {
        uct_posix_mmid_procfs_unpack(mmid, &pid, &peer_fd);
        status = uct_posix_procfs_open(dir, pid, peer_fd, &fd);
    } else if (flags & UCT_POSIX_FLAG_SHM_OPEN) {
        status = uct_posix_shm_open(mmid, 0, &fd);
    } else {
        status = uct_posix_file_open(dir, mmid, 0, &fd);
    }
    if (status != UCS_OK) {
        return status;
    }

#ifdef MAP_HUGETLB
    mmap_flags = (flags & UCT_POSIX_FLAG_HUGETLB) ? MAP_HUGETLB : 0;
#else
    mmap_flags = 0;
#endif
    status = uct_posix_mmap(NULL, length, mmap_flags, fd, "posix_attach", 1,
                            &rseg->address);
    close(fd);
    return status;
}

static ucs_status_t uct_posix_mem_detach_common(const uct_mm_remote_seg_t *rseg)
{
    return uct_posix_munmap(rseg->address, (size_t)rseg->cookie);
}

static ucs_status_t uct_posix_md_query(uct_md_h tl_md, uct_md_attr_t *md_attr)
{
    uct_mm_md_t *md = ucs_derived_of(tl_md, uct_mm_md_t);

    uct_mm_md_query(&md->super, md_attr, 1);
    md_attr->rkey_packed_size = sizeof(uct_posix_packed_rkey_t) +
                                uct_posix_iface_addr_length(md);
    return UCS_OK;
}

static ucs_status_t
uct_posix_rkey_unpack(uct_component_t *component, const void *rkey_buffer,
                      uct_rkey_t *rkey_p, void **handle_p)
{
    const uct_posix_packed_rkey_t *packed_rkey = rkey_buffer;
    uct_mm_remote_seg_t *rseg;
    ucs_status_t status;

    rseg = ucs_malloc(sizeof(*rseg), "posix_remote_seg");
    if (rseg == NULL) {
        ucs_error("failed to allocate posix remote segment descriptor");
        return UCS_ERR_NO_MEMORY;
    }

    status = uct_posix_mem_attach_common(&packed_rkey->seg,
                                         (const char*)(packed_rkey + 1), rseg);
    if (status != UCS_OK) {
        ucs_free(rseg);
        return status;
    }

    uct_mm_md_make_rkey(rseg->address, packed_rkey->address, rkey_p);
    *handle_p = rseg;
    return UCS_OK;
}

static ucs_status_t
uct_posix_rkey_release(uct_component_t *component, uct_rkey_t rkey, void *handle)
{
    uct_mm_remote_seg_t *rseg = handle;
    ucs_status_t status;

    status = uct_posix_mem_detach_common(rseg);
    if (status != UCS_OK) {
        return status;
    }

    ucs_free(rseg);
    return UCS_OK;
}

static ucs_status_t
uct_posix_mkey_pack(uct_md_h tl_md, uct_mem_h memh, void *rkey_buffer)
{
    uct_mm_md_t                      *md = ucs_derived_of(tl_md, uct_mm_md_t);
    uct_mm_seg_t                    *seg = memh;
    uct_posix_packed_rkey_t *packed_rkey = rkey_buffer;

    packed_rkey->seg.seg_id    = seg->seg_id;
    packed_rkey->seg.length_hi = uct_posix_pack_length_hi(seg->length);
    packed_rkey->address       = (uintptr_t)seg->address;
    uct_posix_iface_addr_pack(md, packed_rkey + 1);
    return UCS_OK;
}

static ucs_status_t uct_posix_mem_alloc(uct_mm_md_t *md, uct_mm_seg_t *seg,
                                        unsigned uct_flags, const char *alloc_name)
{
    uct_posix_md_config_t *posix_config = ucs_derived_of(md->config,
                                                         uct_posix_md_config_t);
    int flags, mmap_flags;
    ucs_status_t status;
    int force_hugetlb;
    void *address;
    uint64_t mmid;
    int fd;

    seg->length = ucs_align_up_pow2(seg->length, UCS_BIT(UCT_POSIX_MEM_LOG_ALIGN));
    seg->length = ucs_align_up_pow2(seg->length, ucs_get_page_size());
    flags       = 0;

    /* Generate unique name for shared memory backing file */
    mmid = (unsigned)ucs_generate_uuid((uintptr_t)md);
    for (;;) {
        if (uct_posix_use_shm_open(posix_config)) {
            flags |= UCT_POSIX_FLAG_SHM_OPEN;
            status = uct_posix_shm_open(mmid, UCT_POSIX_SHM_CREATE_FLAGS, &fd);
        } else {
            status = uct_posix_file_open(posix_config->dir, mmid,
                                         UCT_POSIX_SHM_CREATE_FLAGS, &fd);
        }
        if (status == UCS_OK) {
            break;
        } else if (status == UCS_ERR_ALREADY_EXISTS) {
            mmid = rand_r((unsigned*)&mmid); /* continue */
        } else {
            return status;
        }
    }

    /* Check if the location of the backing file has enough memory for the
     * needed size by trying to write there before calling mmap */
    status = uct_posix_test_mem(fd, seg->length);
    if (status != UCS_OK) {
        goto err_close;
    }

    if (posix_config->use_proc_link) {
        /* Remove the original file, to use the symlink in procfs  */
        status = uct_posix_unlink(md, mmid, flags);
        if (status != UCS_OK) {
            goto err_close;
        }

        /* replace mmid by pid+fd */
        mmid   = uct_posix_mmid_procfs_pack(fd);
        flags |= UCT_POSIX_FLAG_PROCFS;
    }

    /* mmap the shared memory segment that was created by shm_open */
    if (uct_flags & UCT_MD_MEM_FLAG_FIXED) {
        mmap_flags   = MAP_FIXED;
    } else {
        seg->address = NULL; // TODO
        mmap_flags   = 0;
    }

    /* try HUGETLB mmap */
    address = MAP_FAILED;
    if (posix_config->super.hugetlb_mode != UCS_NO) {
        force_hugetlb = (posix_config->super.hugetlb_mode == UCS_YES);
#ifdef MAP_HUGETLB
        status = uct_posix_mmap(seg->address, seg->length,
                                mmap_flags | MAP_HUGETLB, fd, alloc_name,
                                force_hugetlb, &address);
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
           flags |= UCT_POSIX_FLAG_HUGETLB;
       }
    }

    /* fallback to regular mmap */
    if (address == MAP_FAILED) {
        ucs_assert(posix_config->super.hugetlb_mode != UCS_YES);
        status = uct_posix_mmap(seg->address, seg->length, mmap_flags, fd,
                                alloc_name, 1, &address);
        if (status != UCS_OK) {
            goto err_close;
        }
    }

    if (uct_flags & UCT_MD_MEM_FLAG_FIXED) {
        ucs_assert(address == seg->address);
    }

    /* create new memory segment */
    ucs_debug("allocated posix shared memory at %p length %zu", seg->address,
              seg->length);

    seg->seg_id  = uct_posix_pack_seg_id(mmid, flags, seg->length);
    seg->address = address;

    if (!posix_config->use_proc_link) {
        /* closing the file here since the peers will open it by file system path */
        close(fd);
    }

    return UCS_OK;

err_close:
    close(fd);
    if (!posix_config->use_proc_link) {
        uct_posix_unlink(md, mmid, flags);
    }
    return status;
}

static ucs_status_t uct_posix_mem_free(uct_mm_md_t *md, const uct_mm_seg_t *seg)
{
    uct_posix_packed_seg_t packed_seg = { .seg_id = seg->seg_id, .length_hi = 0 };
    int flags, fd, dummy_pid;
    ucs_status_t status;
    size_t dummy_length;
    uint64_t mmid;

    status = uct_posix_munmap(seg->address, seg->length);
    if (status != UCS_OK) {
        return status;
    }

    uct_posix_unpack_seg(&packed_seg, &mmid, &flags, &dummy_length);

    if (flags & UCT_POSIX_FLAG_PROCFS) {
        uct_posix_mmid_procfs_unpack(mmid, &dummy_pid, &fd);
        ucs_assert(dummy_pid == getpid());
        close(fd);
    } else {
        status = uct_posix_unlink(md, mmid, flags);
        if (status != UCS_OK) {
            return status;
        }
    }

    return UCS_OK;
}

static ucs_status_t uct_posix_mem_attach(uct_mm_md_t *md, uct_mm_seg_id_t seg_id,
                                         const void *iface_addr,
                                         uct_mm_remote_seg_t *remote_seg)
{
    uct_posix_packed_seg_t packed_seg = { .seg_id = seg_id, .length_hi = 0 };
    return uct_posix_mem_attach_common(&packed_seg, iface_addr, remote_seg);
}

static void uct_posix_mem_detach(uct_mm_md_t *md, const uct_mm_remote_seg_t *rseg)
{
    uct_posix_mem_detach_common(rseg);
}

static uct_mm_md_mapper_ops_t uct_posix_md_ops = {
   .super = {
        .close                  = uct_mm_md_close,
        .query                  = uct_posix_md_query,
        .mem_alloc              = uct_mm_md_mem_alloc,
        .mem_free               = uct_mm_md_mem_free,
        .mem_advise             = (void*)ucs_empty_function_return_unsupported,
        .mem_reg                = (void*)ucs_empty_function_return_unsupported,
        .mem_dereg              = (void*)ucs_empty_function_return_unsupported,
        .mkey_pack              = uct_posix_mkey_pack,
        .is_sockaddr_accessible = (void*)ucs_empty_function_return_zero,
        .detect_memory_type     = (void*)ucs_empty_function_return_unsupported
    },
   .query                       = (void*)ucs_empty_function_return_success,
   .iface_addr_length           = uct_posix_iface_addr_length,
   .iface_addr_pack             = uct_posix_iface_addr_pack,
   .mem_alloc                   = uct_posix_mem_alloc,
   .mem_free                    = uct_posix_mem_free,
   .mem_attach                  = uct_posix_mem_attach,
   .mem_detach                  = uct_posix_mem_detach
};

UCT_MM_TL_DEFINE(posix, &uct_posix_md_ops, uct_posix_rkey_unpack,
                 uct_posix_rkey_release, "POSIX_")
