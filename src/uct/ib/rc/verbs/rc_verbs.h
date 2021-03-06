/**
* Copyright (C) Mellanox Technologies Ltd. 2001-2014.  ALL RIGHTS RESERVED.
*
* See file LICENSE for terms.
*/

#ifndef UCT_RC_VERBS_H
#define UCT_RC_VERBS_H

#include <uct/ib/rc/base/rc_iface.h>
#include <uct/ib/rc/base/rc_ep.h>
#include <ucs/type/class.h>
#include <ucs/datastruct/ptr_array.h>

#include "rc_verbs_common.h"

#if HAVE_IBV_EX_HW_TM
typedef struct uct_rc_verbs_release_desc {
    uct_recv_desc_t             super;
    unsigned                    offset;
} uct_rc_verbs_release_desc_t;
#endif

/**
 * RC verbs communication context.
 */
typedef struct uct_rc_verbs_ep {
    uct_rc_ep_t            super;
    uct_rc_verbs_txcnt_t   txcnt;
#if HAVE_IBV_EX_HW_TM
    struct ibv_qp          *tm_qp;
#endif
} uct_rc_verbs_ep_t;


/**
 * RC verbs interface configuration.
 */
typedef struct uct_rc_verbs_iface_config {
    uct_rc_iface_config_t              super;
    uct_rc_verbs_iface_common_config_t verbs_common;
    uct_rc_fc_config_t                 fc;
#if HAVE_IBV_EX_HW_TM
    struct {
        int                            enable;
        unsigned                       list_size;
        unsigned                       rndv_queue_len;
    } tm;
#endif
} uct_rc_verbs_iface_config_t;


/**
 * RC verbs interface.
 */
typedef struct uct_rc_verbs_iface {
    uct_rc_iface_t              super;
    struct ibv_send_wr          inl_am_wr;
    struct ibv_send_wr          inl_rwrite_wr;
    uct_rc_verbs_iface_common_t verbs_common;
#if HAVE_IBV_EX_HW_TM
    struct {
        uct_rc_srq_t            xrq;       /* TM XRQ */
        ucs_ptr_array_t         rndv_comps;
        unsigned                tag_available;
        int                     num_outstanding;
        unsigned                eager_hdr_size;
        unsigned                rndv_hdr_size;
        uint16_t                unexpected_cnt;
        uint8_t                 enabled;
        struct {
            void                     *arg; /* User defined arg */
            uct_tag_unexp_eager_cb_t cb;   /* Callback for unexpected eager messages */
        } eager_unexp;

        struct {
            void                     *arg; /* User defined arg */
            uct_tag_unexp_rndv_cb_t  cb;   /* Callback for unexpected rndv messages */
        } rndv_unexp;
        uct_rc_verbs_release_desc_t  eager_desc;
        uct_rc_verbs_release_desc_t  rndv_desc;
    } tm;
#endif
    struct {
        unsigned                tx_max_wr;
    } config;

    void (*progress)(void*); /* Progress function (either regular or TM aware) */
} uct_rc_verbs_iface_t;


#define UCT_RC_VERBS_CHECK_AM_SHORT(_iface, _id, _length, _max_inline) \
     UCT_CHECK_AM_ID(_id); \
     UCT_CHECK_LENGTH(sizeof(uct_rc_am_short_hdr_t) + _length + \
                      (_iface)->verbs_common.config.notag_hdr_size, \
                      0, _max_inline, "am_short");

#define UCT_RC_VERBS_CHECK_AM_ZCOPY(_iface, _id, _header_len, _len, _desc_size, _seg_size) \
     UCT_CHECK_AM_ID(_id); \
     UCT_RC_CHECK_ZCOPY_DATA(_header_len, _len, _seg_size) \
     UCT_CHECK_LENGTH(sizeof(uct_rc_hdr_t) + _header_len + \
                      (_iface)->verbs_common.config.notag_hdr_size, \
                      0, _desc_size, "am_zcopy header");

#define UCT_RC_VERBS_GET_TX_DESC(_iface, _mp, _desc, _hdr, _len) \
     { \
         UCT_RC_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc) \
         hdr = _desc + 1; \
         len = uct_rc_verbs_notag_header_fill(_iface, _hdr); \
     }

#define UCT_RC_VERBS_GET_TX_AM_BCOPY_DESC(_iface, _mp, _desc, _id, _pack_cb, \
                                          _arg, _length, _data_length) \
     { \
         void *hdr; \
         size_t len; \
         UCT_RC_VERBS_GET_TX_DESC(_iface, _mp, _desc, hdr, len) \
         (_desc)->super.handler = (uct_rc_send_handler_t)ucs_mpool_put; \
         uct_rc_bcopy_desc_fill(hdr + len, _id, _pack_cb, _arg, &(_data_length)); \
         _length = _data_length + len + sizeof(uct_rc_hdr_t); \
     }

#define UCT_RC_VERBS_GET_TX_AM_ZCOPY_DESC(_iface, _mp, _desc, _id, _header, \
                                          _header_length, _comp, _send_flags, _sge) \
     { \
         void *hdr; \
         size_t len; \
         UCT_RC_VERBS_GET_TX_DESC(_iface, _mp, _desc, hdr, len) \
         uct_rc_zcopy_desc_set_comp(_desc, _comp, _send_flags); \
         uct_rc_zcopy_desc_set_header(hdr + len, _id, _header, _header_length); \
         _sge.length = sizeof(uct_rc_hdr_t) + header_length + len; \
     }


#if HAVE_IBV_EX_HW_TM

/* For RNDV TM enabling 2 QPs should be created, one is for sending WRs and
 * another one for HW (device will use it for RDMA reads and sending RNDV
 * Complete messages).*/
typedef struct uct_rc_verbs_ep_tm_address {
    uct_rc_ep_address_t         super;
    uct_ib_uint24_t             tm_qp_num;
} UCS_S_PACKED uct_rc_verbs_ep_tm_address_t;

typedef struct uct_rc_verbs_ctx_priv {
    uint64_t                    tag;
    uint64_t                    imm_data;
    void                        *buffer;
    uint32_t                    length;
    uint32_t                    tag_handle;
} uct_rc_verbs_ctx_priv_t;

typedef struct uct_rc_verbs_tm_cqe {
    uint64_t                    wr_id;
    enum ibv_wc_opcode          opcode;
    int                         flags;
    uint32_t                    byte_len;
    uint32_t                    imm_data;
    uint32_t                    qp_num;
    uint32_t                    src_qp;
    uint32_t                    slid;
} uct_rc_verbs_tm_cqe_t;

#  define UCT_RC_VERBS_TAG_MIN_POSTED  33

#  define UCT_RC_VERBS_TM_ENABLED(_iface) \
       (IBV_DEVICE_TM_CAPS(uct_ib_iface_device(&(_iface)->super.super), max_num_tags) && \
        (_iface)->tm.enabled)

#  define UCT_RC_VERBS_TM_CONFIG(_config, _field)  (_config)->tm._field

/* If message arrived with imm_data = 0 - it is SW RNDV request */
#  define UCT_RC_VERBS_TM_IS_SW_RNDV(_flags, _imm_data) \
       (ucs_unlikely(((_flags) & IBV_WC_WITH_IMM) && !(_imm_data)))

#  define UCT_RC_VERBS_GET_TX_TM_DESC(_iface, _mp, _desc, _tag, _app_ctx, _hdr, _len) \
       { \
           UCT_RC_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc) \
           hdr = _desc + 1; \
           len = uct_rc_verbs_eager_header_fill(_iface, _hdr, _tag, _app_ctx); \
       }

#  define UCT_RC_VERBS_GET_TM_BCOPY_DESC(_iface, _mp, _desc, _tag, _app_ctx, \
                                         _pack_cb, _arg, _length) \
       { \
           void *hdr; \
           size_t len; \
           UCT_RC_VERBS_GET_TX_TM_DESC(_iface, _mp, _desc, _tag, _app_ctx, hdr, len) \
           (_desc)->super.handler = (uct_rc_send_handler_t)ucs_mpool_put; \
           _length = pack_cb(hdr + len, arg); \
       }

#  define UCT_RC_VERBS_GET_TM_ZCOPY_DESC(_iface, _mp, _desc, _tag, _app_ctx, \
                                         _comp, _send_flags, _sge) \
       { \
           void *hdr; \
           size_t len; \
           UCT_RC_VERBS_GET_TX_TM_DESC(_iface, _mp, _desc, _tag, _app_ctx, hdr, len) \
           uct_rc_zcopy_desc_set_comp(_desc, _comp, _send_flags); \
           _sge.length = len; \
       }

#  define UCT_RC_VERBS_FILL_TM_IMM(_wr, _imm_data, _priv) \
       if (_imm_data == 0) { \
           _wr.opcode = IBV_WR_SEND; \
           _priv = 0; \
       } else { \
           _wr.opcode = IBV_WR_SEND_WITH_IMM; \
           uct_rc_verbs_tag_imm_data_pack(&(_wr.imm_data), &_priv, _imm_data); \
       }

#  define UCT_RC_VERBS_FILL_TM_OP_WR(_iface, _wr, _sge, _iovlen, _opcode, _ctx, _flags) \
       { \
           (_wr)->sg_list = _sge; \
           (_wr)->num_sge = _iovlen; \
           (_wr)->opcode  = _opcode; \
           (_wr)->flags   = _flags | IBV_OPS_TM_SYNC; \
           (_wr)->next    = NULL; \
           (_wr)->wr_id   = (uint64_t)_ctx; \
           (_wr)->tm.unexpected_cnt = (_iface)->tm.unexpected_cnt; \
       }

#  define UCT_RC_VERBS_CHECK_TAG(iface) \
       if (!iface->tm.tag_available) {  \
           return UCS_ERR_EXCEEDS_LIMIT; \
       } \
       if (iface->tm.num_outstanding <= 0) { \
           return UCS_ERR_NO_RESOURCE; \
       }

static UCS_F_ALWAYS_INLINE size_t
uct_rc_verbs_eager_header_fill(uct_rc_verbs_iface_t *iface, void *hdr,
                               uct_tag_t tag, uint32_t app_ctx)
{
    struct ibv_tm_info tm_info;
    uct_ib_device_t *dev = uct_ib_iface_device(&iface->super.super);

    tm_info.op        = IBV_TM_OP_EAGER;
    tm_info.tag.tag   = tag;
    tm_info.priv.data = app_ctx;
    return ibv_pack_tm_info(dev->ibv_context, hdr, &tm_info);
}

static UCS_F_ALWAYS_INLINE void
uct_rc_verbs_iface_fill_inl_tag_sge(uct_rc_verbs_iface_t *iface,
                                    void *tm_hdr, uct_tag_t tag,
                                    const void *buffer, unsigned length,
                                    uint32_t app_ctx)
{
    struct ibv_sge *sge = iface->verbs_common.inl_sge;

    sge[0].length = uct_rc_verbs_eager_header_fill(iface, tm_hdr,
                                                   tag, app_ctx);
    sge[0].addr   = (uintptr_t)tm_hdr;
    sge[1].length = length;
    sge[1].addr   = (uintptr_t)buffer;
}

static UCS_F_ALWAYS_INLINE size_t
uct_rc_verbs_rndv_header_fill(uct_rc_verbs_iface_t *iface, void *hdr,
                              uct_tag_t tag, uint32_t app_ctx, uint32_t rkey,
                              const void *vaddr, uint32_t len)
{
    struct ibv_tm_info tm_info;
    uct_ib_device_t *dev = uct_ib_iface_device(&iface->super.super);

    tm_info.op         = IBV_TM_OP_RNDV;
    tm_info.tag.tag    = tag;
    tm_info.priv.data  = app_ctx;
    tm_info.rndv.rkey  = rkey;
    tm_info.rndv.vaddr = (uintptr_t)vaddr;
    tm_info.rndv.len   = len;
    return ibv_pack_tm_info(dev->ibv_context, hdr, &tm_info);
}

static UCS_F_ALWAYS_INLINE void
uct_rc_verbs_iface_fill_inl_rndv_sge(uct_rc_verbs_iface_t *iface,
                                     void *tm_hdr, uct_tag_t tag,
                                     uint32_t app_ctx, uint32_t rkey,
                                     const void * vaddr, uint32_t len,
                                     const void *hdr, unsigned hdr_len)
{
    struct ibv_sge *sge = iface->verbs_common.inl_sge;

    sge[0].length = uct_rc_verbs_rndv_header_fill(iface, tm_hdr, tag, app_ctx,
                                                  rkey, vaddr, len);
    sge[0].addr   = (uintptr_t)tm_hdr;
    sge[1].length = hdr_len;
    sge[1].addr   = (uintptr_t)hdr;
}

static UCS_F_ALWAYS_INLINE void
uct_rc_verbs_tag_imm_data_pack(uint32_t *ib_imm, uint32_t *app_ctx,
                               uint64_t imm_val)
{
    *ib_imm  = (uint32_t)(imm_val & 0xFFFFFFFF);
    *app_ctx = (uint32_t)(imm_val >> 32);
}

static UCS_F_ALWAYS_INLINE uint64_t
uct_rc_verbs_tag_imm_data_unpack(uint32_t ib_imm, uint32_t app_ctx, int flags)
{
    if (flags & IBV_WC_WITH_IMM) {
        return ((uint64_t)app_ctx << 32) | ib_imm;
    } else {
        return 0ul;
    }
}

static UCS_F_ALWAYS_INLINE uct_rc_verbs_ctx_priv_t*
uct_rc_verbs_iface_ctx_priv(uct_tag_context_t *ctx)
{
    return (uct_rc_verbs_ctx_priv_t*)ctx->priv;
}

static UCS_F_ALWAYS_INLINE unsigned
uct_rc_verbs_iface_tag_get_op_id(uct_rc_verbs_iface_t *iface,
                                 uct_completion_t *comp)
{
    uint32_t prev_ph;
    return ucs_ptr_array_insert(&iface->tm.rndv_comps, comp, &prev_ph);
}

static UCS_F_ALWAYS_INLINE void
uct_rc_verbs_iface_save_tmh(struct ibv_cq_ex *cqe, uct_rc_verbs_ctx_priv_t *priv,
                            int flags, struct ibv_wc_tm_info *tm_info)
{
    priv->tag      = tm_info->tag.tag;
    priv->imm_data = uct_rc_verbs_tag_imm_data_unpack(ibv_wc_read_imm_data(cqe),
                                                      tm_info->priv.data, flags);
}

ucs_status_t uct_rc_verbs_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                             const void *data, size_t length);

ssize_t uct_rc_verbs_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm,
                                        uct_pack_callback_t pack_cb,
                                        void *arg);

ucs_status_t uct_rc_verbs_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                             uint64_t imm, const uct_iov_t *iov,
                                             size_t iovcnt, uct_completion_t *comp);

ucs_status_ptr_t uct_rc_verbs_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                                const void *header,
                                                unsigned header_length,
                                                const uct_iov_t *iov,
                                                size_t iovcnt,
                                                uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *op);

ucs_status_t uct_rc_verbs_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                              const void* header,
                                              unsigned header_length);
#else

#  define UCT_RC_VERBS_TM_ENABLED(_iface)   0

#endif /* HAVE_IBV_EX_HW_TM */


static UCS_F_ALWAYS_INLINE size_t
uct_rc_verbs_notag_header_fill(uct_rc_verbs_iface_t *iface, void *hdr)
{
#if HAVE_IBV_EX_HW_TM
    struct ibv_tm_info tm_info;
    uct_ib_device_t *dev = uct_ib_iface_device(&iface->super.super);

    if (UCT_RC_VERBS_TM_ENABLED(iface)) {
        tm_info.op = IBV_TM_OP_NO_TAG;
        return ibv_pack_tm_info(dev->ibv_context, hdr, &tm_info);
    }
#endif

    return 0;
}


UCS_CLASS_DECLARE(uct_rc_verbs_ep_t, uct_iface_h);
UCS_CLASS_DECLARE_NEW_FUNC(uct_rc_verbs_ep_t, uct_ep_t, uct_iface_h);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_rc_verbs_ep_t, uct_ep_t);

void uct_rc_verbs_ep_am_packet_dump(uct_base_iface_t *iface,
                                    uct_am_trace_type_t type,
                                    void *data, size_t length,
                                    size_t valid_length,
                                    char *buffer, size_t max);

ucs_status_t uct_rc_verbs_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                       unsigned length, uint64_t remote_addr,
                                       uct_rkey_t rkey);

ssize_t uct_rc_verbs_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                  void *arg, uint64_t remote_addr,
                                  uct_rkey_t rkey);

ucs_status_t uct_rc_verbs_ep_put_zcopy(uct_ep_h tl_ep,
                                       const uct_iov_t *iov, size_t iovcnt,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_get_bcopy(uct_ep_h tl_ep,
                                       uct_unpack_callback_t unpack_cb,
                                       void *arg, size_t length,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_get_zcopy(uct_ep_h tl_ep,
                                       const uct_iov_t *iov, size_t iovcnt,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                      const void *buffer, unsigned length);

ssize_t uct_rc_verbs_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                                 uct_pack_callback_t pack_cb, void *arg);

ucs_status_t uct_rc_verbs_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                      unsigned header_length, const uct_iov_t *iov,
                                      size_t iovcnt, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_add64(uct_ep_h tl_ep, uint64_t add,
                                          uint64_t remote_addr, uct_rkey_t rkey);

ucs_status_t uct_rc_verbs_ep_atomic_fadd64(uct_ep_h tl_ep, uint64_t add,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint64_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_swap64(uct_ep_h tl_ep, uint64_t swap,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint64_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare, uint64_t swap,
                                            uint64_t remote_addr, uct_rkey_t rkey,
                                            uint64_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_add32(uct_ep_h tl_ep, uint32_t add,
                                          uint64_t remote_addr, uct_rkey_t rkey);

ucs_status_t uct_rc_verbs_ep_atomic_fadd32(uct_ep_h tl_ep, uint32_t add,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint32_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_swap32(uct_ep_h tl_ep, uint32_t swap,
                                           uint64_t remote_addr, uct_rkey_t rkey,
                                           uint32_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare, uint32_t swap,
                                            uint64_t remote_addr, uct_rkey_t rkey,
                                            uint32_t *result, uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                   uct_completion_t *comp);

ucs_status_t uct_rc_verbs_ep_connect_to_ep(uct_ep_h tl_ep,
                                           const uct_device_addr_t *dev_addr,
                                           const uct_ep_addr_t *ep_addr);

ucs_status_t uct_rc_verbs_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr);

void uct_rc_verbs_iface_progress(void *arg);

ucs_status_t uct_rc_verbs_ep_fc_ctrl(uct_ep_t *tl_ep, unsigned op,
                                     uct_rc_fc_request_t *req);

#endif
