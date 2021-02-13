/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include <common/test.h>

#include "ucp_test.h"

extern "C" {
#include <ucp/core/ucp_rkey.h>
#include <ucp/proto/proto.h>
#include <ucp/proto/proto_select.h>
#include <ucp/proto/proto_select.inl>
#include <ucp/core/ucp_worker.inl>
}

class test_ucp_proto : public ucp_test {
public:
    static void get_test_variants(std::vector<ucp_test_variant>& variants) {
        add_variant(variants, UCP_FEATURE_TAG);
    }

protected:
    virtual void init() {
        modify_config("PROTO_ENABLE", "y");
        ucp_test::init();
        sender().connect(&receiver(), get_ep_params());
    }

    ucp_worker_h worker() {
        return sender().worker();
    }

    void show_proto(ucs::detail::message_stream &ms, void *req, size_t length)
    {
        UCS_STRING_BUFFER_ONSTACK(strb, 256);

        ucp_request_t *ucp_req = ((ucp_request_t*)req) - 1;

        ucp_req->send.proto_config->proto->config_str(
                length, length, ucp_req->send.proto_config->priv, &strb);

        ms << ucp_req->send.proto_config->proto->name << " "
           << ucs_string_buffer_cstr(&strb);
    }

    void test_select(ucp_operation_id_t op_id, ucs_memory_type_t send_mem_type,
                     ucs_memory_type_t recv_mem_type, size_t length)
    {
        mem_buffer send_buffer(length, send_mem_type);
        mem_buffer recv_buffer(length, recv_mem_type);

        ucp_request_param_t sparam = {};
        ucp_request_param_t rparam = {};
        void *sreq = NULL, *rreq = NULL;

        sparam.op_attr_mask |= UCP_OP_ATTR_FLAG_NO_IMM_CMPL;
        rparam.op_attr_mask |= UCP_OP_ATTR_FLAG_NO_IMM_CMPL;

        switch (op_id) {
        case UCP_OP_ID_TAG_SEND:
            sreq = ucp_tag_send_nbx(sender().ep(), send_buffer.ptr(), length, 1,
                                    &sparam);

            rreq = ucp_tag_recv_nbx(receiver().worker(), recv_buffer.ptr(),
                                    length, 1, 1, &rparam);
        default:
            break;
        }

        ASSERT_UCS_PTR_OK(sreq);
        request_wait(rreq);

        if (sreq != NULL) {
            while (ucp_request_check_status(sreq) == UCS_INPROGRESS) {
                progress();
            }
            ucs::detail::message_stream ms("INFO");
            ms << ucp_operation_names[op_id] << " "
               << ucs_memory_type_names[send_mem_type] << "->"
               << ucs_memory_type_names[recv_mem_type] << "," << length << ": ";

            show_proto(ms, sreq, length);
            ucp_request_release(sreq);
        }
    }
};

UCS_TEST_P(test_ucp_proto, select)
{
    // test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_HOST, UCS_MEMORY_TYPE_HOST,
    //             2 * UCS_MBYTE);
    // test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_CUDA,
    //             2 * UCS_MBYTE);
    // test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_CUDA,
    //             16 * UCS_KBYTE);
    test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_HOST, UCS_MEMORY_TYPE_CUDA,
                2 * UCS_MBYTE);
    // test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_HOST,
    //             2 * UCS_MBYTE);
    // test_select(UCP_OP_ID_TAG_SEND, UCS_MEMORY_TYPE_CUDA, UCS_MEMORY_TYPE_HOST,
    //             32 * UCS_KBYTE);
}

UCS_TEST_P(test_ucp_proto, dump_protocols) {
    ucp_proto_select_param_t select_param;
    ucs_string_buffer_t strb;

    select_param.op_id      = UCP_OP_ID_TAG_SEND;
    select_param.op_flags   = 0;
    select_param.dt_class   = UCP_DATATYPE_CONTIG;
    select_param.mem_type   = UCS_MEMORY_TYPE_HOST;
    select_param.sys_dev    = UCS_SYS_DEVICE_ID_UNKNOWN;
    select_param.sg_count   = 1;
    select_param.padding[0] = 0;
    select_param.padding[1] = 0;

    ucs_string_buffer_init(&strb);
    ucp_proto_select_param_str(&select_param, &strb);
    UCS_TEST_MESSAGE << ucs_string_buffer_cstr(&strb);
    ucs_string_buffer_cleanup(&strb);

    ucp_worker_h worker                   = sender().worker();
    ucp_worker_cfg_index_t ep_cfg_index   = sender().ep()->cfg_index;
    ucp_worker_cfg_index_t rkey_cfg_index = UCP_WORKER_CFG_INDEX_NULL;

    ucp_proto_select_lookup(worker, &worker->ep_config[ep_cfg_index].proto_select,
                            ep_cfg_index, rkey_cfg_index, &select_param, 0);
    ucp_ep_print_info(sender().ep(), stdout);
}

UCS_TEST_P(test_ucp_proto, rkey_config) {
    ucp_rkey_config_key_t rkey_config_key;

    rkey_config_key.ep_cfg_index = 0;
    rkey_config_key.md_map       = 0;
    rkey_config_key.mem_type     = UCS_MEMORY_TYPE_HOST;
    rkey_config_key.sys_dev      = UCS_SYS_DEVICE_ID_UNKNOWN;

    ucs_status_t status;

    /* similar configurations should return same index */
    ucp_worker_cfg_index_t cfg_index1;
    status = ucp_worker_rkey_config_get(worker(), &rkey_config_key, NULL,
                                        &cfg_index1);
    ASSERT_UCS_OK(status);

    ucp_worker_cfg_index_t cfg_index2;
    status = ucp_worker_rkey_config_get(worker(), &rkey_config_key, NULL,
                                        &cfg_index2);
    ASSERT_UCS_OK(status);

    EXPECT_EQ(static_cast<int>(cfg_index1), static_cast<int>(cfg_index2));

    rkey_config_key.ep_cfg_index = 0;
    rkey_config_key.md_map       = 1;
    rkey_config_key.mem_type     = UCS_MEMORY_TYPE_HOST;
    rkey_config_key.sys_dev      = UCS_SYS_DEVICE_ID_UNKNOWN;

    /* different configuration should return different index */
    ucp_worker_cfg_index_t cfg_index3;
    status = ucp_worker_rkey_config_get(worker(), &rkey_config_key, NULL,
                                        &cfg_index3);
    ASSERT_UCS_OK(status);

    EXPECT_NE(static_cast<int>(cfg_index1), static_cast<int>(cfg_index3));
}

UCS_TEST_P(test_ucp_proto, worker_print_info_rkey)
{
    ucp_rkey_config_key_t rkey_config_key;

    rkey_config_key.ep_cfg_index = 0;
    rkey_config_key.md_map       = 0;
    rkey_config_key.mem_type     = UCS_MEMORY_TYPE_HOST;
    rkey_config_key.sys_dev      = UCS_SYS_DEVICE_ID_UNKNOWN;

    /* similar configurations should return same index */
    ucp_worker_cfg_index_t cfg_index;
    ucs_status_t status = ucp_worker_rkey_config_get(worker(), &rkey_config_key,
                                                     NULL, &cfg_index);
    ASSERT_UCS_OK(status);

    ucp_worker_print_info(worker(), stdout);
}

UCP_INSTANTIATE_TEST_CASE(test_ucp_proto)
