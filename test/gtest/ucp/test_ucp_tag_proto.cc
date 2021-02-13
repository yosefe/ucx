/**
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "ucp_test.h"


class test_ucp_tag_proto : public ucp_test {
public:
    enum {
        TEST_FLAG_SEND_SYNC    = UCS_BIT(0), /* Sync send, or regular send */
        TEST_FLAG_RECV_EXP     = UCS_BIT(1), /* Expected receive, or unexpected */
        TEST_FLAG_SEND_LESS    = UCS_BIT(2), /* Sender buffer is smaller, or same */
        TEST_FLAG_PEER_FAILURE = UCS_BIT(3)  /* Enable peer failure support */
    };

    static void get_test_variants(std::vector<ucp_test_variant>& variants) {

        get_test_variants(variants, UCP_FEATURE_TAG, 0, "");
        get_test_variants(variants, UCP_FEATURE_TAG | UCP_FEATURE_WAKEUP,
                          TEST_FLAG_PEER_FAILURE, "wkup_err" );
    }

    virtual void init() {
        modify_config("PROTO_ENABLE", "y");
        ucp_test::init();
        ucp_ep_params_t ep_params = get_ep_params();
        sender().connect(&receiver(), ep_params);
        receiver().connect(&sender(), ep_params);
    }

    void* send_nb(void *buffer, size_t size, ucp_tag_t tag) {
        ucp_request_param_t param;
        param.op_attr_mask = 0;
        void *req = (get_test_flags() & TEST_FLAG_SEND_SYNC) ?
                ucp_tag_send_sync_nbx(sender().ep(), buffer, size, tag, &param) :
                ucp_tag_send_nbx     (sender().ep(), buffer, size, tag, &param);
        ASSERT_UCS_PTR_OK(req);
        return req;
    }

    void* recv_nb(void *buffer, size_t size, ucp_tag_t tag, ucp_tag_t tag_mask) {
        ucp_request_param_t param;
        param.op_attr_mask = 0;
        void *req = ucp_tag_recv_nbx(receiver().worker(), buffer, size, tag,
                                     tag_mask, &param);
        ASSERT_UCS_PTR_OK(req);
        return req;
    }

protected:
    void test_mem_types() {
        std::vector<std::vector<ucs_memory_type_t> > pairs =
                ucs::supported_mem_type_pairs();
        for (size_t i = 0; i < pairs.size(); ++i) {
            test_message_sizes(pairs[i][0], pairs[i][1]);
        }
    }

private:

    typedef std::pair<size_t, size_t> chunk_t;

    static void get_test_variants(std::vector<ucp_test_variant>& variants,
                                  uint64_t ctx_features, int test_flags,
                                  const std::string& name) {
        add_variant_with_value(variants, ctx_features, test_flags, name);
        add_variant_with_value(variants, ctx_features,
                               test_flags | TEST_FLAG_RECV_EXP, name + "exp");
        add_variant_with_value(variants, ctx_features,
                               test_flags | TEST_FLAG_SEND_LESS, name + "send_less");
    }

    static void err_handler(void *arg, ucp_ep_h ep, ucs_status_t status) {
    }

    int get_test_flags() {
        return get_variant_value(0);
    }

    ucp_ep_params_t get_ep_params() {
        ucp_ep_params_t ep_params = ucp_test::get_ep_params();
        if (get_test_flags() & TEST_FLAG_PEER_FAILURE) {
            ep_params.field_mask     |= UCP_EP_PARAM_FIELD_ERR_HANDLING_MODE |
                                        UCP_EP_PARAM_FIELD_ERR_HANDLER;
            ep_params.err_mode        = UCP_ERR_HANDLING_MODE_PEER;
            ep_params.err_handler.cb  = err_handler;
            ep_params.err_handler.arg = NULL;
        }
        return ep_params;
    }

    void wait_for_unexp() {
        ucp_tag_message_h msg;
        do {
            ucp_tag_recv_info_t info;
            progress();
            msg = ucp_tag_probe_nb(receiver().worker(), 0, 0, 0, &info);
        } while (msg == NULL);
    }

    void validate(const mem_buffer& send_buf, const mem_buffer& recv_buf,
                  const chunk_t& chunk) {
        size_t offset = chunk.first;
        size_t size   = chunk.second;
        if (!mem_buffer::compare(UCS_PTR_BYTE_OFFSET(send_buf.ptr(), offset),
                                 UCS_PTR_BYTE_OFFSET(recv_buf.ptr(), offset),
                                 size, send_buf.mem_type(), recv_buf.mem_type())) {
            ADD_FAILURE() << "data validation failed at " <<
                             "offset " << offset << " size " << size;
        }
    }

    // TODO add combinations of different datatypes
    void test_xfer(size_t size, unsigned num_iters, unsigned window,
                   ucs_memory_type_t send_mem_type,
                   ucs_memory_type_t recv_mem_type)
    {
        std::vector<ucp_tag_t> tags;
        for (unsigned i = 0; i < num_iters; ++i) {
            tags.push_back(ucs::rand() % 10);
        }

        size_t mem_buffer_size = size * num_iters;
        ASSERT_LT(mem_buffer_size, 2 * UCS_GBYTE);

        mem_buffer send_buf(mem_buffer_size, send_mem_type);
        mem_buffer recv_buf(mem_buffer_size, recv_mem_type);

        mem_buffer::pattern_fill(send_buf.ptr(), send_buf.size(), ucs::rand(),
                                 send_buf.mem_type());

        std::queue< std::pair<size_t,size_t> > chunks;
        std::queue<void*> reqs;
        unsigned iter = 0;
        while (iter < num_iters) {
            size_t offset      = iter * size;
            void *send_ptr     = UCS_PTR_BYTE_OFFSET(send_buf.ptr(), offset);
            void *recv_ptr     = UCS_PTR_BYTE_OFFSET(recv_buf.ptr(), offset);
            ucp_tag_t tag_mask = ucs::rand() % 10;
            size_t send_size   = ((size > 0) &&
                                  (get_test_flags() & TEST_FLAG_SEND_LESS)) ?
                                 (ucs::rand() % size) : size;

            if (get_test_flags() & TEST_FLAG_RECV_EXP) {
                reqs.push(recv_nb(recv_ptr, size, tags[iter], tag_mask));
                reqs.push(send_nb(send_ptr, send_size, tags[iter]));
            } else {
                reqs.push(send_nb(send_ptr, send_size, tags[iter]));
                wait_for_unexp();
                reqs.push(recv_nb(recv_ptr, size, tags[iter], tag_mask));
            }
            chunks.push(std::make_pair(offset, send_size));

            ++iter;
            if ((iter < num_iters) && (reqs.size() >= window)) {
                continue;
            }

            /* Wait for request completion */
            while (!reqs.empty()) {
                request_wait(reqs.front());
                reqs.pop();
            }

            /* Validate receive buffer data */
            while (!chunks.empty()) {
                validate(send_buf, recv_buf, chunks.front());
                chunks.pop();
            }
       }
    }

    void test_message_sizes(ucs_memory_type_t send_mem_type,
                            ucs_memory_type_t recv_mem_type)
    {
        static const size_t MAX_SIZE = (100 * UCS_MBYTE) /
                                       ucs::test_time_multiplier();
        ucs::detail::message_stream ms("INFO");

        ms << ucs_memory_type_names[send_mem_type] << "->" <<
              ucs_memory_type_names[recv_mem_type] << " ";

        /* Test different random sizes */
        for (size_t current_max_size = 128; current_max_size < MAX_SIZE;
             current_max_size *= 4) {

            size_t size        = ucs::rand() % current_max_size;
            unsigned num_iters = ucs_min(30, MAX_SIZE / (size + 1));
            num_iters          = ucs_max(1, num_iters / ucs::test_time_multiplier());

            ms << num_iters << "x" << size << " ";
            fflush(stdout);

            test_xfer(size, num_iters, 10, send_mem_type, recv_mem_type);

            if (HasFailure() || (num_errors() > 0)) {
                break;
            }
       }
    }
};

UCS_TEST_P(test_ucp_tag_proto, default_params) {
    test_mem_types();
}

UCS_TEST_P(test_ucp_tag_proto, rndv_get_zcopy,
           "RNDV_THRESH=0", "RNDV_SCHEME=get_zcopy") {
    test_mem_types();
}

UCS_TEST_P(test_ucp_tag_proto, rndv_put_zcopy,
           "RNDV_THRESH=0", "RNDV_SCHEME=put_zcopy") {
    test_mem_types();
}

UCP_INSTANTIATE_TEST_CASE_GPU_AWARE(test_ucp_tag_proto)
