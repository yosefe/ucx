/*
 * Copyright (C) Mellanox Technologies Ltd. 2020.  ALL RIGHTS RESERVED.
 *
 * See file LICENSE for terms.
 */

#include "ucx_wrapper.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <iostream>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <unistd.h>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <map>
#include <queue>
#include <algorithm>
#include <limits>
#include <malloc.h>
#include <dlfcn.h>

#define ALIGNMENT       4096

/* IO operation type */
typedef enum {
    IO_READ,
    IO_WRITE,
    IO_OP_MAX,
    IO_COMP_MIN  = IO_OP_MAX,
    IO_READ_COMP = IO_COMP_MIN,
    IO_WRITE_COMP
} io_op_t;

static const char *io_op_names[] = {
    "read",
    "write",
    "read completion",
    "write completion"
};

/* test options */
typedef struct {
    std::vector<const char*> servers;
    int                      port_num;
    long                     client_retries;
    double                   client_timeout;
    double                   client_runtime_limit;
    size_t                   iomsg_size;
    size_t                   min_data_size;
    size_t                   max_data_size;
    size_t                   chunk_size;
    long                     iter_count;
    long                     window_size;
    std::vector<io_op_t>     operations;
    unsigned                 random_seed;
    size_t                   num_offcache_buffers;
    bool                     verbose;
    bool                     validate;
} options_t;

#define LOG_PREFIX  "[DEMO]"
#define LOG         UcxLog(LOG_PREFIX)
#define VERBOSE_LOG UcxLog(LOG_PREFIX, _test_opts.verbose)


template<class T, bool use_offcache = false>
class MemoryPool {
public:
    MemoryPool(size_t buffer_size, size_t offcache = 0) :
        _num_allocated(0), _buffer_size(buffer_size) {

        for (size_t i = 0; i < offcache; ++i) {
            _offcache_queue.push(get_free());
        }
    }

    ~MemoryPool() {
        while (!_offcache_queue.empty()) {
            _free_stack.push_back(_offcache_queue.front());
            _offcache_queue.pop();
        }

        if (_num_allocated != _free_stack.size()) {
            LOG << "Some items were not freed. Total:" << _num_allocated
                << ", current:" << _free_stack.size() << ".";
        }

        for (size_t i = 0; i < _free_stack.size(); i++) {
            delete _free_stack[i];
        }
    }

    inline T* get() {
        T* item = get_free();

        if (use_offcache && !_offcache_queue.empty()) {
            _offcache_queue.push(item);
            item = _offcache_queue.front();
            _offcache_queue.pop();
        }

        return item;
    }

    inline void put(T* item) {
        _free_stack.push_back(item);
    }

private:
    inline T* get_free() {
        T* item;

        if (_free_stack.empty()) {
            item = new T(_buffer_size, *this);
            _num_allocated++;
        } else {
            item = _free_stack.back();
            _free_stack.pop_back();
        }
        return item;
    }

private:
    std::vector<T*> _free_stack;
    std::queue<T*>  _offcache_queue;
    uint32_t        _num_allocated;
    size_t          _buffer_size;
};

/**
 * Linear congruential generator (LCG):
 * n[i + 1] = (n[i] * A + C) % M
 * where A, C, M used as in glibc
 */
class IoDemoRandom {
public:
    static void srand(unsigned seed) {
        _seed = seed & _M;
    }

    template <typename T>
    static inline T rand(T min = std::numeric_limits<T>::min(),
                         T max = std::numeric_limits<T>::max() - 1) {
        _seed = (_seed * _A + _C) & _M;
        /* To resolve that LCG returns alternating even/odd values */
        if (max - min == 1) {
            return (_seed & 0x100) ? max : min;
        } else {
            return T(_seed) % (max - min + 1) + min;
        }
    }

private:
    static       unsigned     _seed;
    static const unsigned     _A;
    static const unsigned     _C;
    static const unsigned     _M;
};
unsigned IoDemoRandom::_seed    = 0;
const unsigned IoDemoRandom::_A = 1103515245U;
const unsigned IoDemoRandom::_C = 12345U;
const unsigned IoDemoRandom::_M = 0x7fffffffU;

class P2pDemoCommon : public UcxContext {
public:
    /* data validation header */
    typedef struct __attribute__ ((packed)) {
        uint16_t    chk_sum;
    } chk_hdr_t;

    /* transaction header */
    typedef struct __attribute__ ((packed)) {
        uint32_t    sn;
    } tr_hdr_t;

    /* IO header */
    typedef struct __attribute__ ((packed)) {
        chk_hdr_t   hdr;
        tr_hdr_t    tr;
        io_op_t     op;
        size_t      data_size;
    } iomsg_t;

protected:
    typedef enum {
        XFER_TYPE_SEND,
        XFER_TYPE_RECV
    } xfer_type_t;

    class Buffer {
    public:
        Buffer(size_t size, MemoryPool<Buffer, true>& pool) :
            _capacity(size), _buffer(memalign(ALIGNMENT, size)), _size(0),
            _pool(pool) {
            if (_buffer == NULL) {
                throw std::bad_alloc();
            }
        }

        ~Buffer() {
            free(_buffer);
        }

        void release() {
            _pool.put(this);
        }

        inline void *buffer(size_t offset = 0) const {
            return (uint8_t*)_buffer + offset;
        }

        inline void resize(size_t size) {
            assert(size <= _capacity);
            _size = size;
        }

        inline size_t size() const {
            return _size;
        }

    public:
        const size_t         _capacity;

    private:
        void*                     _buffer;
        size_t                    _size;
        MemoryPool<Buffer, true>& _pool;
    };

    class BufferIov {
    public:
        BufferIov(size_t size, MemoryPool<BufferIov>& pool) : _pool(pool) {
            _iov.reserve(size);
        }

        size_t size() const {
            return _iov.size();
        }

        void init(size_t data_size, MemoryPool<Buffer, true> &chunk_pool,
                  uint32_t sn, bool fill) {
            assert(_iov.empty());

            Buffer *chunk = chunk_pool.get();
            _iov.resize(get_chunk_cnt(data_size, chunk->_capacity));

            size_t remaining = init_chunk(0, chunk, data_size);
            for (size_t i = 1; i < _iov.size(); ++i) {
                remaining = init_chunk(i, chunk_pool.get(), remaining);
            }

            assert(remaining == 0);

            if (fill) {
                fill_data(sn);
            }
        }

        inline Buffer& operator[](size_t i) const {
            return *_iov[i];
        }

        void release() {
            while (!_iov.empty()) {
                _iov.back()->release();
                _iov.pop_back();
            }

            _pool.put(this);
        }

        uint16_t chksum() const {
            return chk_hdr()->chk_sum;
        };

        uint32_t sn() const {
            return tr_hdr()->sn;
        }

        inline uint16_t calc_chksum() const {
            uint16_t chk_sum = ucs_crc16(tr_hdr(),
                                         _iov[0]->size() - sizeof(chk_hdr_t));

            for (size_t i = 1; i < _iov.size(); ++i) {
                chk_sum ^= ucs_crc16(_iov[i]->buffer(), _iov[i]->size());
            }

            return chk_sum;
        }

    private:
        size_t init_chunk(size_t i, Buffer *chunk, size_t remaining) {
            _iov[i] = chunk;
            _iov[i]->resize(std::min(_iov[i]->_capacity, remaining));
            return remaining - _iov[i]->size();
        }

        void fill_data(uint32_t sn) {
            for (size_t i = 0; i < _iov.size(); ++i) {
                uint8_t *buffer = reinterpret_cast<uint8_t*>(_iov[i]->buffer());
                for (size_t j = 0; j < _iov[i]->size(); ++j) {
                    buffer[j] = IoDemoRandom::rand<uint8_t>();
                }
            }

            tr_hdr()->sn       = sn;
            chk_hdr()->chk_sum = calc_chksum();
        }

        chk_hdr_t* chk_hdr() const {
            assert(_iov.size() > 0);
            assert(_iov[0]->size() >= (sizeof(chk_hdr_t) + sizeof(tr_hdr_t)));
            return reinterpret_cast<chk_hdr_t*>(_iov[0]->buffer());
        }

        tr_hdr_t* tr_hdr() const {
            return reinterpret_cast<tr_hdr_t*>(chk_hdr() + 1);
        }

    private:
        std::vector<Buffer*>   _iov;
        MemoryPool<BufferIov>& _pool;
    };

    /* Asynchronous IO message */
    class IoMessage : public UcxCallback {
    public:
        IoMessage(size_t io_msg_size, MemoryPool<IoMessage>& pool) :
            _buffer(malloc(io_msg_size)), _pool(pool),
            _io_msg_size(io_msg_size) {

            if (_buffer == NULL) {
                throw std::bad_alloc();
            }
        }

        void init(io_op_t op, uint32_t sn, size_t data_size, bool validate) {
            iomsg_t *m = reinterpret_cast<iomsg_t *>(_buffer);

            m->tr.sn     = sn;
            m->op        = op;
            m->data_size = data_size;
            if (validate) {
                m->hdr.chk_sum = ucs_crc16(&m->tr, sizeof(*m) - sizeof(m->hdr));
            } else {
                m->hdr.chk_sum = 0;
            }
        }

        ~IoMessage() {
            free(_buffer);
        }

        virtual void operator()(ucs_status_t status) {
            _pool.put(this);
        }

        void *buffer() const {
            return _buffer;
        }

        const iomsg_t* msg() const{
            return reinterpret_cast<iomsg_t*>(buffer());
        }

    private:
        void*                  _buffer;
        MemoryPool<IoMessage>& _pool;
        size_t                 _io_msg_size;
    };

    class SendCompleteCallback : public UcxCallback {
    public:
        SendCompleteCallback(size_t buffer_size,
                             MemoryPool<SendCompleteCallback>& pool) :
            _counter(0), _iov(NULL), _pool(pool) {
        }

        void init(BufferIov* iov) {
            _iov     = iov;
            _counter = iov->size();
            assert(_counter > 0);
        }

        virtual void operator()(ucs_status_t status) {
            if (--_counter > 0) {
                return;
            }

            _iov->release();
            _pool.put(this);
        }

    private:
        size_t                            _counter;
        BufferIov*                        _iov;
        MemoryPool<SendCompleteCallback>& _pool;
    };

    P2pDemoCommon(const options_t& test_opts) :
        UcxContext(test_opts.iomsg_size),
        _test_opts(test_opts),
        _io_msg_pool(test_opts.iomsg_size),
        _send_callback_pool(0),
        _data_buffers_pool(get_chunk_cnt(test_opts.max_data_size,
                                         test_opts.chunk_size)),
        _data_chunks_pool(test_opts.chunk_size, test_opts.num_offcache_buffers) {
    }

    const options_t& opts() const {
        return _test_opts;
    }

    inline size_t get_data_size() {
        return IoDemoRandom::rand(opts().min_data_size,
                                  opts().max_data_size);
    }

    bool send_io_message(UcxConnection *conn, IoMessage *msg) {
        VERBOSE_LOG << "sending IO " << io_op_names[msg->msg()->op] << ", sn "
                    << msg->msg()->tr.sn << " size " << sizeof(iomsg_t);

        /* send IO_READ_COMP as a data since the transaction must be matched
         * by sn on receiver side */
        if (msg->msg()->op == IO_READ_COMP) {
            return conn->send_data(msg->buffer(), opts().iomsg_size,
                                   msg->msg()->tr.sn, msg);
        } else {
            return conn->send_io_message(msg->buffer(), opts().iomsg_size, msg);
        }
    }

    bool send_io_message(UcxConnection *conn, io_op_t op, uint32_t sn,
                         size_t data_size) {
        IoMessage *m = _io_msg_pool.get();
        m->init(op, sn, data_size, opts().validate);
        return send_io_message(conn, m);
    }

    void send_recv_data(UcxConnection* conn, const BufferIov &iov, uint32_t sn,
                        xfer_type_t send_recv_data,
                        UcxCallback* callback = EmptyCallback::get()) {
        for (size_t i = 0; i < iov.size(); ++i) {
            if (send_recv_data == XFER_TYPE_SEND) {
                conn->send_data(iov[i].buffer(), iov[i].size(), sn, callback);
            } else {
                conn->recv_data(iov[i].buffer(), iov[i].size(), sn, callback);
            }
        }
    }

    void send_data(UcxConnection* conn, const BufferIov &iov, uint32_t sn,
                   UcxCallback* callback = EmptyCallback::get()) {
        send_recv_data(conn, iov, sn, XFER_TYPE_SEND, callback);
    }

    void recv_data(UcxConnection* conn, const BufferIov &iov, uint32_t sn,
                   UcxCallback* callback = EmptyCallback::get()) {
        send_recv_data(conn, iov, sn, XFER_TYPE_RECV, callback);
    }

    static uint32_t get_chunk_cnt(size_t data_size, size_t chunk_size) {
        return (data_size + chunk_size - 1) / chunk_size;
    }

    static void validate(uint32_t sn, const BufferIov &iov) {
        if (sn != iov.sn()) {
            LOG << "ERROR: transaction mismatch " << sn << " != " << iov.sn();
            abort();
        }

        /* recalc check sum of all fragments and compare to stored value */
        uint16_t recalc_chksum = iov.calc_chksum();
        if (iov.chksum() != recalc_chksum) {
            LOG << "ERROR: data corruption " << iov.chksum() << " != "
                << recalc_chksum;
            abort();
        }
    }

    void validate(const iomsg_t *msg) {
        if (msg->hdr.chk_sum !=
            ucs_crc16(&msg->tr, sizeof(*msg) - sizeof(msg->hdr))) {
            LOG << "ERROR: corrupted io message";
            abort();
        }
    }

protected:
    const options_t                  _test_opts;
    MemoryPool<IoMessage>            _io_msg_pool;
    MemoryPool<SendCompleteCallback> _send_callback_pool;
    MemoryPool<BufferIov>            _data_buffers_pool;
    MemoryPool<Buffer, true>         _data_chunks_pool;
};

class DemoServer : public P2pDemoCommon {
public:
    // sends an IO response when done
    class IoWriteResponseCallback : public UcxCallback {
    public:
        IoWriteResponseCallback(size_t buffer_size,
            MemoryPool<IoWriteResponseCallback>& pool) :
            _server(NULL), _conn(NULL), _sn(0), _iov(NULL), _pool(pool) {
        }

        void init(DemoServer *server, UcxConnection* conn, uint32_t sn,
                  BufferIov *iov) {
            _server    = server;
            _conn      = conn;
            _sn        = sn;
            _iov       = iov;
            _chunk_cnt = iov->size();
        }

        virtual void operator()(ucs_status_t status) {
            if (--_chunk_cnt > 0) {
                return;
            }

            if (status == UCS_OK) {
                if (_server->opts().validate) {
                    validate(_sn, *_iov);
                }
                _server->send_io_message(_conn, IO_WRITE_COMP, _sn, 0);
            }

            _iov->release();
            _pool.put(this);
        }

    private:
        DemoServer*                          _server;
        UcxConnection*                       _conn;
        uint32_t                             _chunk_cnt;
        uint32_t                             _sn;
        BufferIov*                           _iov;
        MemoryPool<IoWriteResponseCallback>& _pool;
    };

    DemoServer(const options_t& test_opts) :
        P2pDemoCommon(test_opts), _callback_pool(0) {
    }

    void run() {
        struct sockaddr_in listen_addr;
        memset(&listen_addr, 0, sizeof(listen_addr));
        listen_addr.sin_family      = AF_INET;
        listen_addr.sin_addr.s_addr = INADDR_ANY;
        listen_addr.sin_port        = htons(opts().port_num);

        listen((const struct sockaddr*)&listen_addr, sizeof(listen_addr));
        for (;;) {
            try {
                progress();
            } catch (const std::exception &e) {
                std::cerr << e.what();
            }
        }
    }

    void handle_io_read_request(UcxConnection* conn, const iomsg_t *msg) {
        // send data
        VERBOSE_LOG << "sending IO read data";
        assert(opts().max_data_size >= msg->data_size);

        BufferIov *iov           = _data_buffers_pool.get();
        SendCompleteCallback *cb = _send_callback_pool.get();

        iov->init(msg->data_size, _data_chunks_pool, msg->tr.sn,
                  opts().validate);
        cb->init(iov);

        send_data(conn, *iov, msg->tr.sn, cb);

        // send response as data
        VERBOSE_LOG << "sending IO read response";
        IoMessage *response = _io_msg_pool.get();
        response->init(IO_READ_COMP, msg->tr.sn, 0, opts().validate);
        send_io_message(conn, response);
    }

    void handle_io_write_request(UcxConnection* conn, const iomsg_t *msg) {
        VERBOSE_LOG << "receiving IO write data";
        assert(msg->data_size != 0);

        BufferIov *iov             = _data_buffers_pool.get();
        IoWriteResponseCallback *w = _callback_pool.get();

        iov->init(msg->data_size, _data_chunks_pool, msg->tr.sn, false);
        w->init(this, conn, msg->tr.sn, iov);

        recv_data(conn, *iov, msg->tr.sn, w);
    }

    virtual void dispatch_connection_error(UcxConnection *conn) {
        LOG << "deleting connection " << conn;
        delete conn;
    }

    virtual void dispatch_io_message(UcxConnection* conn, const void *buffer,
                                     size_t length) {
        iomsg_t const *msg = reinterpret_cast<const iomsg_t*>(buffer);

        VERBOSE_LOG << "got io message " << io_op_names[msg->op] << " sn "
                    << msg->tr.sn << " data size " << msg->data_size
                    << " conn " << conn;

        if (opts().validate) {
            validate(msg);
        }

        if (msg->op == IO_READ) {
            handle_io_read_request(conn, msg);
        } else if (msg->op == IO_WRITE) {
            handle_io_write_request(conn, msg);
        } else {
            LOG << "Invalid opcode: " << msg->op;
        }
    }

private:
    MemoryPool<IoWriteResponseCallback> _callback_pool;
};


class DemoClient : public P2pDemoCommon {
public:
    typedef struct {
        UcxConnection* conn;
        long           retry_count;               /* Connect retry counter */
        long           num_sent;                  /* Total number of sent operations */
        size_t         active_index;              /* Index in active vector */
        long           num_completed[IO_OP_MAX];  /* Number of completed operations */
        long           prev_completed[IO_OP_MAX]; /* Completed in last report */
    } server_info_t;

    class IoReadResponseCallback : public UcxCallback {
    public:
        IoReadResponseCallback(size_t buffer_size,
            MemoryPool<IoReadResponseCallback>& pool) :
            _comp_counter(0), _io_counter(NULL),
            _server_io_counter(NULL), _sn(0),
            _validate(false), _iov(NULL),
            _buffer(malloc(buffer_size)), _pool(pool) {

            if (_buffer == NULL) {
                throw std::bad_alloc();
            }
        }

        void init(long *io_counter, long *conn_io_counter,
                  uint32_t sn, bool validate, BufferIov *iov) {
            /* wait for all data chunks and the read response completion */
            _comp_counter      = iov->size() + 1;
            _io_counter        = io_counter;
            _server_io_counter = conn_io_counter;
            _sn                = sn;
            _validate          = validate;
            _iov               = iov;
        }

        ~IoReadResponseCallback() {
            free(_buffer);
        }

        virtual void operator()(ucs_status_t status) {
            if (--_comp_counter > 0) {
                return;
            }

            ++(*_io_counter);
            ++(*_server_io_counter);
            if (_validate && (status == UCS_OK)) {
                validate(_sn, *_iov);
            }

            _iov->release();
            _pool.put(this);
        }

        void* buffer() {
            return _buffer;
        }

    private:
        long                                _comp_counter;
        long*                               _io_counter;
        long*                               _server_io_counter;
        uint32_t                            _sn;
        bool                                _validate;
        BufferIov*                          _iov;
        void*                               _buffer;
        MemoryPool<IoReadResponseCallback>& _pool;
    };

    DemoClient(const options_t& test_opts) :
        P2pDemoCommon(test_opts), _prev_connect_time(0),
        _num_sent(0), _num_completed(0),
        _status(OK), _start_time(get_time()),
        _retry(0), _read_callback_pool(opts().iomsg_size) {
    }

    typedef enum {
        OK,
        CONN_RETRIES_EXCEEDED,
        WAIT_RESPONSES_TIMEOUT
    } status_t;

    size_t get_server_index(const UcxConnection *conn) {
        return _server_index_lookup[conn];
    }

    size_t do_io_read(server_info_t& server_info, uint32_t sn) {
        size_t data_size = get_data_size();
        IoMessage *m     = _io_msg_pool.get();

        m->init(IO_READ, sn, data_size, opts().validate);
        if (!send_io_message(server_info.conn, m)) {
            return 0;
        }

        ++server_info.num_sent;
        ++_num_sent;

        BufferIov *iov            = _data_buffers_pool.get();
        IoReadResponseCallback *r = _read_callback_pool.get();

        iov->init(data_size, _data_chunks_pool, sn, false);
        r->init(&_num_completed, &server_info.num_completed[IO_READ], sn,
                opts().validate, iov);

        recv_data(server_info.conn, *iov, sn, r);
        server_info.conn->recv_data(r->buffer(), opts().iomsg_size, sn, r);

        return data_size;
    }

    size_t do_io_write(server_info_t& server_info, uint32_t sn) {
        size_t data_size = get_data_size();

        if (!send_io_message(server_info.conn, IO_WRITE, sn, data_size)) {
            return 0;
        }

        ++server_info.num_sent;
        ++_num_sent;

        BufferIov *iov           = _data_buffers_pool.get();
        SendCompleteCallback *cb = _send_callback_pool.get();

        iov->init(data_size, _data_chunks_pool, sn, opts().validate);
        cb->init(iov);

        VERBOSE_LOG << "sending data " << iov << " size "
                    << data_size << " sn " << sn;
        send_data(server_info.conn, *iov, sn, cb);
        return data_size;
    }

    virtual void dispatch_io_message(UcxConnection* conn, const void *buffer,
                                     size_t length) {
        iomsg_t const *msg = reinterpret_cast<const iomsg_t*>(buffer);

        VERBOSE_LOG << "got io message " << io_op_names[msg->op] << " sn "
                    << msg->tr.sn << " data size " << msg->data_size
                    << " conn " << conn;

        if (msg->op >= IO_COMP_MIN) {
            assert(msg->op == IO_WRITE_COMP);
            ++_num_completed;
            ++_server_info[get_server_index(conn)].num_completed[IO_WRITE];
        }
    }

    long get_num_uncompleted(size_t server_index) const {
        return _server_info[server_index].num_sent -
               (_server_info[server_index].num_completed[IO_READ] +
                _server_info[server_index].num_completed[IO_WRITE]);
    }

    static void reset_server_info(server_info_t& server_info) {
        server_info.conn                   = NULL;
        server_info.num_sent               = 0;
        for (int op = 0; op < IO_OP_MAX; ++op) {
            server_info.num_completed[op]  = 0;
            server_info.prev_completed[op] = 0;
        }
    }

    virtual void dispatch_connection_error(UcxConnection *conn) {
        LOG << "setting error flag on connection " << conn;
        size_t server_index        = get_server_index(conn);
        server_info_t& server_info = _server_info[server_index];

        // Don't wait from completions on this connection
        _num_sent -= get_num_uncompleted(server_index);

        // Remove connection pointer
        _server_index_lookup.erase(conn);
        delete conn;

        // Replace in _active_servers by the last element in the vector
        size_t active_index = server_info.active_index;
        std::swap(_active_servers[active_index], _active_servers.back());
        assert(_active_servers.back() == server_index);

        // Update the active index of the server we swap with
        server_info_t& replacement_server_info =
                _server_info[_active_servers[active_index]];
        assert(replacement_server_info.active_index == _active_servers.size() - 1);
        replacement_server_info.active_index = active_index;

        _active_servers.pop_back();
        reset_server_info(server_info);
    }

    void wait_for_responses(long max_outstanding) {
        struct timeval tv_start = {};
        bool timer_started      = false;
        struct timeval tv_curr, tv_diff;
        long count;

        count = 0;
        while (((_num_sent - _num_completed) > max_outstanding) && (_status == OK)) {
            if (count < 1000) {
                progress();
                ++count;
                continue;
            }

            count = 0;

            gettimeofday(&tv_curr, NULL);

            if (!timer_started) {
                tv_start      = tv_curr;
                timer_started = true;
                continue;
            }

            timersub(&tv_curr, &tv_start, &tv_diff);
            double elapsed = tv_diff.tv_sec + (tv_diff.tv_usec * 1e-6);
            if (elapsed > _test_opts.client_timeout * 10) {
                LOG << "timeout waiting for " << (_num_sent - _num_completed)
                    << " replies";
                _status = WAIT_RESPONSES_TIMEOUT;
            }
        }
    }

    UcxConnection* connect(const char* server) {
        struct sockaddr_in connect_addr;
        std::string server_addr;
        int port_num;

        memset(&connect_addr, 0, sizeof(connect_addr));
        connect_addr.sin_family = AF_INET;

        const char *port_separator = strchr(server, ':');
        if (port_separator == NULL) {
            /* take port number from -p argument */
            port_num    = opts().port_num;
            server_addr = server;
        } else {
            /* take port number from the server parameter */
            server_addr = std::string(server)
                            .substr(0, port_separator - server);
            port_num    = atoi(port_separator + 1);
        }

        connect_addr.sin_port = htons(port_num);
        int ret = inet_pton(AF_INET, server_addr.c_str(), &connect_addr.sin_addr);
        if (ret != 1) {
            LOG << "invalid address " << server_addr;
            return NULL;
        }

        return UcxContext::connect((const struct sockaddr*)&connect_addr,
                                   sizeof(connect_addr));
    }

    static double get_time() {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return tv.tv_sec + (tv.tv_usec * 1e-6);
    }

    const std::string server_name(size_t server_index) {
        std::stringstream ss;
        ss << "server [" << server_index << "] " << opts().servers[server_index];
        return ss.str();
    }

    void connect_failed(size_t server_index) {
        server_info_t& server_info = _server_info[server_index];

        ++server_info.retry_count;

        UcxLog log(LOG_PREFIX);
        log << "Connect to " << server_name(server_index) << " failed"
            << " (retry " << server_info.retry_count;
        if (opts().client_retries < std::numeric_limits<long>::max()) {
            log << "/" << opts().client_retries;
        }
        log << ")";

        if (server_info.retry_count >= opts().client_retries) {
            /* If at least one server exceeded its retries, bail */
            _status = CONN_RETRIES_EXCEEDED;
        }
    }

    void connect_all(bool force) {
        if (_active_servers.size() == _server_info.size()) {
            // All servers are connected
            return;
        }

        if (!force && !_active_servers.empty()) {
            // The active list is not empty, and we don't have to check the
            // connect retry timeout
            return;
        }

        double curr_time = get_time();
        if (curr_time < (_prev_connect_time + opts().client_timeout)) {
            // Not enough time elapsed since previous connection attempt
            return;
        }

        for (size_t server_index = 0; server_index < _server_info.size();
             ++server_index) {
            server_info_t& server_info = _server_info[server_index];
            if (server_info.conn != NULL) {
                // Server is already connected
                continue;
            }

            // If retry count exceeded for at least one server, we should have
            // exited already
            assert(_status == OK);
            assert(server_info.retry_count < opts().client_retries);

            server_info.conn = connect(opts().servers[server_index]);
            if (server_info.conn == NULL) {
                connect_failed(server_index);
                if (_status != OK) {
                    break;
                }
                continue;
            }

            server_info.retry_count = 0;
            _server_index_lookup[server_info.conn] = server_index;

            server_info.active_index = _active_servers.size();
            _active_servers.push_back(server_index);

            LOG << "Connected to " << server_name(server_index);
        }

        _prev_connect_time = curr_time;
    }

    status_t run() {
        _server_info.resize(opts().servers.size());
        std::for_each(_server_info.begin(), _server_info.end(),
                      reset_server_info);

        _status = OK;

        // TODO reset these values by canceling requests
        _num_sent      = 0;
        _num_completed = 0;

        uint32_t sn                  = IoDemoRandom::rand<uint32_t>();
        double prev_time             = get_time();
        long total_iter              = 0;
        long total_prev_iter         = 0;
        op_info_t op_info[IO_OP_MAX] = {{0,0}};

        while ((total_iter < opts().iter_count) && (_status == OK)) {
            VERBOSE_LOG << " <<<< iteration " << total_iter << " >>>>";

            wait_for_responses(opts().window_size - 1);
            if (_status != OK) {
                break;
            }

            connect_all((total_iter % 10) == 0);
            if (_status != OK) {
                break;
            }

            if (_active_servers.empty()) {
                LOG << "All remote servers are down, reconnecting in "
                    << opts().client_timeout << " seconds";
                sleep(opts().client_timeout);
                continue;
            }

            /* Pick random connected server */
            size_t active_index = IoDemoRandom::rand(size_t(0),
                                                     _active_servers.size() - 1);
            size_t server_index = _active_servers[active_index];
            assert(_server_info[server_index].conn != NULL);

            io_op_t op = get_op();
            size_t size;
            switch (op) {
            case IO_READ:
                size = do_io_read(_server_info[server_index], sn);
                break;
            case IO_WRITE:
                size = do_io_write(_server_info[server_index], sn);
                break;
            default:
                abort();
            }

            op_info[op].total_bytes += size;
            op_info[op].num_iters++;

            if (((total_iter % 10) == 0) && (total_iter > total_prev_iter)) {
                /* Print performance every 1 second */
                double curr_time = get_time();
                if (curr_time >= (prev_time + 1.0)) {
                    wait_for_responses(0);
                    if (_status != OK) {
                        break;
                    }

                    report_performance(total_iter - total_prev_iter,
                                       curr_time - prev_time, op_info);
                    total_prev_iter = total_iter;
                    prev_time       = curr_time;
                }
            }

            ++total_iter;
            ++sn;
        }

        wait_for_responses(0);
        if (_status == OK) {
            double curr_time = get_time();
            report_performance(total_iter - total_prev_iter,
                               curr_time - prev_time, op_info);
        }

        for (size_t server_index = 0; server_index < _server_info.size();
             ++server_index) {
            LOG << "Disconnecting from server " << server_name(server_index);
            delete _server_info[server_index].conn;
            _server_info[server_index].conn = NULL;
        }
        _server_index_lookup.clear();
        _active_servers.clear();

        return _status;
    }

    status_t get_status() const {
        return _status;
    }

    static const char* get_status_str(status_t status) {
        switch (status) {
        case OK:
            return "OK";
        case CONN_RETRIES_EXCEEDED:
            return "connection retries exceeded";
        case WAIT_RESPONSES_TIMEOUT:
            return "wait responses timeout";
        default:
            return "invalid status";
        }
    }

private:
    typedef struct {
        long      num_iters;
        size_t    total_bytes;
    } op_info_t;

    inline io_op_t get_op() {
        if (opts().operations.size() == 1) {
            return opts().operations[0];
        }

        return opts().operations[IoDemoRandom::rand(
                                 size_t(0), opts().operations.size() - 1)];
    }

    void report_performance(long num_iters, double elapsed, op_info_t *op_info) {
        if (num_iters == 0) {
            return;
        }

        double latency_usec = (elapsed / num_iters) * 1e6;
        bool first_print    = true;

        UcxLog log(LOG_PREFIX);

        for (unsigned op_id = 0; op_id < IO_OP_MAX; ++op_id) {
            if (!op_info[op_id].total_bytes) {
                continue;
            }

            if (!first_print) {
                log << ", "; // print comma for non-first operation
            }
            first_print = false;

            // Report bandwidth
            double throughput_mbs = op_info[op_id].total_bytes /
                                    elapsed / (1024.0 * 1024.0);
            log << io_op_names[op_id] << " " << throughput_mbs << " MB/s";
            op_info[op_id].total_bytes = 0;

            // Collect min/max among all connections
            long delta_min = std::numeric_limits<long>::max(), delta_max = 0;
            for (size_t server_index = 0; server_index < _server_info.size();
                 ++server_index) {
                server_info_t& server_info = _server_info[server_index];
                long delta_completed = server_info.num_completed[op_id] -
                                       server_info.prev_completed[op_id];
                delta_min = std::min(delta_completed, delta_min);
                delta_max = std::max(delta_completed, delta_max);

                server_info.prev_completed[op_id] =
                        server_info.num_completed[op_id];
            }

            // Report delta of min/max/total operations for every connection
            log << " min:" << delta_min << " max:" << delta_max
                << " total:" << op_info[op_id].num_iters << " ops";
            op_info[op_id].num_iters = 0;
        }

        log << ", active: " << _active_servers.size();

        if (opts().window_size == 1) {
            log << ", latency: " << latency_usec << " usec";
        }
    }

private:
    std::vector<server_info_t>              _server_info;
    std::vector<size_t>                     _active_servers;
    std::map<const UcxConnection*, size_t>  _server_index_lookup;
    double                                  _prev_connect_time;
    long                                    _num_sent;
    long                                    _num_completed;
    status_t                                _status;
    double                                  _start_time;
    unsigned                                _retry;
    MemoryPool<IoReadResponseCallback>      _read_callback_pool;
};

static int set_data_size(char *str, options_t *test_opts)
{
    const static char token = ':';
    char *val1, *val2;

    if (strchr(str, token) == NULL) {
        test_opts->min_data_size =
            test_opts->max_data_size = strtol(str, NULL, 0);
        return 0;
    }

    val1 = strtok(str, ":");
    val2 = strtok(NULL, ":");

    if ((val1 != NULL) && (val2 != NULL)) {
        test_opts->min_data_size = strtol(val1, NULL, 0);
        test_opts->max_data_size = strtol(val2, NULL, 0);
    } else if (val1 != NULL) {
        if (str[0] == ':') {
            test_opts->min_data_size = 0;
            test_opts->max_data_size = strtol(val1, NULL, 0);
        } else {
            test_opts->min_data_size = strtol(val1, NULL, 0);
        }
    } else {
        return -1;
    }

    return 0;
}

static int set_time(char *str, double *dest_p)
{
    char units[3] = "";
    int num_fields;
    double value;
    double per_sec;

    if (!strcmp(str, "inf")) {
        *dest_p = std::numeric_limits<double>::max();
        return 0;
    }

    num_fields = sscanf(str, "%lf%c%c", &value, &units[0], &units[1]);
    if (num_fields == 1) {
        per_sec = 1;
    } else if ((num_fields == 2) || (num_fields == 3)) {
        if (!strcmp(units, "h")) {
            per_sec = 1.0 / 3600.0;
        } else if (!strcmp(units, "m")) {
            per_sec = 1.0 / 60.0;
        } else if (!strcmp(units, "s")) {
            per_sec = 1;
        } else if (!strcmp(units, "ms")) {
            per_sec = 1e3;
        } else if (!strcmp(units, "us")) {
            per_sec = 1e6;
        } else if (!strcmp(units, "ns")) {
            per_sec = 1e9;
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    *(double*)dest_p = value / per_sec;
    return 0;
}

static void adjust_opts(options_t *test_opts) {
    if (test_opts->operations.size() == 0) {
        test_opts->operations.push_back(IO_WRITE);
    }

    test_opts->chunk_size = std::min(test_opts->chunk_size,
                                     test_opts->max_data_size);
}

static int parse_args(int argc, char **argv, options_t *test_opts)
{
    char *str;
    bool found;
    int c;

    test_opts->port_num             = 1337;
    test_opts->client_retries       = std::numeric_limits<long>::max();
    test_opts->client_timeout       = 5.0;
    test_opts->client_runtime_limit = std::numeric_limits<double>::max();
    test_opts->min_data_size        = 4096;
    test_opts->max_data_size        = 4096;
    test_opts->chunk_size           = std::numeric_limits<unsigned>::max();
    test_opts->num_offcache_buffers = 0;
    test_opts->iomsg_size           = 256;
    test_opts->iter_count           = 1000;
    test_opts->window_size          = 1;
    test_opts->random_seed          = std::time(NULL);
    test_opts->verbose              = false;
    test_opts->validate             = false;

    while ((c = getopt(argc, argv, "p:c:r:d:b:i:w:k:o:t:l:s:v:q")) != -1) {
        switch (c) {
        case 'p':
            test_opts->port_num = atoi(optarg);
            break;
        case 'c':
            if (strcmp(optarg, "inf")) {
                test_opts->client_retries = strtol(optarg, NULL, 0);
            }
            break;
        case 'r':
            test_opts->iomsg_size = strtol(optarg, NULL, 0);
            if (test_opts->iomsg_size < sizeof(P2pDemoCommon::iomsg_t)) {
                std::cout << "io message size must be >= "
                          << sizeof(P2pDemoCommon::iomsg_t) << std::endl;
                return -1;
            }
            break;
        case 'd':
            if (set_data_size(optarg, test_opts) == -1) {
                std::cout << "invalid data size range '" << optarg << "'" << std::endl;
                return -1;
            }
            break;
        case 'b':
            test_opts->num_offcache_buffers = strtol(optarg, NULL, 0);
            break;
        case 'i':
            test_opts->iter_count = strtol(optarg, NULL, 0);
            if (test_opts->iter_count == 0) {
                test_opts->iter_count = std::numeric_limits<long int>::max();
            }
            break;
        case 'w':
            test_opts->window_size = atoi(optarg);
            break;
        case 'k':
            test_opts->chunk_size = strtol(optarg, NULL, 0);
            break;
        case 'o':
            str = strtok(optarg, ",");
            while (str != NULL) {
                found = false;

                for (int op_it = 0; op_it < IO_OP_MAX; ++op_it) {
                    if (!strcmp(io_op_names[op_it], str)) {
                        io_op_t op = static_cast<io_op_t>(op_it);
                        if (std::find(test_opts->operations.begin(),
                                      test_opts->operations.end(),
                                      op) == test_opts->operations.end()) {
                            test_opts->operations.push_back(op);
                        }
                        found = true;
                    }
                }

                if (!found) {
                    std::cout << "invalid operation name '" << str << "'" << std::endl;
                    return -1;
                }

                str = strtok(NULL, ",");
            }

            if (test_opts->operations.size() == 0) {
                std::cout << "no operation names were provided '" << optarg << "'" << std::endl;
                return -1;
            }
            break;
        case 't':
            if (set_time(optarg, &test_opts->client_timeout) != 0) {
                std::cout << "invalid '" << optarg << "' value for client timeout" << std::endl;
                return -1;
            }
            break;
        case 'l':
            if (set_time(optarg, &test_opts->client_runtime_limit) != 0) {
                std::cout << "invalid '" << optarg << "' value for client run-time limit" << std::endl;
                return -1;
            }
            break;
        case 's':
            test_opts->random_seed = strtoul(optarg, NULL, 0);
            break;
        case 'v':
            test_opts->verbose = true;
            break;
        case 'q':
            test_opts->validate = true;
            break;
        case 'h':
        default:
            std::cout << "Usage: io_demo [options] [server_address]" << std::endl;
            std::cout << "       or io_demo [options] [server_address0:port0] [server_address1:port1]..." << std::endl;
            std::cout << "" << std::endl;
            std::cout << "Supported options are:" << std::endl;
            std::cout << "  -p <port>                  TCP port number to use" << std::endl;
            std::cout << "  -o <op1,op2,...,opN>       Comma-separated string of IO operations [read|write]" << std::endl;
            std::cout << "                             NOTE: if using several IO operations, performance" << std::endl;
            std::cout << "                                   measurments may be inaccurate" << std::endl;
            std::cout << "  -d <min>:<max>             Range that should be used to get data" << std::endl;
            std::cout << "                             size of IO payload" << std::endl;
            std::cout << "  -b <number of buffers>     Number of offcache IO buffers" << std::endl;
            std::cout << "  -i <iterations-count>      Number of iterations to run communication" << std::endl;
            std::cout << "  -w <window-size>           Number of outstanding requests" << std::endl;
            std::cout << "  -k <chunk-size>            Split the data transfer to chunks of this size" << std::endl;
            std::cout << "  -r <io-request-size>       Size of IO request packet" << std::endl;
            std::cout << "  -c <client retries>        Number of connection retries on client" << std::endl;
            std::cout << "                             (or \"inf\") for failure" << std::endl;
            std::cout << "  -t <client timeout>        Client timeout (or \"inf\")" << std::endl;
            std::cout << "  -l <client run-time limit> Time limit to run the IO client (or \"inf\")" << std::endl;
            std::cout << "                             Examples: -l 17.5s; -l 10m; 15.5h" << std::endl;
            std::cout << "  -s <random seed>           Random seed to use for randomizing" << std::endl;
            std::cout << "  -v                         Set verbose mode" << std::endl;
            std::cout << "  -q                         Enable data integrity and transaction check" << std::endl;
            std::cout << "" << std::endl;
            return -1;
        }
    }

    while (optind < argc) {
        test_opts->servers.push_back(argv[optind++]);
    }

    adjust_opts(test_opts);

    return 0;
}

static int do_server(const options_t& test_opts)
{
    DemoServer server(test_opts);
    if (!server.init()) {
        return -1;
    }

    server.run();
    return 0;
}

static int do_client(const options_t& test_opts)
{
    IoDemoRandom::srand(test_opts.random_seed);
    LOG << "random seed: " << test_opts.random_seed;

    DemoClient client(test_opts);
    if (!client.init()) {
        return -1;
    }

    DemoClient::status_t status = client.run();
    LOG << "Client exit with status '" << DemoClient::get_status_str(status) << "'";
    return (status == DemoClient::OK) ? 0 : -1;
}

static void print_info(int argc, char **argv)
{
    // Process ID and hostname
    char host[64];
    gethostname(host, sizeof(host));
    LOG << "Starting io_demo pid " << getpid() << " on " << host;

    // Command line
    std::stringstream cmdline;
    for (int i = 0; i < argc; ++i) {
        cmdline << argv[i] << " ";
    }
    LOG << "Command line: " << cmdline.str();

    // UCX library path
    Dl_info info;
    int ret = dladdr((void*)ucp_init_version, &info);
    if (ret) {
        LOG << "UCX library path: " << info.dli_fname;
    }
}

int main(int argc, char **argv)
{
    options_t test_opts;
    int ret;

    print_info(argc, argv);

    ret = parse_args(argc, argv, &test_opts);
    if (ret < 0) {
        return ret;
    }

    if (test_opts.servers.empty()) {
        return do_server(test_opts);
    } else {
        return do_client(test_opts);
    }
}
