#pragma once

#include <rte_mbuf.h>
#include <rte_errno.h>
#include <stdexcept>

class RteMemPool {
    struct rte_mempool *mbuf_mp{nullptr};

  public:
    RteMemPool(
        const char *name,
        unsigned int total_mbuf_num,
        unsigned int mbuf_cache_size,
        uint16_t priv_size,
        uint16_t data_room_size,
        int socket_id) {

        mbuf_mp = rte_pktmbuf_pool_create(name, total_mbuf_num, mbuf_cache_size, priv_size, data_room_size, socket_id);

        if (mbuf_mp == nullptr)
            throw std::runtime_error("Error: can't init mbuf pool: "+ std::string{rte_strerror(rte_errno)});        
    }

    auto GetRteMemPoolPtr() const { return mbuf_mp; }
};
