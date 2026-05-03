#pragma once

#include <rte_errno.h>
#include <rte_mbuf.h>
#include <stdexcept>

class RteMemPool {
    struct rte_mempool *m_mBufPtr{nullptr};

  public:
    /*!
     * \brief RteMemPool
     * \param The name of the mbuf pool.
     * \param The number of elements in the mbuf pool.
     * \param Size of the per-core object cache. See rte_mempool_create() for details.
     * \param     Size of application private are between the rte_mbuf structure
    and the data buffer. This value must be aligned to RTE_MBUF_PRIV_ALIGN.
     * \param Size of data buffer in each mbuf, including RTE_PKTMBUF_HEADROOM
     * \param The socket identifier where the memory should be allocated.
     */
    RteMemPool(
        const char *name,
        unsigned int totalMbufNum,
        unsigned int mbufCacheSize,
        uint16_t privSize,
        uint16_t dataRoomSize,
        int socketId) {

        m_mBufPtr = rte_pktmbuf_pool_create(name, totalMbufNum, mbufCacheSize, privSize, dataRoomSize, socketId);

        if (m_mBufPtr == nullptr)
            throw std::runtime_error("Error: can't init mbuf pool: " + std::string{rte_strerror(rte_errno)});
    }

    /*!
     * \brief Get a mbuf pool ptr.
     */
    auto GetRteMemPoolPtr() const { return m_mBufPtr; }

    /*!
     * \brief Free a mempool
     */
    void Free() noexcept { rte_mempool_free(m_mBufPtr); }
};
