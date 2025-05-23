#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/Acl/Util/Offset.h"
#include "NetDecoder/EtherType.h"
#include <NetDecoder/PacketBase.h>
#include <NetDecoder/Util/Packet.h>
#include <rte_ethdev.h>

namespace Nta::Network {

WorkerAcl::WorkerAcl(
    std::shared_ptr<DpdkDevice> rxDevice,
    std::shared_ptr<DpdkDevice> txDevice,
    std::shared_ptr<RteAclContext> context,
    const uint32_t core)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{context}, m_CoreId{core} {    
    m_QueueIndicesRx.reserve(RTE_MAX_QUEUES_PER_PORT);
    m_QueueIndicesTx.reserve(RTE_MAX_QUEUES_PER_PORT);
}

bool WorkerAcl::run(uint32_t coreId) {
    if (!m_RxDevice)
        return false;

    if (m_CoreId >= RTE_MAX_LCORE) {
        throw std::runtime_error("Illegal core id: " + std::to_string(coreId) + "!");
    }

    if (m_QueueIndicesRx.empty()) {
        for (auto n = 0; n < m_RxDevice->GetRawDevecePtr()->getTotalNumOfRxQueues(); n++) {
            m_QueueIndicesRx.push_back(n);
        }
    }

    if (m_TxDevice && m_QueueIndicesTx.empty()) {
        for (auto n = 0; n < m_TxDevice->GetRawDevecePtr()->getTotalNumOfTxQueues(); n++) {
            m_QueueIndicesTx.push_back(n);
        }
    }

    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        for (const auto &queueIdRx : m_QueueIndicesRx) {
            // Reset all runtime variables
            m_Rv.Reset();

            // Receive packets from RX device
            auto mBufArray = m_RxDevice->GetMbufArray(m_CoreId);
            if (m_Rv.numRxPackets = m_RxDevice->RecivePackets(queueIdRx, mBufArray); m_Rv.numRxPackets > 0) {
                std::for_each_n(std::begin(mBufArray), m_Rv.numRxPackets, [&](rte_mbuf *pktMbuf) {
                    auto data = rte_pktmbuf_mtod_offset(pktMbuf, const uint8_t *, 0);
                    auto len = static_cast<size_t>(rte_pktmbuf_pkt_len(pktMbuf));
                    auto [ok, packet] = m_Decoder.FullProcessing(ETHER_HDR, data, len);

                    (void)ok;
                    (void)packet;

                    // Fill mbuf data
                    pktMbuf->packet_type = Util::GetPacketType(packet);
                    pktMbuf->l2_len = m_Decoder.GetHandledBytesL2();
                    pktMbuf->l3_len = m_Decoder.GetHandledBytesL3();                    
                    pktMbuf->l4_len = m_Decoder.GetHandledBytesL4();

                    // pktMbuf->hash.rss;
                    // pktMbuf->hash.usr = Util::GetPacketHash(HashType::5Tuple);

                    // Create pointers for ACL filter
                    m_AclDataPtrs[m_Rv.n] = nullptr;
                    m_AclDataPtrs[m_Rv.n++] =
                        GetRtePktMbufMtodOffset<IpV4HeaderPtoto>(pktMbuf, m_Decoder.GetHandledBytesL2());
                    m_Decoder.ResetHandledBytes();
                });

                if (auto [ok, matchedRuleIdxs] = m_AclLookUp.Classify(*m_AclContext, m_AclDataPtrs, m_Rv.n); ok) {
                    std::for_each_n(
                        std::begin(matchedRuleIdxs), m_Rv.numRxPackets, [&, pktIndex = size_t{}](auto &ruleIdx) mutable {
                            if (ruleIdx != 0) {
                                m_MatchPackets[m_Rv.matchPacketsCounter] = nullptr;
                                m_MatchPackets[m_Rv.matchPacketsCounter++] = mBufArray[pktIndex];
                            } else {
                                rte_pktmbuf_free(mBufArray[pktIndex]);
                            }
                            mBufArray[pktIndex++] = nullptr;
                        });

                    // Send received packets if it needed
                    if (m_TxDevice && m_Rv.matchPacketsCounter > 0) {
                        m_Rv.numTxPackets = m_TxDevice->SendPackets(0, m_MatchPackets, m_Rv.matchPacketsCounter);

                        /* Free any unsent packets. */
                        if (unlikely(m_Rv.numTxPackets < m_Rv.matchPacketsCounter)) {
                            for (uint16_t buf = m_Rv.numTxPackets; buf < m_Rv.matchPacketsCounter; buf++)
                                rte_pktmbuf_free(m_MatchPackets[buf]);
                        }
                    }
                }
            }
        }
    }
    return m_Stop.load();
}

void WorkerAcl::stop() {
    m_Stop.exchange(true);
}

uint32_t WorkerAcl::getCoreId() const {
    return m_CoreId;
}

void WorkerAcl::SetCoreId(const uint32_t id) {
    m_CoreId = id;
}

void WorkerAcl::SetQueueIdxsRx(const std::vector<int> &idxs) {
    m_QueueIndicesRx = idxs;
}

void WorkerAcl::SetQueueIdxsTx(const std::vector<int> &idxs) {
    m_QueueIndicesTx = idxs;
}

} // namespace Nta::Network
