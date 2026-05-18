#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/Acl/Util/Offset.h"
#include <NetDecoder/PacketBase.h>
#include <NetDecoder/Util/Packet.h>
#include <algorithm>
#include <rte_ethdev.h>

namespace Nta::Network {

WorkerAcl::WorkerAcl(
    std::shared_ptr<DpdkDevice> rxDevice,
    std::shared_ptr<DpdkDevice> txDevice,
    std::shared_ptr<RteAclContext> context,
    const uint16_t linkLayer,
    const uint32_t core,
    const uint16_t nbPkts)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{context}, m_CoreId{core},
      m_PacketBuffers{RTE_MAX_LCORE, MbufArray{nbPkts, nullptr}},
      m_MatchPackets{RTE_MAX_LCORE, MbufArray{nbPkts, nullptr}}, m_AclDataPtrs{nbPkts, nullptr}, m_StopAtEmptyRx{false},
      m_LinkLayer{linkLayer} {
    m_QueueIndicesRx.reserve(RTE_MAX_QUEUES_PER_PORT);
    m_QueueIndicesTx.reserve(RTE_MAX_QUEUES_PER_PORT);
}

int WorkerAcl::Run(void *) {
    if (!m_RxDevice)
        return false;

    if (m_QueueIndicesRx.empty()) {
        for (auto n = 0; n < m_RxDevice->GetTotalNumOfRxQueues(); n++) {
            m_QueueIndicesRx.push_back(n);
        }
    }

    if (m_TxDevice && m_QueueIndicesTx.empty()) {
        for (auto n = 0; n < m_TxDevice->GetTotalNumOfTxQueues(); n++) {
            m_QueueIndicesTx.push_back(n);
        }
    }

    // Open rx-device
    m_RxDevice->Open();

    // Open tx-device
    if (m_TxDevice)
        m_TxDevice->Open();

    // Get packet buffer
    MbufArray pktBuf = m_PacketBuffers.at(m_CoreId);
    if (pktBuf.size() == 0)
        throw std::runtime_error(
            "ACL: The number of packets actually retrieved is 0 for core: " + std::to_string(m_CoreId));

    // Get match buffer
    MbufArray matchPkts = m_MatchPackets.at(m_CoreId);
    if (pktBuf.size() == 0)
        throw std::runtime_error("ACL: The number of match-packets is 0 for core: " + std::to_string(m_CoreId));

    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        for (const auto &queueIdRx : m_QueueIndicesRx) {
            // Reset all runtime variables
            m_Rv.Reset();

            // Receive packets from RX device
            if (m_Rv.numRxPackets = m_RxDevice->RecivePackets(queueIdRx, pktBuf); m_Rv.numRxPackets > 0) {
                std::for_each_n(
                    std::begin(pktBuf), std::min<uint16_t>(m_Rv.numRxPackets, pktBuf.size()), [&](rte_mbuf *pktMbuf) {
                        auto data = rte_pktmbuf_mtod_offset(pktMbuf, const uint8_t *, 0);
                        auto len = static_cast<size_t>(rte_pktmbuf_pkt_len(pktMbuf));
                        auto [ok, packet] = m_Decoder.FullProcessing(m_LinkLayer, data, len);

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
                        std::begin(matchedRuleIdxs),
                        std::min<uint16_t>(m_Rv.numRxPackets, pktBuf.size()),
                        [&, pktIndex = size_t{}](auto &ruleIdx) mutable {
                            if (ruleIdx != 0) {
                                matchPkts[m_Rv.matchPacketsCounter] = nullptr;
                                matchPkts[m_Rv.matchPacketsCounter++] = pktBuf[pktIndex];
                            } else {
                                rte_pktmbuf_free(pktBuf[pktIndex]);
                            }
                            pktBuf[pktIndex++] = nullptr;
                        });

                    // Send received packets if it needed
                    if (m_TxDevice && m_Rv.matchPacketsCounter > 0) {
                        m_Rv.numTxPackets = m_TxDevice->SendPackets(0, matchPkts, m_Rv.matchPacketsCounter);

                        /* Free any unsent packets. */
                        if (unlikely(m_Rv.numTxPackets < m_Rv.matchPacketsCounter)) {
                            for (uint16_t buf = m_Rv.numTxPackets; buf < m_Rv.matchPacketsCounter; buf++)
                                rte_pktmbuf_free(matchPkts[buf]);
                        }
                    }
                }
            } else {
                if (m_StopAtEmptyRx)
                    Stop();
            }
        }
    }

    // Close
    m_RxDevice->Close();
    if (m_TxDevice)
        m_TxDevice->Close();

    return m_Stop.load();
}

void WorkerAcl::Stop() {
    m_Stop.exchange(true);
}

uint32_t WorkerAcl::GetCoreId() const {
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

void WorkerAcl::SetQueueIdxRx(const int &idx) {
    m_QueueIndicesRx.push_back(idx);
}

void WorkerAcl::SetQueueIdxTx(const int &idx) {
    m_QueueIndicesTx.push_back(idx);
}

void WorkerAcl::StopAtEmptyRxEnable(const bool enable) noexcept {
    m_StopAtEmptyRx = enable;
}

} // namespace Nta::Network
