#include "Handlers/Dpdk/Acl/WorkerAcl.h"
#include "Handlers/Dpdk/Acl/Util/Offset.h"
#include <NetDecoder/PacketBase.h>
#include <rte_ethdev.h>

namespace Nta::Network {

WorkerAcl::WorkerAcl(
    std::shared_ptr<DpdkDevice> rxDevice,
    std::shared_ptr<DpdkDevice> txDevice,
    std::shared_ptr<RteAclContext> context,
    const uint32_t core)
    : m_RxDevice{rxDevice}, m_TxDevice{txDevice}, m_AclContext{context}, m_CoreId{core} {
    m_MatchPackets.reserve(64); // Eq to DpdkDevice::m_BufArray{64};
}

bool WorkerAcl::run(uint32_t coreId) {
    if (!m_RxDevice || !m_TxDevice)
        return false;

    if (m_CoreId == RTE_MAX_LCORE) {
        m_CoreId = coreId;
    }

    m_Stop.exchange(false);

    while (!m_Stop.load()) {
        // receive packets from RX device
        if (uint16_t numOfPackets = m_RxDevice->RecivePackets(0); numOfPackets > 0) {

            auto mBufArray = m_RxDevice->GetMbufArray();

            PrefetchCpuCache(mBufArray, 3); ///\todo add 2 cfg

            std::for_each_n(std::begin(mBufArray), numOfPackets, [&](auto pktMbuf) {
                auto data = rte_pktmbuf_mtod_offset(pktMbuf, const uint8_t *, 0);
                auto len = static_cast<size_t>(rte_pktmbuf_pkt_len(pktMbuf));
                auto [ok, packet] = m_Decoder.FullProcessing(LinkLayer::Eth, data, len);

                (void)ok;
                (void)packet;

                m_AclDataPtrs.push_back(
                    GetRtePktMbufMtodOffset<IpV4HeaderPtoto>(pktMbuf, m_Decoder.GetHandledBytesL2()));
                m_Decoder.ResetHandledBytes();
            });

            if (auto [ok, matchedRuleIdxs] = m_AclLookUp.Classify(*m_AclContext, m_AclDataPtrs); ok) {
                std::for_each_n(
                    std::begin(matchedRuleIdxs), numOfPackets, [&, pktIndex = size_t{}](auto &ruleIdx) mutable {
                        if (ruleIdx != 0)
                            m_MatchPackets.push_back(mBufArray[pktIndex]);
                        pktIndex++;
                    });

                // send received packet on the TX device
                m_TxDevice->SendPackets(0, m_MatchPackets);
                m_MatchPackets.clear();
                m_AclDataPtrs.clear();
            } else {
                ///\todo log
            }

            auto erased = std::erase_if(mBufArray, [](rte_mbuf *buf) {
                if (likely(buf != nullptr)) {
                    rte_pktmbuf_free(buf);
                    return true;
                }
                return false;
            });
            mBufArray.insert(std::end(mBufArray), erased, nullptr);
        } else {
            int a = 0;
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

} // namespace Nta::Network
