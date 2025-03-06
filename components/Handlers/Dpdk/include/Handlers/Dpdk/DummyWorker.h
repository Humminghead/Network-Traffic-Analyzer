#pragma once

#include <DpdkDeviceList.h>
#include <atomic>
#include <rte_build_config.h>
#include <thread>

namespace Nta::Network {

class Dummy : public pcpp::DpdkWorkerThread {
  private:
    std::atomic_bool m_Stop{true};
    uint32_t m_CoreId{RTE_MAX_LCORE};

  public:
    Dummy() = default;
    virtual ~Dummy() = default;

    /*!
     * \brief start running the worker thread
     * \param coreId
     * \return
     */
    bool run(uint32_t coreId) override {
        m_CoreId = coreId;
        m_Stop.exchange(false);

        while (!m_Stop.load()) {
            using namespace std::chrono;
            std::this_thread::sleep_for(1s);
        }
        return true;
    }

    /*!
     * \brief ask the worker thread to stop
     */
    void stop() override { m_Stop.exchange(true); }

    /*!
     * \brief getCoreId
     * \return
     */
    uint32_t getCoreId() const override { return m_CoreId; }
};




} // namespace Nta::Network
