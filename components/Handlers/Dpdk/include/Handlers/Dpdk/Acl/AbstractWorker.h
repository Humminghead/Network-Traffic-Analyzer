#pragma once

#include <cstdint>

namespace Nta::Network {

class AbstractWorker {
public:
    virtual ~AbstractWorker() = default;
    /*!
     * \brief start running the worker thread
     * \param args
     * \return
     */
    virtual int Run(void *args) = 0;

    /*!
     * \brief ask the worker thread to Stop
     */
    virtual auto Stop() -> void = 0;

    /*!
     * \brief GetCoreId
     * \return
     */
    virtual auto GetCoreId() const -> uint32_t = 0;
};
}
