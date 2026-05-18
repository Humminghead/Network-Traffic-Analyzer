#pragma once

#include <string>
#include <nlohmann/json.hpp>
#include <Misc.h>

namespace preprocessing::ip
{

struct AsmIpConfiguration {
    bool     enabled       {false};
    size_t   message_size  {64*1024}; //!< размер asm сообщения
    uint32_t cache_ttl_s   {1};       //!< Время жизни элемента кэша.
    uint32_t cache_ttl_ns  {0};       //!< Время жизни элемента кэша в наносекундах.
    size_t   pool_capacity {1024};    //!< Размер пула записей кэша.

    AsmIpConfiguration() = default;
    AsmIpConfiguration(std::string const& confStr) {
        nlohmann::json conf(nlohmann::json::parse(confStr));
        dpi::utils::json::tryGetValue(conf, "enabled",       enabled,       true);
        dpi::utils::json::tryGetValue(conf, "message_size",  message_size,  9000UL);
        dpi::utils::json::tryGetValue(conf, "cache_ttl_s",   cache_ttl_s,   1U);
        dpi::utils::json::tryGetValue(conf, "cache_ttl_ns",  cache_ttl_ns,  0U);
        dpi::utils::json::tryGetValue(conf, "pool_capacity", pool_capacity, 8UL);
        if (!enabled) pool_capacity = 0UL; 
    }
    AsmIpConfiguration(nlohmann::json const& conf) {
        dpi::utils::json::tryGetValue(conf, "enabled",       enabled,       true);
        dpi::utils::json::tryGetValue(conf, "message_size",  message_size,  9000UL);
        dpi::utils::json::tryGetValue(conf, "cache_ttl_s",   cache_ttl_s,   1U);
        dpi::utils::json::tryGetValue(conf, "cache_ttl_ns",  cache_ttl_ns,  0U);
        dpi::utils::json::tryGetValue(conf, "pool_capacity", pool_capacity, 8UL);
        if (!enabled) pool_capacity = 0UL; 
    }
};

}
