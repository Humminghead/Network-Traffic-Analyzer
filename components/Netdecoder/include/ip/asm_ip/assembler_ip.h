#pragma once

#include <cstring>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "../../packetbase.h"
#include "../../decoderbase.h"
#include "../ip4parser.h"
#include "../ip6parser.h"
#include "../ipparseresult.h"

#include "assembler_ip_config.h"
#include "assembler.h"
#include "data_management/lru_cache.h"
#include "data_management/lru_cache_common.h"
#include "assembler_stat.h"

namespace preprocessing::ip
{
struct key_t {
    uint32_t id = 0;
    uint32_t src[4] = {0, 0, 0, 0};
    uint32_t dst[4] = {0, 0, 0, 0};

    static key_t generate(uint32_t id_, in6_addr src_, in6_addr dst_) {
        return {
            id_, 
            {src_.__in6_u.__u6_addr32[0], src_.__in6_u.__u6_addr32[1], src_.__in6_u.__u6_addr32[2], src_.__in6_u.__u6_addr32[3]},
            {dst_.__in6_u.__u6_addr32[0], dst_.__in6_u.__u6_addr32[1], dst_.__in6_u.__u6_addr32[2], dst_.__in6_u.__u6_addr32[3]}
        };
    }
    static key_t generate(uint32_t id_, uint32_t src_[4], uint32_t dst_[4]) {
        return {id_, {src_[0], src_[1], src_[2], src_[3]}, {dst_[0], dst_[1], dst_[2], dst_[3]}};
    }
    static key_t generate(uint32_t id_, uint32_t src_, uint32_t dst_) {
        return {id_, {src_, 0, 0, 0}, {dst_, 0, 0, 0}};
    }
    bool operator==(const key_t& other) const { return memcmp(this, &other, sizeof(struct key_t)) == 0; }

    key_t& operator=(const key_t& k) {
        id = k.id;
        src[0] = k.src[0];
        src[1] = k.src[1];
        src[2] = k.src[2];
        src[3] = k.src[3];
        dst[0] = k.dst[0];
        dst[1] = k.dst[1];
        dst[2] = k.dst[2];
        dst[3] = k.dst[3];
        return *this;
    }
};

using cache_value_t = assembly::message_assembler_t;

struct cache_value_initializer_t {
    template <typename... Args>
    void operator()(cache_value_t* data, Args&&...) const
    {
        data->reset();
    }
};

class assembler
{
    bool enabled {false};
    common::data_management::lru_cache_setting_t cache_settings {5, 1024};
    void  set_ip_protocol(protocols::PacketBase& packet, protocols::IpParseResult& res) {
        if (res.frag_hdr) {
            packet.ip6frag = reinterpret_cast<decltype(packet.ip6frag)>(res.frag_hdr);
            const_cast<ip6_frag*>(reinterpret_cast<const ip6_frag*>(packet.ip6frag))->ip6f_nxt = res.payload_proto;
        } else {
            if (res.version == 4)
                const_cast<uint8_t&>(packet.iph->protocol) = res.payload_proto;
            else
                const_cast<ip6_hdr*>(reinterpret_cast<const ip6_hdr*>(packet.ip6h))->ip6_nxt = res.payload_proto;
        }
    }

public:
    assembler(AsmIpConfiguration const& asm_ip_conf, protocols::IpAssemblerStat& stat)
        : enabled(asm_ip_conf.enabled) 
        , cache_settings(asm_ip_conf.cache_ttl_s, asm_ip_conf.pool_capacity)
        , cache_(cache_settings, drop_callback_t(this))
        , stat_(stat)
    {}

    bool addFragment(protocols::PacketBase packet, const uint8_t* &payload, size_t& payload_size) {
        if (!enabled) return false;

        protocols::IpParseResult res {};
        if (!parseFragment(packet, res))
            return false;

        payload = res.payload;
        payload_size = res.payload_len;
        const key_t key = res.version == 4
            ? key_t::generate(res.fragment.id, packet.iph->saddr, packet.iph->daddr)
            : key_t::generate(res.fragment.id, packet.ip6h->ip6_src, packet.ip6h->ip6_dst);

        auto cache_value = cache_.get(key, packet.tm, packet.tm_ns);
        if (!cache_value.value) {
            stat_.cache_empty++;
            cache_.remove_oldest();
            cache_value = cache_.get(key, packet.tm, packet.tm_ns);
        }
        cache_value_t* record = cache_value.value;
        bool is_new = cache_value.is_new;

        if (!record) return false;

        if (is_new) stat_.cache_allocated++;

        auto result = record->push(res.fragment.offset, !res.fragment.more, payload, payload_size);

        switch (result) {
            case cache_value_t::result_e::complete: {
                stat_.assembled_messages++;
                stat_.assembled_fragments += record->fragment_count();

                payload = record->start();
                payload_size = record->data_size();
                // При успешном завершении сборки фрагментированного ipv6-сообщения выполняется
                // установка значения upper-level-протокола в соответствующем заголовке 
                // packet.iph->protocol или packet.ip6h->ip6_nxt или packet.ip6_frag->ip6f_nxt
                // для последующего разбора payload
                set_ip_protocol(packet, res);
                return true;
            } break;

            case cache_value_t::result_e::buffer_oversize: {
                stat_.assembling_failed++;
                stat_.failure_buffer_oversize++;
            } break;
            case cache_value_t::result_e::fragments_overlaps: {
                stat_.assembling_failed++;
                stat_.failure_fragments_overlaps++;
            } break;
            case cache_value_t::result_e::unexpected_end: {
                stat_.assembling_failed++;
                stat_.failure_unexpected_end++;
            } break;
            case cache_value_t::result_e::holes_oversize: {
                stat_.assembling_failed++;
                stat_.failure_holes_oversize++;
            } break;

            default:
                break;
        }
        return false;
    }

    const protocols::IpAssemblerStat& getAssemblerStat() const { return stat_; }

private:
    using initializer_t = cache_value_initializer_t;

    friend class drop_callback_t;
    struct drop_callback_t {
        assembler* assembler_ = nullptr;

        drop_callback_t(assembler* assembler) : assembler_(assembler){};
        void operator()(const cache_value_t& value)
        {
            assembler_->stat_.drop_messages++;
            assembler_->stat_.drop_fragments += value.fragment_count();
        }

        drop_callback_t(drop_callback_t&&) = default;
        drop_callback_t(const drop_callback_t&) = default;
    };

    struct hash_t {
        size_t operator()(const key_t& k) const { 
            return  
                ((static_cast<size_t>(k.src[0]) << 32) | k.dst[0])
                ^ ((static_cast<size_t>(k.src[1]) << 32) | k.dst[1])
                ^ ((static_cast<size_t>(k.src[2]) << 32) | k.dst[2])
                ^ ((static_cast<size_t>(k.src[3]) << 32) | k.dst[3])
                ^ k.id; 
        }
    };

    common::data_management::lru_cache_t<key_t, cache_value_t, drop_callback_t, initializer_t, hash_t> cache_;
    protocols::IpAssemblerStat& stat_;

    bool parseFragment(const protocols::PacketBase& packet, protocols::IpParseResult& res) {
        switch (packet.get_ip_version()) {
        case 4:
            if (!protocols::parseIp4((const uint8_t*)packet.iph, packet.get_total_size(), res))
                return false;
            break;
        case 6:
        {
            if (nullptr == packet.ip6frag)   
                return false;
            if (!protocols::parseIp6((const uint8_t*)packet.ip6h, packet.get_total_size(), res))
                return false;
            break;
        }
        default:
            return false;
        }
        return true;
    }
};
}  // namespace processing::ip
