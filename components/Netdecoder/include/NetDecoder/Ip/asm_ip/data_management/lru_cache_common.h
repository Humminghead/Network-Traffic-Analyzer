#pragma once

#include <stdint.h>
#include <cstddef>

namespace common {

inline uint64_t concatenate_time(uint32_t sec, uint32_t nsec) {
  return (static_cast<uint64_t>(sec) * 1'000'000'000) + nsec;
}

namespace data_management {

/*!
 * \brief Настройки lru_cache_t.
 */
struct lru_cache_setting_t {
  uint32_t element_life_time_s = 0; //!< Время жизни элемента кэша.
  uint32_t element_life_time_ns = 0;//!< Время жизни элемента кэша в наносекундах.
  size_t pool_capacity = 0;         //!< Размер пула записей кэша.

  lru_cache_setting_t(uint32_t ttl_s, size_t capacity) 
    : element_life_time_s(ttl_s)
    , element_life_time_ns(0)
    , pool_capacity(capacity)
  {}

  lru_cache_setting_t(uint32_t ttl_s, uint32_t ttl_ns, size_t capacity) 
    : element_life_time_s(ttl_s)
    , element_life_time_ns(ttl_ns)
    , pool_capacity(capacity)
  {}

  lru_cache_setting_t(const lru_cache_setting_t&) = default;
  lru_cache_setting_t& operator=(const lru_cache_setting_t&) = default;

  uint64_t life_time_ns() const {
    return common::concatenate_time(element_life_time_s, element_life_time_ns);
  }
};

/*!
 * \brief Структура времени.
 */
struct time_t {
  uint32_t secs = 0;  //!< Секунды.
  uint32_t nsecs = 0; //!< Доли секунд (в наносекундах).
};

/*!
 * \brief Результат метода получения записи кэша.
 */
template <typename Value_type>
struct get_result_template_t {
  Value_type* value = nullptr;  //!< Данные
  bool is_new = false;          //!< Флаг создания нового элемента.
};

/*!
 * \brief Стандартный функтор, вызывающийся при удалении элемента.
 *        Не выполняет ничего.
 * \tparam T Тип аргумента.
 */
template <typename T>
struct empty_drop_callback_t {
  void operator()(const T&) {};
};

}
}
