#pragma once

#include "lru_list.h"
#include "pool.h"
#include "initializers.h"
#include <unordered_map>
#include "lru_cache_common.h"

namespace common {
namespace data_management {

// TODO: Сделать опцию аллокации без вызова конструктора.

/*!
 * \brief Статистика lru_cache_t.
 */
struct lru_cache_stat_t {
  size_t allocation_failure = 0; //!< Провалы аллокации записей кэша. Вызвано истощением пула.
  size_t drops = 0;              //!< Количество закрытых записей кэша.
};


/*!
 * \brief Класс кэша с ограниченным временем жизни неиспользуемых элементов.
 *
 * \tparam Key_type Тип ключа записи.
 * \tparam Value_type Тип записи.
 * \tparam Drop_callback Тип callback функтора, вызываемого при удалении записи при тайм-ауте.
 * \tparam Initializer Тип функтора инициализирующего выделяемый объект.
 * \tparam Hash_type Тип хэш функтора.
 */
template <typename Key_type, typename Value_type,
          typename Drop_callback = empty_drop_callback_t<Value_type>,
          typename Initializer = empty_initializer<Value_type>,
          typename Hash_type = std::hash<Key_type>>
class lru_cache_t {
public:

  /*!
   * \brief Тип callback функтора, вызываемого при удалении записи при тайм-ауте.
   */
  using drop_callback_t = Drop_callback;

  /*!
   * \brief Тип функтора инициализирующего выделяемый объект.
   */
  using initializer_t = Initializer;

  /*!
   * \brief Тип функтора хеша.
   */
  using hash_t = Hash_type;

  /*!
   * \brief Результат метода получения записи кэша.
   */
  using get_result_t = get_result_template_t<Value_type>;

public:
  /*!
   * \brief Конструктор.
   * \tparam Args Типы аргументов, передаваемых для создания элементов пула.
   * \param settings Настройки.
   * \param drop_callback Функтор, вызывающийся при удалении элемента по таймауту.
   * \param initializer Функтор, инициализирующий элемент при выделении элемента.
   * \param hash Функтор, расчёта хеша.
   * \param args Аргументы, передаваемые для создания элементов пула.
   */
  template <typename... Args>
  lru_cache_t(const lru_cache_setting_t& settings, const Drop_callback& drop_callback = {},
              const Initializer& initializer = {}, const Hash_type& hash = {},
              Args&&... args)
    : settings_(settings)
    , pool_(settings_.pool_capacity, std::forward<Args>(args)...)
    , cache_map_(0, hash)
    , drop_callback_(drop_callback)
    , initializer_(initializer)
  {
    if (pool_.capacity())
      cache_map_.reserve(settings_.pool_capacity + 1);
  }

  bool contains(const Key_type& key) {
    return cache_map_.find(key) != cache_map_.end();
  }

  template <typename ...Args>
  get_result_t just_get(const Key_type& key, uint32_t tm_s, uint32_t tm_ns, Args&&... args) {

  #if __cplusplus >= 201703L
    auto [it, done] = cache_map_.try_emplace(key, nullptr);
  #else
    auto emplace_result = cache_map_.emplace(key, nullptr);
    auto it = emplace_result.first;
    bool done = emplace_result.second;
  #endif
    if (done) {
      auto& item = it->second;
      item = pool_.allocate();
      if (item == nullptr) {
        stat_.allocation_failure++;
        cache_map_.erase(it);
        return {nullptr, done};
      }
      initializer_(&(item->data.value), std::forward<Args>(args)...);
      lru_.add(item);
      item->data.key = key;
      item->data.tm_s = tm_s;
      item->data.tm_ns = tm_ns;
      return {&(item->data.value), done};
    }
    else {
      auto& item = it->second;
      item->data.tm_s = tm_s;
      item->data.tm_ns = tm_ns;
      lru_.up(item);
      return {&(item->data.value), done};
    }
  }

  template <typename ...Args>
  get_result_t get(const Key_type& key, uint32_t tm_s, uint32_t tm_ns, Args&&... args) {
    remove_old(tm_s);
    return just_get(key, tm_s, tm_ns, std::forward<Args>(args)...);
  }

  Value_type* find(const Key_type& key) {
    auto it = cache_map_.find(key);
    return (it != cache_map_.end()) ? &(it->second->data.value) : nullptr;
  }

  void remove(const Key_type& key) {
  #if __cplusplus >= 201703L
    auto node = cache_map_.extract(key);
    if (!node.empty()) {
      auto item = node.mapped();
  #else
    auto it = cache_map_.find(key);
    if (it != cache_map_.end()) {
      auto item = it->second;
      cache_map_.erase(it);
  #endif
      lru_.del(item);
      pool_.deallocate(item);
    }
  }

  void remove_old(uint32_t tm_s) {
    for (auto item = lru_.last();
        item && (tm_s - item->data.tm_s) >= settings_.element_life_time_s;
        item = lru_.last()
    ) {
      stat_.drops++;
      drop_callback_(item->data.value);
      lru_.del(item);
      cache_map_.erase(item->data.key);
      pool_.deallocate(item);
    }
  }

  template <typename Callback>
  void remove_and_process_old(Callback& callback, uint32_t tm_s, uint32_t tm_ns) {
    uint64_t c_time = common::concatenate_time(tm_s, tm_ns);
    uint64_t limit_time = settings_.life_time_ns();

    for (value_container_t* item = lru_.last();
        item && (c_time - item->data.time_ns()) >= limit_time;
        item = lru_.last()
    ) {
      stat_.drops++;
      drop_callback_(item->data.value);
      callback(item->data.value);
      lru_.del(item);
      cache_map_.erase(item->data.key);
      pool_.deallocate(item);
    }
  }

  void remove_oldest() {
    auto item = lru_.last();
    if (!item) return;
    drop_callback_(item->data.value);
    stat_.drops++;
    lru_.del(item);
    cache_map_.erase(item->data.key);
    pool_.deallocate(item);
  }

  drop_callback_t& drop_callback() {
    return drop_callback_;
  }

  size_t available_count() const { return pool_.available_count(); }

  size_t active_count() const { return pool_.allocated(); }

private:
  /*!
   * \brief Контейнер данных.
   */
  struct payload_container_t {
    payload_container_t() = default;
    template <typename... Args>
    payload_container_t(Args&&... args) : value(std::forward<Args>(args)...) {}
    Value_type value; //!< Данные записи кэша.
    Key_type key;     //!< Ключ записи кэша.
    uint32_t tm_s;    //!< Последний момент доступа к записи.
    uint32_t tm_ns;   //!< Доли секунд момента доступа к записи.
    uint64_t time_ns() const { return common::concatenate_time(tm_s, tm_ns); }
  };

  using lru_t = lru_list_t<payload_container_t>;
  using value_container_t = typename lru_t::item_t;
  using cache_map_t = std::unordered_map<Key_type, value_container_t*, Hash_type>;

  lru_cache_setting_t settings_;
  pool_t<value_container_t> pool_;
  cache_map_t cache_map_;
  lru_t lru_;
  drop_callback_t drop_callback_;
  initializer_t initializer_;

  lru_cache_stat_t stat_;
};

}
}
