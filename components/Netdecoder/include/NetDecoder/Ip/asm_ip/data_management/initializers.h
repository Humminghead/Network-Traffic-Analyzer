#pragma once

#include <utility>

namespace common {
namespace data_management {

/*!
 * \brief Функтор инициализации.
 *        Не производит никаких действий.
 * \tparam T Тип инициализируемого объекта.
 */
template <typename T>
struct empty_initializer {
  template <typename... Args>
  void operator()(T*, Args&&...) const {
  }
};

/*!
 * \brief Функтор инициализации.
 *        Вызывает размещающий new.
 * \tparam T Тип инициализируемого объекта.
 */
template <typename T>
struct placement_new_initializer {
  template <typename... Args>
  void operator()(T* data, Args&&... args) const {
    new (data) T{std::forward<Args>(args)...};
  }
};

}
}
