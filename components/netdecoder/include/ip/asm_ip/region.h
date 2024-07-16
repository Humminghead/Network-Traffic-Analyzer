#pragma once

#include <cstddef>
#include <limits>

namespace common {

/*!
 * \brief Регион значений.
 */
struct region_t {
  size_t begin = 0;                                 //!< Начало региона.
  size_t end = std::numeric_limits<size_t>::max();  //!< Конец региона.

  /*!
   * \brief Проверяет, полное вхождение передаваемого региона в текущий регион.
   * \param o Проверяемый регион.
   * \return bool true - передаваемый регион полностью входит в текущий, false - иначе.
   */
  bool contains(const region_t& o) const {
    return begin <= o.begin && end >= o.end;
  }

  /*!
   * \brief Проверяет перекрытие регионов.
   *        Регионы должны иметь общую и различающиеся области.
   * \param o Проверяемый регион.
   * \return bool true - передаваемый регион пересекается c текущим, false - иначе.
   */
  bool overlaps(const region_t& o) const {
    return  (begin > o.begin && begin < o.end) ||
            (end > o.begin && end < o.end);
  }

  bool operator==(const region_t& o) const {
    return begin == o.begin && end == o.end;
  }

  /*!
   * \brief Вычисляет длину региона.
   * \return size_t Длину региона.
   */
  size_t length() const {
    return end - begin;
  }
};

}