#pragma once

#include "region.h"

#include <cstdint>
#include <cstring>
#include <vector>
#include <iostream>
#include <iomanip>

namespace preprocessing {
namespace assembly {

/*!
 * \brief Размер буфера сообщений.
 */
constexpr size_t message_buffer_capacity = 64 * 1024;

/*!
 * \brief Изначальный размер вектора пустых областей сообщения.
 */
constexpr size_t holes_capacity = 7;

/*!
 * \brief Сборщик сообщения из сегментов.
 * Собирает сообщение из сегментов, отслеживая незаполненны области сообщения.
 * Может применяться для сборке сообщений при неупорядоченном поступлении фрагментов.
 */
class message_assembler_t {

    std::vector<common::region_t> holes_;     //!< Незаполненные области сообщения.
    size_t fragment_count_ = 0;               //!< Количество сохраненных фрагментов.
    size_t data_size_ = 0;                    //!< Объем данных сообщения.
    uint8_t buffer_[message_buffer_capacity]; //!< Буфер сообщения.

public:

    message_assembler_t() {
      holes_.reserve(holes_capacity);
    }

    /*!
     * \brief Инициализирует объект стандартными значениями.
     */
    void reset() {
      data_size_ = 0;
      fragment_count_ = 0;
      holes_.clear();
      holes_.push_back(common::region_t{});
    }

    /*!
     * \brief Статус сборки сообщения и обработки фрагмента.
     */
    enum class result_e {
      complete,             //!< Сообщение успешно собрано.
      incomplete,           //!< Фрагмент успешно обработан.
      buffer_oversize,      //!< Превышен размер буфера сообщения.
      fragments_overlaps,   //!< Фрагмент частично или полностью накладывается на уже сохраненный фрагмент.
      unexpected_end,       //!< Пришел конечный фрагмент в позицию до полученного ранее конечного фрагмента.
      holes_oversize,       //!< Превышено количество пустых регионов.
    };

    /*!
     * \brief Обрабатывает фрагмент, для сборки сообщения.
     * \param offset Смещение фрагмента.
     * \param is_last_fragment Флаг конечного фрагмент.
     * \param data Данные фрагмента.
     * \param size Длина фрагмента.
     * \return result_e Статус сборки сообщения и обработки фрагмента.
     */
    result_e push(uint16_t offset, bool is_last_fragment, const uint8_t* data, size_t size) {

      if (offset + size > message_buffer_capacity) {
        return result_e::buffer_oversize;
      }

      common::region_t fragment {offset, offset + size};
      bool was_insertion = false;

      for (auto hole = holes_.begin(); hole != holes_.end(); ++hole) {
        if (hole->contains(fragment)) {

          if (is_last_fragment) {

            // Проверка конечного фрагмента.
            // Этот фрагмент соответствует последней из holes_
            // Но приходит не обязательно последним. Критерий успешного завершения - отсутствие holes_.
            if ((data_size_ + size) > holes_.back().end) { 
              return result_e::unexpected_end;
            }
            if (std::addressof(*hole) == std::addressof(holes_.back()))
              hole->end = fragment.end;
            else
              holes_.pop_back();
          }

          if (*hole == fragment)  holes_.erase(hole);
          else if (hole->begin == fragment.begin) hole->begin = fragment.end;
          else if (hole->end == fragment.end) hole->end = fragment.begin;
          else {
            if (holes_.size() >= holes_capacity) {
              return result_e::holes_oversize;
            }
            auto tmp_hole_begin = hole->begin;
            hole->begin = fragment.end;
            holes_.insert(hole, {tmp_hole_begin, fragment.begin});
          }

          std::memcpy(buffer_ + offset, data, size);
          fragment_count_++;
          data_size_ += size;

          was_insertion = true;
          break;
        }
      }

      if (!was_insertion) {
        return result_e::fragments_overlaps;
      }

      return holes_.empty() ? result_e::complete : result_e::incomplete;
    }

    /*!
     * \brief Возвращает количество собранных фрагментов.
     * \return size_t Количество собранных фрагментов.
     */
    size_t fragment_count() const {return fragment_count_;}

    /*!
     * \brief Возвращает начало буфера собранного сообщения.
     * \return uint8_t* Начало буфера собранного сообщения.
     */
    uint8_t* start() { return buffer_; }
    /*!
     * \brief Возвращает начало буфера собранного сообщения.
     * \return uint8_t* Начало буфера собранного сообщения.
     */
    const uint8_t* start() const { return buffer_; }

    /*!
     * \brief Возвращает конец буфера собранного сообщения.
     * \return uint8_t* Конец буфера собранного сообщения.
     */
    uint8_t* end() { return buffer_ + data_size_; }
    /*!
     * \brief Возвращает конец буфера собранного сообщения.
     * \return uint8_t* Конец буфера собранного сообщения.
     */
    const uint8_t* end() const { return buffer_ + data_size_; }

    /*!
     * \brief Возвращает размер собранного сообщения.
     * \return size_t Размер собранного сообщения.
     */
    size_t data_size() const {
      return data_size_;
    }

    size_t collected_size() const {
      if (holes_.empty())
        return 0;

      size_t size = 0;
      size_t data_begin = 0;
      for (const auto& hole : holes_) {
        size += hole.begin - data_begin;
        data_begin = hole.end;
      }

      if (data_size_) {
        size += data_size_ - data_begin;
      }

      return size;
    }

};

}
}
