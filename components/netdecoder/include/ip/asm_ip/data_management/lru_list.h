#pragma once

#include <stdint.h>

namespace common {
namespace data_management {

template<typename Payload_type> class lru_list_t;

/*!
 * \brief Элемент LRU списка.
 * \tparam Payload_type Тип вложенных данных.
 */
template <typename Payload_type>
class lru_list_item_t {
  friend class lru_list_t<Payload_type>;
  lru_list_item_t<Payload_type>* next = nullptr;
  lru_list_item_t<Payload_type>* prev = nullptr;

public:
  Payload_type data;

  /*!
    * \brief Конструктор. 
    * Создает элемент со стандартными указателями на предыдущий и последующий элементы.
    * Вложенные данные создается через конструктор принимающий перечень передаваемых аргументов.
    * \tparam Args Типы аргументов конструктора вложенных данных.
    * \param args Аргументы конструктора вложенных данных.
    */
  template <typename ...Args>
  lru_list_item_t(Args ...args)
    : data(args...)
  {}
};

/*!
 * \brief LRU список.
 * \tparam Payload_type Тип вложения вложенных данных.
 */
template <typename Payload_type>
class lru_list_t {
public:
  using item_t = lru_list_item_t<Payload_type>;

  item_t* first() { return head_; }

  item_t* last() { return (head_ != nullptr) ? head_->prev : head_; }

  void add(item_t* item) {
    if (head_) {
      item->next = head_;
      item->prev = head_->prev;
      head_->prev->next = item;
      head_->prev = item;
    }
    else {
      item->next = item;
      item->prev = item;
    }
    head_ = item;
  }

  void up(item_t* item) {
    del(item);
    add(item);
  }

  void del(item_t* item) {
    lru_list_item_t<Payload_type>* next = item->next;
    lru_list_item_t<Payload_type>* prev = item->prev;

    if (item == head_ && item == item->next) {  // only 1 element
      head_ = nullptr;
    }
    else {
      next->prev = prev;
      prev->next = next;
      if (item == head_) {
        head_ = head_->next;
      }
    }
  }

private:
  item_t* head_ = nullptr;
};

}
}