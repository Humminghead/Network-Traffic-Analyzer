#pragma once

#include <vector>
#include <unordered_set>

namespace common {
namespace data_management {

template <typename T>
class pool_t {
public:

  template <typename... Args>
  pool_t(size_t capacity, Args&&... args)
    : capacity_(capacity)
  {
    objects_.reserve(capacity_);
    available_.reserve(capacity_);
    for (size_t i = 0; i < capacity_; i++) {
      objects_.emplace_back(std::forward<Args>(args)...);
      available_.emplace(&objects_[i]);
    }
  }

  T* allocate() {
    auto first = available_.begin();
    if (first == available_.end()) {
      //throw std::bad_alloc();
      return nullptr;
    }
    T* element = *first;
    available_.erase(first);
    return element;
  }

  void deallocate(T* element) {
    if (element < std::addressof(objects_.front()) || std::addressof(objects_.back()) < element) {
      // throw some exception;
      return;
    }
    available_.emplace(element);
  }

  size_t available_count() const {
    return available_.size();
  }

  size_t capacity() const {
    return capacity_;
  }

  size_t allocated() const {
    return capacity() - available_count();
  }

private:
  size_t capacity_;
  std::vector<T> objects_;
  std::unordered_set<T*> available_;

};

}
}
