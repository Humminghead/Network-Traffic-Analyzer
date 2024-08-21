#pragma once

template <class T>
static inline const T shift_rigth(T& size, const T shift) { size += shift; return shift; }

template <class T>
static inline const T shift_left(T& size, const T shift) { size -= shift; return shift; }
