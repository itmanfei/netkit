#pragma once
#include <iomanip>
#include <iostream>
#if 1
#include <syncstream>

#define TRACE_OBJ(tag)        \
  std::osyncstream(std::cout) \
      << "[" << this << "@" << std::setw(32) << tag << "] "

#define TRACE_TEST(tag)       \
  std::osyncstream(std::cout) \
      << "[" << (void*)nullptr << "@" << std::setw(32) << tag << "] "

#else

#define TRACE_OBJ(tag) \
  std::cout << "[" << this << "@" << std::setw(32) << tag << "] "

#define TRACE_TEST(tag) \
  std::cout << "[" << (void*)nullptr << "@" << std::setw(32) << tag << "] "

#endif
