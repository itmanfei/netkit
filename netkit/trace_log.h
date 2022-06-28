#pragma once
#include <iomanip>
#include <iostream>
#include <syncstream>

#if !defined(ENABLE_TRACE_OBJ)

namespace netkit {

class NullBuffer : public std::streambuf {
 public:
  int overflow(int c) override { return c; }
};

class NullStream : public std::ostream {
 public:
  NullStream() : std::ostream(&nullbuf_) {}

  static NullStream& Instance() noexcept {
    static NullStream inst;
    return inst;
  }

 private:
  NullBuffer nullbuf_;
};

}  // namespace netkit

#define TRACE_OBJ(tag) ::netkit::NullStream::Instance()

#else

#define TRACE_OBJ(tag)        \
  std::osyncstream(std::cout) \
      << "[" << this << "@" << std::setw(32) << tag << "] "

#endif

#define TRACE_TEST(tag)       \
  std::osyncstream(std::cout) \
      << "[" << (void*)nullptr << "@" << std::setw(32) << tag << "] "
