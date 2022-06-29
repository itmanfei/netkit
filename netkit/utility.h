#pragma once
#include <algorithm>
#include <string>
#include <string_view>

namespace netkit::util {

static inline void ToLower(std::string& str) noexcept {
  std::transform(str.begin(), str.end(), str.begin(), tolower);
}

static inline void ToUpper(std::string& str) noexcept {
  std::transform(str.begin(), str.end(), str.begin(), toupper);
}

static inline void TrimAllSpace(std::string& str) noexcept {
  str.erase(remove_if(str.begin(), str.end(), isspace), str.end());
}

std::string MakeMd5(const void* bytes, std::size_t bytes_size) noexcept;

static std::string MakeMd5(const std::string& str) noexcept {
  return MakeMd5(str.c_str(), str.size());
}

static std::string MakeMd5(std::string_view str) noexcept {
  return MakeMd5(str.data(), str.size());
}

}  // namespace netkit::util
