#pragma once
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace netkit::http {

class Filter;

class Settings {
 public:
  using FilterList = std::vector<std::shared_ptr<Filter>>;

  std::uint32_t header_limit() const noexcept { return header_limit_; }

  Settings& set_header_limit(std::uint32_t val) noexcept {
    header_limit_ = val;
    return *this;
  }

  const std::optional<std::uint64_t>& body_limit() const noexcept {
    return body_limit_;
  }

  Settings& set_body_limit(const std::optional<std::uint64_t>& val) noexcept {
    body_limit_ = val;
    return *this;
  }

  const std::chrono::milliseconds& read_timeout() const noexcept {
    return read_timeout_;
  }

  Settings& set_read_timeout(const std::chrono::milliseconds& val) noexcept {
    read_timeout_ = val;
    return *this;
  }

  const FilterList& filters() const noexcept { return filters_; }

  Settings& AddFilter(const std::shared_ptr<Filter>& filter) {
    filters_.emplace_back(filter);
    return *this;
  }

 private:
  std::uint32_t header_limit_ = 8 * 1024;
  std::optional<std::uint64_t> body_limit_ = 1024 * 1024;
  std::chrono::milliseconds read_timeout_ = std::chrono::seconds(60);
  FilterList filters_;
};

}  // namespace netkit::http
