#pragma once
#include <netkit/http/filter.h>

#include <boost/beast/core/string_type.hpp>
#include <vector>

namespace netkit::http {

class CorsFilter : public Filter {
 public:
  const char* name() const noexcept override { return "CorsFilter"; }

  Result OnIncomingRequest(const Context::Ptr& ctx) override;

  void OnOutgingResponse(const Context::Ptr& ctx,
                         boost::beast::http::response_header<>& resp) override;

  CorsFilter& set_allow_origins(
      const std::vector<std::string>& allow_origins) noexcept;

  CorsFilter& set_allow_headers(
      const std::vector<std::string>& allow_headers) noexcept;

  CorsFilter& set_allow_methods(
      const std::vector<std::string>& allow_methods) noexcept;

  CorsFilter& set_expose_headers(
      const std::vector<std::string>& expose_headers) noexcept;

  CorsFilter& set_max_age(std::int32_t max_age) noexcept {
    max_age_ = std::to_string(max_age);
    return *this;
  }

  CorsFilter& set_allow_credentials(bool allow_credentials) noexcept {
    allow_credentials_ = allow_credentials;
    return *this;
  }

  CorsFilter& set_allow_any_origins(bool allow_any_origins) noexcept {
    allow_any_origins_ = allow_any_origins;
    return *this;
  }

  CorsFilter& set_allow_any_headers(bool allow_any_headers) noexcept {
    allow_any_headers_ = allow_any_headers;
    return *this;
  }

 private:
  Result HandleOptions(const Context::Ptr& ctx) const;

  std::string VerifyOrigin(boost::beast::string_view origin) const;

  std::string Preflight(boost::beast::string_view origin,
                        boost::beast::string_view request_method,
                        boost::beast::string_view request_headers) const;

 private:
  std::vector<std::string> allow_origins_;
  std::vector<std::string> allow_headers_;
  std::string allow_headers_string_;
  std::vector<std::string> allow_methods_;
  std::string allow_methods_string_;
  std::vector<std::string> expose_headers_;
  std::string expose_headers_string_;
  std::string max_age_ = "3600";
  bool allow_credentials_ = false;
  bool allow_any_origins_ = false;
  bool allow_any_headers_ = false;
};

}  // namespace netkit::http
