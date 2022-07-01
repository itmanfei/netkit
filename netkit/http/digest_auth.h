#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace netkit::http {

class AuthorizationDigest {
 public:
  std::string username;
  std::string realm;
  std::string nonce;
  std::string uri;
  std::string response;
  std::string algorithm;
  std::uint32_t nc = 0;
  std::optional<std::string> cnonce;
  std::optional<std::string> opaque;
  std::optional<std::string> qop;

  std::string ToString() const noexcept;

  bool ParseFromString(std::string_view str) noexcept;

  bool ParseFromString(const std::string& str) noexcept {
    return ParseFromString(std::string_view(str));
  }

  bool ParseFromString(const char* str, std::size_t size) noexcept {
    return ParseFromString(std::string_view(str, size));
  }
};

class WwwAuthenticateDigest {
 public:
  bool stale = false;
  std::string realm;
  std::string nonce;
  std::string algorithm;
  std::vector<std::string> domains;
  std::optional<std::string> opaque;
  std::unordered_set<std::string> qop_set;

  std::string ToString() const noexcept;

  bool ParseFromString(std::string_view str) noexcept;

  bool ParseFromString(const std::string& str) noexcept {
    return ParseFromString(std::string_view(str));
  }

  bool ParseFromString(const char* str, std::size_t size) noexcept {
    return ParseFromString(std::string_view(str, size));
  }

  std::string MakeResponse(const std::string& username,
                           const std::string& password,
                           const std::string& method,
                           const std::string& uri) const noexcept;

  std::string MakeResponse(const std::string& username,
                           const std::string& password,
                           const std::string& method, const std::string& uri,
                           std::uint32_t nc,
                           const std::string& cnonce) const noexcept;

  std::string MakeResponse(const std::string& username,
                           const std::string& password,
                           const std::string& method, const std::string& uri,
                           const std::string& body, std::uint32_t nc,
                           const std::string& cnonce) const noexcept;
};

}  // namespace netkit::http
