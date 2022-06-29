#pragma once
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace netkit::http {

// RFC2617 3.2.1
struct WwwAuthenticateInfo {
  bool success = false;
  bool stale = false;
  std::string scheme;
  std::string realm;
  std::string nonce;
  std::string algorithm;
  std::vector<std::string> domains;
  std::optional<std::string> opaque;
  std::unordered_set<std::string> qop_set;
};

WwwAuthenticateInfo ParseWwwAuthenticateString(std::string_view www) noexcept;

static inline WwwAuthenticateInfo ParseWwwAuthenticateString(
    const std::string& www) noexcept {
  return ParseWwwAuthenticateString(std::string_view(www));
}

static inline WwwAuthenticateInfo ParseWwwAuthenticateString(
    const char* www, std::size_t size) noexcept {
  return ParseWwwAuthenticateString(std::string_view(www, size));
}

// for no qop
std::string MakeWwwAuthenticateResponse(const std::string& realm,
                                        const std::string& username,
                                        const std::string& password,
                                        const std::string& method,
                                        const std::string& uri,
                                        const std::string& nonce) noexcept;

// for auth
std::string MakeWwwAuthenticateResponse(
    const std::string& realm, const std::string& username,
    const std::string& password, const std::string& method,
    const std::string& uri, const std::string& nonce, std::uint32_t nc,
    const std::string& cnonce) noexcept;

// for auth-int
std::string MakeWwwAuthenticateResponse(
    const std::string& realm, const std::string& username,
    const std::string& password, const std::string& method,
    const std::string& uri, const std::string& body, const std::string& nonce,
    std::uint32_t nc, const std::string& cnonce) noexcept;

}  // namespace netkit::http
