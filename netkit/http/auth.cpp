#include "auth.h"

#include <sstream>
#include <string_view>

#include "../utility.h"

namespace netkit::http {

WwwAuthenticateInfo ParseWwwAuthenticateString(std::string_view www) noexcept {
  WwwAuthenticateInfo info;
  info.success = false;

  do {
    const auto npos = std::string_view::npos;
    auto pos1 = www.find(' ');
    if (pos1 == npos) break;
    info.scheme = www.substr(0, pos1);

    pos1 = www.find("realm=\"");
    if (pos1 == npos) break;
    auto pos2 = www.find('"', pos1 + 7);
    if (pos2 == npos) break;
    info.realm = www.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = www.find("domain=\"");
    if (pos1 != npos) {
      pos2 = www.find('"', pos1 + 8);
      if (pos2 != npos) {
        std::string uri;
        const auto sub = www.substr(pos1 + 8, pos2 - pos1 - 8);
        for (const auto c : sub) {
          if (c != ' ') {
            uri.push_back(c);
          } else {
            if (uri.size() > 0) {
              info.domains.emplace_back(uri);
              uri = "";
            }
          }
        }
        if (uri.size() > 0) {
          info.domains.emplace_back(uri);
        }
      }
    }

    pos1 = www.find("nonce=\"");
    if (pos1 == npos) break;
    pos2 = www.find('"', pos1 + 7);
    if (pos2 == npos) break;
    info.nonce = www.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = www.find("opaque=\"");
    if (pos1 != npos) {
      pos2 = www.find('"', pos1 + 8);
      if (pos2 != npos) {
        info.opaque = www.substr(pos1 + 8, pos2 - pos1 - 8);
      }
    }

    pos1 = www.find("stale=");
    if (pos1 != npos) {
      std::string_view sub;
      pos2 = www.find(',');
      if (pos2 != npos) {
        sub = www.substr(pos1 + 6, pos2 - pos1 - 6);
      } else {
        sub = www.substr(pos1 + 6);
      }
      if (sub.size() == 4) {
        if ((sub[0] == 't' || sub[0] == 'T') &&
            (sub[1] == 'r' || sub[1] == 'R') &&
            (sub[2] == 'u' || sub[2] == 'U') &&
            (sub[3] == 'e' || sub[3] == 'E')) {
          info.stale = true;
        }
      } else {
        info.stale = false;
      }
    }

    pos1 = www.find("algorithm=");
    if (pos1 != npos) {
      pos2 = www.find(',');
      if (pos2 != npos) {
        info.algorithm = www.substr(pos1 + 10, pos2 - pos1 - 10);
      } else {
        info.algorithm = www.substr(pos1 + 10);
      }
    } else {
      info.algorithm = "MD5";
    }

    pos1 = www.find("qop=\"");
    if (pos1 != npos) {
      pos2 = www.find('"', pos1 + 5);
      if (pos2 != npos) {
        std::string qop;
        const auto sub = www.substr(pos1 + 5, pos2 - pos1 - 5);
        for (const auto c : sub) {
          if (c != ',') {
            qop.push_back(c);
          } else {
            if (qop.size() > 0) {
              info.qop_set.insert(qop);
              qop = "";
            }
          }
        }
        if (qop.size() > 0) {
          info.qop_set.insert(qop);
        }
      }
    }

    info.success = true;
  } while (false);
  return info;
}

std::string MakeDigestMd5Response(const std::string& realm,
                                  const std::string& username,
                                  const std::string& password,
                                  const std::string& method,
                                  const std::string& uri,
                                  const std::string& nonce) noexcept {
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri);
  return util::MakeMd5(ha1 + ":" + nonce + ":" + ha2);
}

std::string MakeDigestMd5Response(
    const std::string& realm, const std::string& username,
    const std::string& password, const std::string& method,
    const std::string& uri, const std::string& nonce, std::uint32_t nonce_count,
    const std::string& cnonce) noexcept {
  char nc_hex[10] = {0};
  snprintf(nc_hex, sizeof(nc_hex), "%08x", nonce_count);
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri);
  return util::MakeMd5(ha1 + ":" + nonce + ":" + nc_hex + ":" + cnonce +
                       ":auth:" + ha2);
}

std::string MakeDigestMd5Response(
    const std::string& realm, const std::string& username,
    const std::string& password, const std::string& method,
    const std::string& uri, const std::string& body, const std::string& nonce,
    std::uint32_t nonce_count, const std::string& cnonce) noexcept {
  char nc_hex[10] = {0};
  snprintf(nc_hex, sizeof(nc_hex), "%08x", nonce_count);
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri + ":" + util::MakeMd5(body));
  return util::MakeMd5(ha1 + ":" + nonce + ":" + nc_hex + ":" + cnonce +
                       ":auth-int:" + ha2);
}

std::string MakeDigestAuthorizationString(
    const std::string& username, const std::string& realm,
    const std::string& nonce, const std::string& uri,
    const std::string& response, const std::string& algorithm,
    const std::optional<std::string>& opaque) noexcept {
  std::ostringstream oss;
  oss << "Digest username=\"" << username << "\", realm=\"" << realm
      << "\", nonce=\"" << nonce << "\", uri=\"" << uri << "\", response=\""
      << response << "\", algorithm=" << algorithm;
  if (opaque) {
    oss << ", opaque=\"" << *opaque << "\"";
  }
  return oss.str();
}

std::string MakeDigestAuthorizationString(
    const std::string& username, const std::string& realm,
    const std::string& nonce, std::uint32_t nonce_count, const std::string& uri,
    const std::string& response, const std::string& algorithm,
    const std::string& qop, const std::optional<std::string>& opaque,
    const std::string& cnonce) noexcept {
  char nc_hex[10] = {0};
  snprintf(nc_hex, sizeof(nc_hex), "%08x", nonce_count);
  std::ostringstream oss;
  oss << "Digest username=\"" << username << "\", realm=\"" << realm
      << "\", nonce=\"" << nonce << "\", nc=" << nc_hex << ", uri=\"" << uri
      << "\", response=\"" << response << "\", algorithm=" << algorithm
      << ", qop=" << qop << ", cnonce=\"" << cnonce << "\"";
  if (opaque) {
    oss << ", opaque=\"" << *opaque << "\"";
  }
  return oss.str();
}

}  // namespace netkit::http
