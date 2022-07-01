#include "digest_auth.h"

#include <sstream>

#include "netkit/utility.h"

namespace netkit::http {

std::string AuthorizationDigest::ToString() const noexcept {
  std::ostringstream oss;
  oss << "Digest username=\"" << username << "\", realm=\"" << realm
      << "\", nonce=\"" << nonce << "\", uri=\"" << uri << "\", response=\""
      << response << "\"";
  if (algorithm.size() > 0) {
    oss << ", algorithm=" << algorithm;
  }
  if (cnonce) {
    oss << ", cnonce=\"" << *cnonce << "\"";
  }
  if (opaque) {
    oss << ", opaque=\"" << *opaque << "\"";
  }
  if (qop) {
    oss << ", qop=" << *qop;
  }
  if (nc > 0) {
    char nc_hex[10] = {0};
    snprintf(nc_hex, sizeof(nc_hex), "%08x", nc);
    oss << ", nc=" << nc_hex;
  }
  return oss.str();
}

bool AuthorizationDigest::ParseFromString(std::string_view str) noexcept {
  do {
    const auto npos = std::string_view::npos;
    auto pos1 = str.find("username=\"");
    if (pos1 == npos) break;
    auto pos2 = str.find('"', pos1 + 10);
    if (pos2 == npos) break;
    username = str.substr(pos1 + 10, pos2 - pos1 - 10);

    pos1 = str.find("realm=\"");
    if (pos1 == npos) break;
    pos2 = str.find('"', pos1 + 7);
    if (pos2 == npos) break;
    realm = str.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = str.find("nonce=\"");
    if (pos1 == npos) break;
    pos2 = str.find('"', pos1 + 7);
    if (pos2 == npos) break;
    nonce = str.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = str.find("uri=\"");
    if (pos1 == npos) break;
    pos2 = str.find('"', pos1 + 5);
    if (pos2 == npos) break;
    uri = str.substr(pos1 + 5, pos2 - pos1 - 5);

    pos1 = str.find("response=\"");
    if (pos1 == npos) break;
    pos2 = str.find('"', pos1 + 10);
    if (pos2 == npos) break;
    response = str.substr(pos1 + 10, pos2 - pos1 - 10);

    pos1 = str.find("algorithm=");
    if (pos1 != npos) {
      pos2 = str.find(',', pos1 + 10);
      if (pos2 != npos) {
        algorithm = str.substr(pos1 + 10, pos2 - pos1 - 10);
      } else {
        algorithm = str.substr(pos1 + 10);
      }
    } else {
      algorithm = "MD5";
    }

    pos1 = str.find("opaque=\"");
    if (pos1 != npos) {
      pos2 = str.find('"', pos1 + 8);
      if (pos2 == npos) break;
      opaque = str.substr(pos1 + 8, pos2 - pos1 - 8);
    }

    pos1 = str.find("qop=");
    if (pos1 != npos) {
      pos2 = str.find(',', pos1 + 4);
      if (pos2 != npos) {
        qop = str.substr(pos1 + 4, pos2 - pos1 - 4);
      } else {
        qop = str.substr(pos1 + 4);
      }
    }

    if (qop) {
      if (qop == "auth" || qop == "auth-int") {
        pos1 = str.find("cnonce=\"");
        if (pos1 == npos) break;
        pos2 = str.find('"', pos1 + 8);
        if (pos2 == npos) break;
        cnonce = str.substr(pos1 + 8, pos2 - pos1 - 8);
        pos1 = str.find("nc=");
        if (pos1 == npos) break;
        pos2 = str.find(',', pos1 + 3);
        std::string nc_hex;
        if (pos2 == npos) {
          nc_hex = str.substr(pos1 + 3);
        } else {
          nc_hex = str.substr(pos1 + 3, pos2 - pos1 - 3);
        }
        try {
          nc = std::stoul(nc_hex, nullptr, 16);
        } catch (const std::exception&) {
          nc = 0;
          break;
        }
      } else {
        break;
      }
    }

    return true;
  } while (false);
  return false;
}

std::string WwwAuthenticateDigest::ToString() const noexcept {
  std::ostringstream oss;
  oss << "Digest realm=\"" << realm << "\", nonce=\"" << nonce << "\"";
  if (algorithm.size() > 0) {
    oss << ", algorithm=" << algorithm;
  }
  if (domains.size() > 0) {
    oss << ", domain=\"";
    for (const auto& domain : domains) {
      oss << domain << ",";
    }
    oss.seekp(-1, std::ios::end);
    oss << "\"";
  }
  if (opaque) {
    oss << ", opaque=\"" << *opaque << "\"";
  }
  if (qop_set.size() > 0) {
    oss << ", qop=\"";
    for (const auto& qop : qop_set) {
      oss << qop << ",";
    }
    oss.seekp(-1, std::ios::end);
    oss << "\"";
  }
  if (stale) {
    oss << ", stale=true";
  }
  return oss.str();
}

bool WwwAuthenticateDigest::ParseFromString(std::string_view str) noexcept {
  do {
    const auto npos = std::string_view::npos;
    auto pos1 = str.find("realm=\"");
    if (pos1 == npos) break;
    auto pos2 = str.find('"', pos1 + 7);
    if (pos2 == npos) break;
    realm = str.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = str.find("domain=\"");
    if (pos1 != npos) {
      pos2 = str.find('"', pos1 + 8);
      if (pos2 == npos) break;
      std::string uri;
      const auto sub = str.substr(pos1 + 8, pos2 - pos1 - 8);
      for (const auto c : sub) {
        if (c != ' ') {
          uri.push_back(c);
        } else {
          if (uri.size() > 0) {
            domains.emplace_back(uri);
            uri = "";
          }
        }
      }
      if (uri.size() > 0) {
        domains.emplace_back(uri);
      }
    }

    pos1 = str.find("nonce=\"");
    if (pos1 == npos) break;
    pos2 = str.find('"', pos1 + 7);
    if (pos2 == npos) break;
    nonce = str.substr(pos1 + 7, pos2 - pos1 - 7);

    pos1 = str.find("opaque=\"");
    if (pos1 != npos) {
      pos2 = str.find('"', pos1 + 8);
      if (pos2 == npos) break;
      opaque = str.substr(pos1 + 8, pos2 - pos1 - 8);
    }

    pos1 = str.find("stale=");
    if (pos1 != npos) {
      std::string_view sub;
      pos2 = str.find(',', pos1 + 6);
      if (pos2 != npos) {
        sub = str.substr(pos1 + 6, pos2 - pos1 - 6);
      } else {
        sub = str.substr(pos1 + 6);
      }
      if (sub.size() == 4) {
        if ((sub[0] == 't' || sub[0] == 'T') &&
            (sub[1] == 'r' || sub[1] == 'R') &&
            (sub[2] == 'u' || sub[2] == 'U') &&
            (sub[3] == 'e' || sub[3] == 'E')) {
          stale = true;
        }
      } else {
        stale = false;
      }
    }

    pos1 = str.find("algorithm=");
    if (pos1 != npos) {
      pos2 = str.find(',', pos1 + 10);
      if (pos2 != npos) {
        algorithm = str.substr(pos1 + 10, pos2 - pos1 - 10);
      } else {
        algorithm = str.substr(pos1 + 10);
      }
    } else {
      algorithm = "MD5";
    }

    pos1 = str.find("qop=\"");
    if (pos1 != npos) {
      pos2 = str.find('"', pos1 + 5);
      if (pos2 == npos) break;
      std::string qop;
      const auto sub = str.substr(pos1 + 5, pos2 - pos1 - 5);
      for (const auto c : sub) {
        if (c != ',') {
          qop.push_back(c);
        } else {
          if (qop.size() > 0) {
            qop_set.insert(qop);
            qop = "";
          }
        }
      }
      if (qop.size() > 0) {
        qop_set.insert(qop);
      }
    }

    return true;
  } while (false);
  return false;
}

std::string WwwAuthenticateDigest::MakeResponse(
    const std::string& username, const std::string& password,
    const std::string& method, const std::string& uri) const noexcept {
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri);
  return util::MakeMd5(ha1 + ":" + nonce + ":" + ha2);
}

std::string WwwAuthenticateDigest::MakeResponse(
    const std::string& username, const std::string& password,
    const std::string& method, const std::string& uri, std::uint32_t nc,
    const std::string& cnonce) const noexcept {
  char nc_hex[10] = {0};
  snprintf(nc_hex, sizeof(nc_hex), "%08x", nc);
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri);
  return util::MakeMd5(ha1 + ":" + nonce + ":" + nc_hex + ":" + cnonce +
                       ":auth:" + ha2);
}

std::string WwwAuthenticateDigest::MakeResponse(
    const std::string& username, const std::string& password,
    const std::string& method, const std::string& uri, const std::string& body,
    std::uint32_t nc, const std::string& cnonce) const noexcept {
  char nc_hex[10] = {0};
  snprintf(nc_hex, sizeof(nc_hex), "%08x", nc);
  auto ha1 = util::MakeMd5(username + ":" + realm + ":" + password);
  auto ha2 = util::MakeMd5(method + ":" + uri + ":" + util::MakeMd5(body));
  return util::MakeMd5(ha1 + ":" + nonce + ":" + nc_hex + ":" + cnonce +
                       ":auth-int:" + ha2);
}

}  // namespace netkit::http
