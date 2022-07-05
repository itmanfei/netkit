#include "cors_filter.h"

#include <boost/algorithm/string.hpp>

#include "../utility.h"
#include "connection.h"

namespace netkit::http {

namespace http = boost::beast::http;

Filter::Result CorsFilter::OnIncomingRequest(const Context::Ptr& ctx) {
  ctx->set_origin("");
  auto& req = ctx->parser().get();
  if (req.method() == http::verb::options) {
    return HandleOptions(ctx);
  }
  auto it = req.find(http::field::origin);
  if (it == req.end()) {
    return Result::kPassed;
  }
  auto allowed_origin = VerifyOrigin(it->value());
  if (allowed_origin.empty()) {
    ctx->Forbidden("Origin not allowed", "text/plain", false);
    return Result::kResponded;
  }
  ctx->set_origin(allowed_origin);
  return Result::kPassed;
}

void CorsFilter::OnOutgingResponse(const Context::Ptr& ctx,
                                   http::response_header<>& resp) {
  if (ctx->origin().size() > 0) {
    resp.set(http::field::access_control_allow_origin, ctx->origin());
    if (allow_any_headers_) {
      resp.set(http::field::access_control_allow_headers, "*");
    } else if (allow_headers_string_.size() > 0) {
      resp.set(http::field::access_control_allow_headers,
               allow_headers_string_);
    }
    resp.set(http::field::access_control_allow_methods, allow_methods_string_);
    resp.set(http::field::access_control_max_age, max_age_);
    if (expose_headers_string_.size() > 0) {
      resp.set(http::field::access_control_expose_headers,
               expose_headers_string_);
    }
  }
}

CorsFilter& CorsFilter::set_allow_origins(
    const std::vector<std::string>& allow_origins) noexcept {
  allow_origins_ = allow_origins;
  for (auto& origin : allow_origins_) {
    auto pos = origin.find(":80");
    if (pos == std::string::npos) {
      pos = origin.find(":443");
    }
    if (pos != std::string::npos) {
      origin = origin.substr(0, pos);
    }
    util::ToLower(origin);
  }
  return *this;
}

CorsFilter& CorsFilter::set_allow_headers(
    const std::vector<std::string>& allow_headers) noexcept {
  allow_headers_ = allow_headers;
  allow_headers_string_ = "";
  for (auto& header : allow_headers_) {
    util::ToLower(header);
    allow_headers_string_.append(header);
    allow_headers_string_.append(",");
  }
  if (allow_headers_string_.size() > 0) {
    allow_headers_string_.pop_back();
  }
  return *this;
}

CorsFilter& CorsFilter::set_allow_methods(
    const std::vector<std::string>& allow_methods) noexcept {
  allow_methods_ = allow_methods;
  allow_methods_string_ = "";
  for (auto& method : allow_methods_) {
    util::ToUpper(method);
    allow_methods_string_.append(method);
    allow_methods_string_.append(",");
  }
  if (allow_methods_string_.size() > 0) {
    allow_methods_string_.pop_back();
  }
  return *this;
}

CorsFilter& CorsFilter::set_expose_headers(
    const std::vector<std::string>& expose_headers) noexcept {
  expose_headers_ = expose_headers;
  expose_headers_string_ = "";
  for (const auto& header : expose_headers_) {
    expose_headers_string_.append(header);
    expose_headers_string_.append(",");
  }
  if (expose_headers_string_.size() > 0) {
    expose_headers_string_.pop_back();
  }
  return *this;
}

Filter::Result CorsFilter::HandleOptions(const Context::Ptr& ctx) const {
  auto& parser = ctx->parser();
  http::response<http::empty_body> resp;
  resp.version(parser.get().version());
  if ((parser.content_length() && *parser.content_length() > 0) ||
      parser.chunked()) {
    resp.keep_alive(false);
    resp.result(http::status::payload_too_large);
  } else {
    auto origin = parser.get()[http::field::origin];
    if (origin.size() > 0) {
      auto request_method =
          parser.get()[http::field::access_control_request_method];
      if (request_method.empty()) {
        resp.result(http::status::bad_request);
      } else {
        auto request_headers =
            parser.get()[http::field::access_control_request_headers];
        auto allowed_origin =
            Preflight(origin, request_method, request_headers);
        if (allowed_origin.size() > 0) {
          ctx->set_origin(allowed_origin);
          resp.result(http::status::ok);
        } else {
          resp.result(http::status::forbidden);
        }
      }
    } else {
      resp.result(http::status::ok);
      resp.set(http::field::allow, "*");
      resp.set(http::field::age, "3600");
    }
  }
  ctx->Response(std::move(resp));
  return Result::kResponded;
}

std::string CorsFilter::VerifyOrigin(boost::beast::string_view origin) const {
  std::string allowed_origin;
  if (allow_any_origins_) {
    allowed_origin = "*";
  } else {
    auto pos = origin.find(":80");
    if (pos == std::string::npos) {
      pos = origin.find(":443");
    }
    if (pos != std::string::npos) {
      allowed_origin = origin.substr(0, pos).to_string();
    } else {
      allowed_origin = origin.to_string();
    }
    util::ToLower(allowed_origin);
    auto it = std::find_if(allow_origins_.begin(), allow_origins_.end(),
                           [&allowed_origin](const std::string& item) {
                             return item == allowed_origin;
                           });
    if (it == allow_origins_.end()) {
      allowed_origin = "";
    } else {
      allowed_origin = origin.to_string();
    }
  }
  return allowed_origin;
}

std::string CorsFilter::Preflight(
    boost::beast::string_view origin, boost::beast::string_view request_method,
    boost::beast::string_view request_headers) const {
  auto allowed_origin = VerifyOrigin(origin);
  if (allowed_origin.empty()) {
    return "";
  }
  {
    auto req_method = request_method.to_string();
    util::ToUpper(req_method);
    auto it = std::find_if(allow_methods_.begin(), allow_methods_.end(),
                           [&req_method](const std::string& method) {
                             return method == req_method;
                           });
    if (it == allow_methods_.end()) {
      return "";
    }
  }
  if (!allow_any_headers_ && request_headers.size() > 0) {
    auto req_headers = request_headers.to_string();
    util::TrimAllSpace(req_headers);
    util::ToLower(req_headers);
    std::vector<std::string> vec;
    boost::split(vec, req_headers, boost::is_any_of(","));
    for (const auto& header : vec) {
      auto it = std::find_if(
          allow_headers_.begin(), allow_headers_.end(),
          [&header](const std::string& item) { return item == header; });
      if (it == allow_headers_.end()) {
        return "";
      }
    }
  }
  return allowed_origin;
}

}  // namespace netkit::http
