#include "context.h"

#include "connection.h"

namespace netkit::http {

void Context::ExpiresAfter(const std::chrono::milliseconds& time) {
  std::visit([&](const auto& conn) { conn->ExpiresAfter(time); }, conn_);
}

void Context::ExpiresNever() {
  std::visit([](const auto& conn) { conn->ExpiresNever(); }, conn_);
}

void Context::Response(boost::beast::http::status status, bool keep_alive) {
  boost::beast::http::response<boost::beast::http::empty_body> resp(
      status, parser_.get().version());
  resp.content_length(0);
  resp.keep_alive(keep_alive);
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status) {
  Response(status, parser_.keep_alive());
}

void Context::Response(boost::beast::http::status status, std::string&& body,
                       const char* content_type, bool keep_alive) {
  boost::beast::http::response<boost::beast::http::string_body> resp(
      status, parser_.get().version());
  resp.keep_alive(keep_alive);
  resp.set(boost::beast::http::field::content_type, content_type);
  resp.body() = std::move(body);
  resp.prepare_payload();
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status, std::string&& body,
                       const char* content_type) {
  Response(status, std::move(body), content_type, parser_.keep_alive());
}

}  // namespace netkit::http
