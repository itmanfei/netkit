#include "context.h"

#include "connection.h"

namespace netkit::http {

void Context::set_user_data(std::any&& data) noexcept {
  std::visit(
      [&data](const auto& conn) { conn->set_user_data(std::move(data)); },
      conn_);
}

void Context::Response(boost::beast::http::status status,
                       const HeaderList& headers) {
  Response(status, req_.keep_alive(), headers);
}

void Context::Response(boost::beast::http::status status, bool keep_alive,
                       const HeaderList& headers) {
  boost::beast::http::response<boost::beast::http::empty_body> resp(
      status, req_.version());
  resp.content_length(0);
  resp.keep_alive(keep_alive);
  for (const auto& pair : headers) {
    resp.set(pair.first, pair.second);
  }
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status, std::string&& body,
                       const char* content_type, const HeaderList& headers) {
  Response(status, std::move(body), content_type, req_.keep_alive(), headers);
}

void Context::Response(boost::beast::http::status status, std::string&& body,
                       const char* content_type, bool keep_alive,
                       const HeaderList& headers) {
  boost::beast::http::response<boost::beast::http::string_body> resp(
      status, req_.version());
  resp.keep_alive(keep_alive);
  resp.set(boost::beast::http::field::content_type, content_type);
  for (const auto& pair : headers) {
    resp.set(pair.first, pair.second);
  }
  resp.body() = std::move(body);
  resp.prepare_payload();
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status,
                       const std::string& body, const char* content_type,
                       const HeaderList& headers) {
  Response(status, body, content_type, req_.keep_alive(), headers);
}

void Context::Response(boost::beast::http::status status,
                       const std::string& body, const char* content_type,
                       bool keep_alive, const HeaderList& headers) {
  boost::beast::http::response<boost::beast::http::string_body> resp(
      status, req_.version());
  resp.keep_alive(keep_alive);
  resp.set(boost::beast::http::field::content_type, content_type);
  for (const auto& pair : headers) {
    resp.set(pair.first, pair.second);
  }
  resp.body() = body;
  resp.prepare_payload();
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status, const char* body,
                       const char* content_type, const HeaderList& headers) {
  Response(status, body, content_type, req_.keep_alive(), headers);
}

void Context::Response(boost::beast::http::status status, const char* body,
                       const char* content_type, bool keep_alive,
                       const HeaderList& headers) {
  boost::beast::http::response<boost::beast::http::string_body> resp(
      status, req_.version());
  resp.keep_alive(keep_alive);
  resp.set(boost::beast::http::field::content_type, content_type);
  for (const auto& pair : headers) {
    resp.set(pair.first, pair.second);
  }
  resp.body() = body;
  resp.prepare_payload();
  Response(std::move(resp));
}

void Context::Response(boost::beast::http::status status, const char* body,
                       std::size_t size, const char* content_type,
                       const HeaderList& headers) {
  Response(status, body, size, content_type, req_.keep_alive(), headers);
}

void Context::Response(boost::beast::http::status status, const char* body,
                       std::size_t size, const char* content_type,
                       bool keep_alive, const HeaderList& headers) {
  boost::beast::http::response<boost::beast::http::string_body> resp(
      status, req_.version());
  resp.keep_alive(keep_alive);
  resp.set(boost::beast::http::field::content_type, content_type);
  for (const auto& pair : headers) {
    resp.set(pair.first, pair.second);
  }
  resp.body().append(body, size);
  resp.prepare_payload();
  Response(std::move(resp));
}

}  // namespace netkit::http
