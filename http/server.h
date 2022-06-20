#pragma once
#include <netkit/http/connection.h>
#include <netkit/http/router.h>
#include <netkit/io_context_pool.h>
#include <netkit/tcp/listener.h>

namespace netkit::http {

template <class T>
class BasicServer : public std::enable_shared_from_this<BasicServer<T>> {
  using Self = BasicServer;
  static constexpr const char* kTag = "http.BasicServer";

 public:
  explicit BasicServer(IoContextPool& pool) noexcept : listener_(pool) {
    static_assert(std::is_same_v<T, PlainConnection>,
                  "The connection type must be <PlainConnection>");
    TRACE_OBJ(kTag) << "Create plain server" << std::endl;
  }

  BasicServer(IoContextPool& pool, boost::asio::ssl::context& ssl_ctx) noexcept
      : listener_(pool), ssl_ctx_(&ssl_ctx) {
    static_assert(
        std::is_same_v<T, SslConnection> || std::is_same_v<T, DetectConnection>,
        "The connection type must be <SslConnection> or "
        "<DetectConnection>");
    TRACE_OBJ(kTag) << "Create ssl server" << std::endl;
  }

  ~BasicServer() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  Settings& settings() noexcept { return settings_; }

  template <class Function>
  void HandleFunc(const std::string& target, Function&& func,
                  const std::vector<std::string>& allowed_methods = {}) {
    router_.AddRoute(target, std::forward<Function>(func), allowed_methods);
  }

  void ListenAndServe(const std::string& address, std::uint16_t port,
                      bool reuse_address = true) {
    listener_.ListenAndAccept(
        address, port, reuse_address,
        std::bind_front(&Self::OnNewConnection, Self::shared_from_this()));
  }

  void Close() noexcept { listener_.Close(); }

 private:
  void OnNewConnection(boost::asio::ip::tcp::socket&& socket) {
    boost::beast::tcp_stream stream(std::move(socket));
    stream.expires_after(settings_.read_timeout());
    std::make_shared<T>(std::move(stream), *ssl_ctx_,
                        boost::beast::flat_buffer{}, settings_, router_)
        ->Run();
  }

 private:
  Router router_;
  Settings settings_;
  tcp::Listener listener_;
  boost::asio::ssl::context* ssl_ctx_ = nullptr;
};

// Only for http
using PlainServer = BasicServer<PlainConnection>;

// Only for https
using SslServer = BasicServer<SslConnection>;

// Both http and https(Automatic detection of http or https)
using DetectServer = BasicServer<DetectConnection>;

}  // namespace netkit::http
