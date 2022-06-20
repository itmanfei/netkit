#pragma once
#include <netkit/http/context.h>
#include <netkit/http/filter.h>
#include <netkit/http/router.h>
#include <netkit/http/settings.h>
#include <netkit/trace_log.h>

#include <boost/beast/ssl.hpp>
#include <memory>

namespace netkit::http {

template <class T>
class BasicConnection {
  friend class Context;
  using Self = BasicConnection;
  static constexpr const char* kTag = "http.BasicConnection";

 public:
  BasicConnection(boost::beast::flat_buffer&& buffer, Settings& settings,
                  Router& router) noexcept
      : buffer_(std::move(buffer)), settings_(settings), router_(router) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
  }

  ~BasicConnection() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

 protected:
  T& Derived() noexcept { return static_cast<T&>(*this); }

  void ExpiresAfter(const std::chrono::milliseconds& time) {
    boost::beast::get_lowest_layer(Derived().stream()).expires_after(time);
  }

  void ExpiresNever() {
    boost::beast::get_lowest_layer(Derived().stream()).expires_never();
  }

  void ReadHeader() {
    parser_.emplace();
    parser_->header_limit(settings_.header_limit());
    if (settings_.body_limit()) {
      parser_->body_limit(*settings_.body_limit());
    } else {
      parser_->body_limit(boost::none);
    }
    boost::beast::http::async_read_header(
        Derived().stream(), buffer_, *parser_,
        std::bind_front(&Self::OnReadHeader, Derived().shared_from_this()));
  }

  void OnReadHeader(const boost::beast::error_code& ec,
                    std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (ec) {
      TRACE_OBJ(kTag) << "Read header " << ec << std::endl;
      if (ec == boost::beast::http::error::end_of_stream) {
        Derived().DoEof();
      }
    } else {
      ExpiresNever();
      auto ctx = std::make_shared<Context>(
          std::static_pointer_cast<Self>(Derived().shared_from_this()),
          *parser_);
      for (const auto& filter : settings_.filters()) {
        if (filter->OnIncomingRequest(ctx) == Filter::Result::kResponded) {
          return;
        }
      }
      try {
        const auto method = parser_->get().method_string();
        const auto target = parser_->get().target();
        router_.Routing(ctx, method.to_string(),
                        std::string_view(target.data(), target.size()));
      } catch (const std::exception& e) {
        return ctx->BadRequest(e.what(), "text/plain", false);
      }
    }
  }

  template <class Handler>
  void ReadSome(void* buf, std::size_t size, Handler&& handler) {
    parser_->get().body().data = buf;
    parser_->get().body().size = size;
    boost::beast::http::async_read(Derived().stream(), buffer_, *parser_,
                                   std::forward<Handler>(handler));
  }

  template <class Handler>
  void ReadAll(void* buf, std::size_t size, Handler&& handler) {
    ReadSome(buf, size,
             std::bind_front(&Self::OnReadSome<Handler>, this, (char*)buf, size,
                             0, std::forward<Handler>(handler)));
  }

  template <class Handler>
  void OnReadSome(char* buf, std::size_t size, std::size_t total_transferred,
                  Handler&& handler, boost::beast::error_code&& ec,
                  std::size_t bytes_transferred) {
    total_transferred += bytes_transferred;
    if (ec == boost::beast::http::error::need_buffer) {
      ec = {};
    }
    if (ec) {
      handler(ec, total_transferred);
    } else {
      buf += bytes_transferred;
      size -= bytes_transferred;
      if (parser_->is_done()) {
        handler(ec, total_transferred);
      } else {
        ReadSome(
            buf, size,
            std::bind_front(&Self::OnReadSome<Handler>, this, buf, size,
                            total_transferred, std::forward<Handler>(handler)));
      }
    }
  }

  template <class Body>
  void Response(const Context::Ptr& ctx,
                boost::beast::http::response<Body>&& resp) {
    if (!resp.has_content_length() && !resp.chunked()) {
      resp.content_length(0);
    }
    const auto method = parser_->get().method_string();
    const auto target = parser_->get().target();
    for (const auto& filter : settings_.filters()) {
      filter->OnOutgingResponse(ctx, resp);
    }
    auto sp =
        std::make_shared<boost::beast::http::response<Body>>(std::move(resp));
    resp_ = sp;
    boost::beast::http::async_write(
        Derived().stream(), *sp,
        std::bind_front(&Self::OnWrite, Derived().shared_from_this(),
                        !sp->keep_alive()));
  }

  void OnWrite(bool close, const boost::beast::error_code& ec,
               std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    resp_ = nullptr;
    if (!ec) {
      if (close) {
        Derived().DoEof();
      } else {
        ExpiresAfter(settings_.read_timeout());
        ReadHeader();
      }
    } else {
      TRACE_OBJ(kTag) << "Write " << ec << std::endl;
    }
  }

 protected:
  boost::beast::flat_buffer buffer_;
  Settings& settings_;
  Router& router_;
  std::optional<Parser> parser_;
  std::shared_ptr<void> resp_;
};

class PlainConnection : public BasicConnection<PlainConnection>,
                        public std::enable_shared_from_this<PlainConnection> {
  static constexpr const char* kTag = "http.PlainConnection";

 public:
  PlainConnection(boost::beast::tcp_stream&& stream,
                  boost::asio::ssl::context& ssl_ctx,
                  boost::beast::flat_buffer&& buffer, Settings& settings,
                  Router& router) noexcept
      : BasicConnection(std::move(buffer), settings, router),
        stream_(std::move(stream)) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
  }

  ~PlainConnection() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  void Run() { ReadHeader(); }

  boost::beast::tcp_stream& stream() noexcept { return stream_; }

  void DoEof() {
    boost::beast::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    if (ec) {
      TRACE_OBJ(kTag) << "Shotdown " << ec << std::endl;
    }
  }

 private:
  boost::beast::tcp_stream stream_;
};

class SslConnection : public BasicConnection<SslConnection>,
                      public std::enable_shared_from_this<SslConnection> {
  using Self = SslConnection;
  static constexpr const char* kTag = "http.SslConnection";

 public:
  SslConnection(boost::beast::tcp_stream&& stream,
                boost::asio::ssl::context& ssl_ctx,
                boost::beast::flat_buffer&& buffer, Settings& settings,
                Router& router) noexcept
      : BasicConnection(std::move(buffer), settings, router),
        stream_(std::move(stream), ssl_ctx) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
  }

  ~SslConnection() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  void Run() {
    stream_.async_handshake(
        boost::asio::ssl::stream_base::server, buffer_.data(),
        std::bind_front(&Self::OnHandshake, shared_from_this()));
  }

  boost::beast::ssl_stream<boost::beast::tcp_stream>& stream() noexcept {
    return stream_;
  }

  void DoEof() {
    stream_.async_shutdown(
        std::bind_front(&Self::OnShutdown, shared_from_this()));
  }

 private:
  void OnHandshake(const boost::beast::error_code& ec, std::size_t bytes_used) {
    if (!ec) {
      buffer_.consume(bytes_used);
      ReadHeader();
    } else {
      TRACE_OBJ(kTag) << "Handshake " << ec << std::endl;
    }
  }

  void OnShutdown(const boost::beast::error_code& ec) {
    if (ec) {
      TRACE_OBJ(kTag) << "Shotdown " << ec << std::endl;
    }
  }

 private:
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
};

class DetectConnection : public std::enable_shared_from_this<DetectConnection> {
  using Self = DetectConnection;
  static constexpr const char* kTag = "http.DetectConnection";

 public:
  DetectConnection(boost::beast::tcp_stream&& stream,
                   boost::asio::ssl::context& ssl_ctx,
                   boost::beast::flat_buffer&& buffer, Settings& settings,
                   Router& router) noexcept
      : stream_(std::move(stream)),
        ssl_ctx_(ssl_ctx),
        settings_(settings),
        router_(router) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
  }

  ~DetectConnection() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  void Run() {
    boost::beast::async_detect_ssl(
        stream_, buffer_, std::bind_front(&Self::OnDetect, shared_from_this()));
  }

 private:
  void OnDetect(const boost::beast::error_code& ec, bool is_ssl) {
    if (!ec) {
      if (is_ssl) {
        std::make_shared<SslConnection>(std::move(stream_), ssl_ctx_,
                                        std::move(buffer_), settings_, router_)
            ->Run();
      } else {
        std::make_shared<PlainConnection>(std::move(stream_), ssl_ctx_,
                                          std::move(buffer_), settings_,
                                          router_)
            ->Run();
      }
    } else {
      TRACE_OBJ(kTag) << "Detect " << ec << std::endl;
    }
  }

 private:
  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;
  boost::asio::ssl::context& ssl_ctx_;
  Settings& settings_;
  Router& router_;
};

}  // namespace netkit::http
