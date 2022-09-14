#pragma once
#include <netkit/http/context.h>
#include <netkit/http/filter.h>
#include <netkit/http/router.h>
#include <netkit/http/settings.h>

#include <any>
#include <boost/beast/ssl.hpp>
#include <memory>

namespace netkit::http {

using Parser = boost::beast::http::request_parser<BodyType>;

template <class D>
class BasicConnection {
  friend class Context;
  using Self = BasicConnection;

 public:
  BasicConnection(boost::beast::flat_buffer&& buffer, Settings& settings,
                  Router& router) noexcept
      : buffer_(std::move(buffer)), settings_(settings), router_(router) {}

  ~BasicConnection() noexcept {}

 protected:
  D& Derived() noexcept { return static_cast<D&>(*this); }

  void set_user_data(std::any&& data) noexcept { user_data_ = std::move(data); }

  template <class T>
  T* try_get_user_data() noexcept {
    if (user_data_.has_value()) {
      try {
        return std::any_cast<T>(&user_data_);
      } catch (const std::exception&) {
      }
    }
    return nullptr;
  }

  void ReadRequest() {
    parser_.emplace();
    parser_->header_limit(settings_.header_limit());
    if (settings_.body_limit()) {
      parser_->body_limit(*settings_.body_limit());
    } else {
      parser_->body_limit(boost::none);
    }
    boost::beast::http::async_read(
        Derived().stream(), buffer_, *parser_,
        [self = Derived().shared_from_this()](
            const boost::beast::error_code& ec, std::size_t bytes_transferred) {
          self->OnRequest(ec, bytes_transferred);
        });
  }

  void OnRequest(const boost::beast::error_code& ec,
                 std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    if (ec) {
      if (ec == boost::beast::http::error::end_of_stream) {
        Derived().DoEof();
      }
    } else {
      Derived().ExpiresNever();
      auto ctx = std::make_shared<Context>(
          std::static_pointer_cast<Self>(Derived().shared_from_this()),
          parser_->release());
      for (const auto& filter : settings_.filters()) {
        if (filter->OnIncomingRequest(ctx) == Filter::Result::kResponded) {
          return;
        }
      }
      try {
        auto method = ctx->GetRequest().method_string();
        auto target = ctx->GetRequest().target();
        router_.Routing(ctx, method.to_string(),
                        std::string_view(target.data(), target.size()));
      } catch (const std::exception& e) {
        return ctx->BadRequest(e.what(), "text/plain", false);
      }
    }
  }

  template <class Body>
  void Response(const Context::Ptr& ctx,
                boost::beast::http::response<Body>&& resp) {
    if (!resp.has_content_length() && !resp.chunked()) {
      resp.content_length(0);
    }
    for (const auto& filter : settings_.filters()) {
      filter->OnOutgingResponse(ctx, resp);
    }
    auto sp =
        std::make_shared<boost::beast::http::response<Body>>(std::move(resp));
    resp_ = sp;
    boost::beast::http::async_write(
        Derived().stream(), *sp,
        [self = Derived().shared_from_this(), close = !sp->keep_alive()](
            const boost::beast::error_code& ec, std::size_t bytes_transferred) {
          self->OnWrite(close, ec, bytes_transferred);
        });
  }

  void OnWrite(bool close, const boost::beast::error_code& ec,
               std::size_t bytes_transferred) {
    boost::ignore_unused(bytes_transferred);
    resp_ = nullptr;
    if (!ec) {
      if (close) {
        Derived().DoEof();
      } else {
        Derived().ExpiresAfter(settings_.read_timeout());
        ReadRequest();
      }
    }
  }

 protected:
  boost::beast::flat_buffer buffer_;
  Settings& settings_;
  Router& router_;
  std::optional<Parser> parser_;
  std::shared_ptr<void> resp_;
  std::any user_data_;
};

class PlainConnection : public BasicConnection<PlainConnection>,
                        public std::enable_shared_from_this<PlainConnection> {
 public:
  PlainConnection(boost::beast::tcp_stream&& stream,
                  boost::asio::ssl::context& ssl_ctx,
                  boost::beast::flat_buffer&& buffer, Settings& settings,
                  Router& router) noexcept
      : BasicConnection(std::move(buffer), settings, router),
        stream_(std::move(stream)) {}

  ~PlainConnection() noexcept {}

  void Run() { ReadRequest(); }

  boost::beast::tcp_stream& stream() noexcept { return stream_; }

  void ExpiresAfter(const std::chrono::milliseconds& time) {
    stream_.expires_after(time);
  }

  void ExpiresNever() { stream_.expires_never(); }

  void DoEof() {
    boost::beast::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
  }

 private:
  boost::beast::tcp_stream stream_;
};

class SslConnection : public BasicConnection<SslConnection>,
                      public std::enable_shared_from_this<SslConnection> {
  using Self = SslConnection;

 public:
  SslConnection(boost::beast::tcp_stream&& stream,
                boost::asio::ssl::context& ssl_ctx,
                boost::beast::flat_buffer&& buffer, Settings& settings,
                Router& router) noexcept
      : BasicConnection(std::move(buffer), settings, router),
        stream_(std::move(stream), ssl_ctx) {}

  ~SslConnection() noexcept {}

  void Run() {
    stream_.async_handshake(
        boost::asio::ssl::stream_base::server, buffer_.data(),
        [this, self = shared_from_this()](const boost::beast::error_code& ec,
                                          std::size_t bytes_used) {
          if (!ec) {
            buffer_.consume(bytes_used);
            ReadRequest();
          }
        });
  }

  boost::beast::ssl_stream<boost::beast::tcp_stream>& stream() noexcept {
    return stream_;
  }

  void ExpiresAfter(const std::chrono::milliseconds& time) {
    stream_.next_layer().expires_after(time);
  }

  void ExpiresNever() { stream_.next_layer().expires_never(); }

  void DoEof() {
    stream_.async_shutdown([](const boost::beast::error_code& ec) {});
  }

 private:
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
};

class DetectConnection : public std::enable_shared_from_this<DetectConnection> {
  using Self = DetectConnection;

 public:
  DetectConnection(boost::beast::tcp_stream&& stream,
                   boost::asio::ssl::context& ssl_ctx,
                   boost::beast::flat_buffer&& buffer, Settings& settings,
                   Router& router) noexcept
      : stream_(std::move(stream)),
        ssl_ctx_(ssl_ctx),
        settings_(settings),
        router_(router) {}

  ~DetectConnection() noexcept {}

  void Run() {
    boost::beast::async_detect_ssl(
        stream_, buffer_,
        [this, self = shared_from_this()](const boost::beast::error_code& ec,
                                          bool is_ssl) {
          if (!ec) {
            if (is_ssl) {
              std::make_shared<SslConnection>(std::move(stream_), ssl_ctx_,
                                              std::move(buffer_), settings_,
                                              router_)
                  ->Run();
            } else {
              std::make_shared<PlainConnection>(std::move(stream_), ssl_ctx_,
                                                std::move(buffer_), settings_,
                                                router_)
                  ->Run();
            }
          }
        });
  }

 private:
  boost::beast::tcp_stream stream_;
  boost::beast::flat_buffer buffer_;
  boost::asio::ssl::context& ssl_ctx_;
  Settings& settings_;
  Router& router_;
};

}  // namespace netkit::http
