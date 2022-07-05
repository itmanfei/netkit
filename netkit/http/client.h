#pragma once
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <string>
#include <vector>

namespace netkit::http {

template <class T>
class BasicClient {
 public:
  BasicClient(boost::asio::io_context& ioc, const std::string& host,
              std::uint16_t port) noexcept
      : resolver_(ioc), host_(host), port_(std::to_string(port)) {}

  void AddHeader(const std::string& key, const std::string& value) noexcept {
    add_headers_.emplace_back(std::make_pair(key, value));
  }

  template <class ReqBody, class RespBody>
  void SendRequest(boost::beast::http::request<ReqBody>& req,
                   boost::beast::http::response<RespBody>& resp) {
    req.set(boost::beast::http::field::host, host_ + ":" + port_);
    for (const auto& pair : add_headers_) {
      req.set(pair.first, pair.second);
    }
    DoRequest(req, resp);
  }

  void Close() noexcept {
    resolver_.cancel();
    Derived().DoClose();
    connected_ = false;
  }

 private:
  T& Derived() noexcept { return static_cast<T&>(*this); }

  template <class ReqBody, class RespBody>
  void DoRequest(boost::beast::http::request<ReqBody>& req,
                 boost::beast::http::response<RespBody>& resp) {
    resp = {};
    if (!connected_) {
      auto results = resolver_.resolve(host_, port_);
      Derived().DoConnect(results);
    }
    bool retry = connected_;
    bool success = false;
    try {
      auto& stream = Derived().stream();
      boost::beast::http::write(stream, req);
      boost::beast::http::read(stream, buffer_, resp);
      success = true;
    } catch (const std::exception&) {
      Close();
      if (!retry) {
        throw;
      }
    }
    if (!success) {
      DoRequest(req, resp);  // retry
    } else {
      if (req.need_eof() || resp.need_eof()) {
        Close();
      } else {
        connected_ = true;
      }
    }
  }

 private:
  bool connected_ = false;
  boost::asio::ip::tcp::resolver resolver_;
  std::string host_;
  std::string port_;
  boost::beast::flat_buffer buffer_;
  std::vector<std::pair<std::string, std::string>> add_headers_;
};

class PlainClient : public BasicClient<PlainClient> {
 public:
  PlainClient(boost::asio::io_context& ioc, const std::string& host,
              std::uint16_t port) noexcept
      : BasicClient(ioc, host, port), stream_(ioc) {}

 private:
  void DoConnect(const boost::asio::ip::tcp::resolver::results_type& results) {
    stream_.connect(results);
  }

  void DoClose() noexcept {
    boost::system::error_code ec;
    stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
  }

 private:
  friend class BasicClient;
  boost::beast::tcp_stream& stream() noexcept { return stream_; }

 private:
  boost::beast::tcp_stream stream_;
};

class SslClient : public BasicClient<SslClient> {
 public:
  SslClient(boost::asio::io_context& ioc, boost::asio::ssl::context& ssl_ctx,
            const std::string& host, std::uint16_t port) noexcept
      : BasicClient(ioc, host, port), stream_(ioc, ssl_ctx) {}

 private:
  void DoConnect(const boost::asio::ip::tcp::resolver::results_type& results) {
    stream_.next_layer().connect(results);
    stream_.handshake(boost::asio::ssl::stream_base::client);
  }

  void DoClose() noexcept {
    boost::system::error_code ec;
    stream_.shutdown(ec);
  }

 private:
  boost::beast::ssl_stream<boost::beast::tcp_stream>& stream() noexcept {
    return stream_;
  }

 private:
  friend class BasicClient;
  boost::beast::ssl_stream<boost::beast::tcp_stream> stream_;
};

}  // namespace netkit::http
