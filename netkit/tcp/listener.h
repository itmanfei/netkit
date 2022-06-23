#pragma once
#include <netkit/io_context_pool.h>

namespace netkit::tcp {

class Listener {
  using Self = Listener;
  static constexpr const char* kTag = "tcp.Listener";

 public:
  explicit Listener(IoContextPool& pool) noexcept
      : pool_(pool), socket_(pool.Get()), acceptor_(pool.Get()) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
  }

  ~Listener() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  template <class Handler>
  void ListenAndAccept(const std::string& address, std::uint16_t port,
                       bool reuse_address, Handler&& handler) {
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::make_address(address), port);
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(
        boost::asio::socket_base::reuse_address(reuse_address));
    acceptor_.bind(endpoint);
    acceptor_.listen();
    TRACE_OBJ(kTag) << "Listen at " << address << ":" << port << std::endl;
    DoAccept(std::forward<Handler>(handler));
  }

  void Close() {
    boost::asio::post(acceptor_.get_executor(), [this]() { DoClose(); });
  }

 private:
  template <class Handler>
  void DoAccept(Handler&& handler) {
    acceptor_.async_accept(socket_,
                           std::bind_front(&Self::OnAccept<Handler>, this,
                                           std::forward<Handler>(handler)));
  }

  template <class Handler>
  void OnAccept(Handler&& handler, const boost::system::error_code& ec) {
    if (!ec) {
      TRACE_OBJ(kTag) << "Client incoming from " << socket_.remote_endpoint()
                      << std::endl;
      handler(std::move(socket_));
    } else {
      TRACE_OBJ(kTag) << "Accept " << ec << std::endl;
    }
    if (acceptor_.is_open()) {
      socket_ = boost::asio::ip::tcp::socket(pool_.Get());
      DoAccept(std::forward<Handler>(handler));
    }
  }

  void DoClose() noexcept {
    TRACE_OBJ(kTag) << "Close" << std::endl;
    boost::system::error_code ec;
    acceptor_.cancel(ec);
    acceptor_.close(ec);
  }

 private:
  IoContextPool& pool_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::ip::tcp::acceptor acceptor_;
};

}  // namespace netkit::tcp
