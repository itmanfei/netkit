#pragma once
#include <boost/asio.hpp>
#include <chrono>
#include <functional>

namespace netkit {

class TimeoutMonitor {
  using Self = TimeoutMonitor;

 public:
  explicit TimeoutMonitor(boost::asio::io_context& ioc) noexcept
      : timer_(ioc) {}

  template <class _Rep, class _Period, class Handler>
  void Start(const std::chrono::duration<_Rep, _Period>& time,
             Handler&& handler) {
    timer_.expires_after(time);
    timer_.async_wait([this, handler = std::forward<Handler>(handler)](
                          const boost::system::error_code& ec) mutable {
      if (!ec) {
        handler();
      }
    });
  }

  void Cancel() {
    try {
      timer_.cancel();
    } catch (const std::exception&) {
    }
  }

 private:
  boost::asio::steady_timer timer_;
};

}  // namespace netkit
