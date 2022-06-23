#include <netkit/tcp/listener.h>

#include <iostream>

using namespace netkit;

static void OnNewConnection(const std::shared_ptr<tcp::Listener>& listener,
                            boost::asio::ip::tcp::socket&& socket) {}

void TestTcpListener(std::stop_token st, IoContextPool& pool,
                     const std::string& address, std::uint16_t port) {
  auto listener = std::make_shared<tcp::Listener>(pool);
  listener->ListenAndAccept(address, port, true,
                            std::bind_front(OnNewConnection, listener));
  while (!st.stop_requested()) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(100ms);
  }
  listener->Close();
}
