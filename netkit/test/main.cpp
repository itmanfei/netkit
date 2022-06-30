#include <boost/core/ignore_unused.hpp>
#include <csignal>

#include "test.h"

#if _WIN32
#if _DEBUG
#pragma comment(lib, "../x64/Debug/netkit.lib")
#else
#pragma comment(lib, "../x64/Release/netkit.lib")
#endif
#endif

std::stop_source stop;

static void CtrlHandler(std::int32_t sig) {
  signal(SIGINT, CtrlHandler);
  stop.request_stop();
  stop = {};
}

int main() {
  signal(SIGINT, CtrlHandler);

  {
    IoContextPool pool(2);

    std::thread([&pool]() { pool.Run(); }).detach();

    TestHttpClient(stop.get_token(), pool);

    TestTcpListener(stop.get_token(), pool, "0.0.0.0", 12345);

    TestHttpRouter(stop.get_token());

    TestHttpServer(stop.get_token(), pool, "0.0.0.0", 8087);

    pool.Stop();
  }
}
