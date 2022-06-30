#include <netkit/http/client.h>
#include <netkit/io_context_pool.h>

#include <boost/json.hpp>
#include <iostream>

using namespace netkit;

void TestHttpClient(std::stop_token st, IoContextPool& pool) {
  http::PlainClient client(pool.Get(), "192.168.20.142", 8003);
  boost::json::object obj{
      {"RegisterObject", {{"DeviceID", "51010700011209155082"}}}};
  boost::beast::http::request<boost::beast::http::string_body> req(
      boost::beast::http::verb::post, "/VIID/System/Register", 11);
  req.body() = boost::json::serialize(obj);
  req.prepare_payload();
  boost::beast::http::response<boost::beast::http::string_body> resp;
  client.SendRequest(req, resp);
  std::cout << resp << std::endl;
  while (!st.stop_requested()) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1s);
  }
}