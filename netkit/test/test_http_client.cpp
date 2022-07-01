#include <netkit/http/client.h>
#include <netkit/http/digest_auth.h>
#include <netkit/io_context_pool.h>

#include <boost/json.hpp>
#include <iostream>

using namespace netkit;

void TestHttpClient(std::stop_token st, IoContextPool& pool) {
  const std::string username = "admin";
  const std::string password = "123456";
  const std::string cnonce = "abce12346";
  const std::string device_id = "51010700011209155082";
  const std::string url = "/VIID/System/Register";
  http::PlainClient client(pool.Get(), "192.168.20.142", 8003);
  boost::json::object obj{{"RegisterObject", {{"DeviceID", device_id}}}};
  boost::beast::http::request<boost::beast::http::string_body> req(
      boost::beast::http::verb::post, url, 11);
  req.set("User-Identify", device_id);
  req.set(boost::beast::http::field::content_type, "application/VIID+JSON");
  req.body() = boost::json::serialize(obj);
  req.prepare_payload();
  boost::beast::http::response<boost::beast::http::string_body> resp;
  client.SendRequest(req, resp);
  std::cout << resp << std::endl;
  if (resp.result_int() == 401) {
    const auto www = resp[boost::beast::http::field::www_authenticate];
    if (www.starts_with("Digest ")) {
      http::WwwAuthenticateDigest www_digest;
      if (www_digest.ParseFromString(www.data(), www.size())) {
        http::AuthorizationDigest auth_digest;
        auth_digest.cnonce = cnonce;
        auth_digest.nonce = www_digest.nonce;
        auth_digest.nc = 1;
        auth_digest.opaque = www_digest.opaque;
        auth_digest.qop = "auth";
        auth_digest.realm = www_digest.realm;
        auth_digest.response =
            www_digest.MakeResponse(username, password, "POST", url, 1, cnonce);
        auth_digest.uri = url;
        auth_digest.username = username;
        req.set(boost::beast::http::field::authorization,
                auth_digest.ToString());
        client.SendRequest(req, resp);
        std::cout << resp << std::endl;
      }
    }
  }
  while (!st.stop_requested()) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1s);
  }
}