#include <netkit/http/cors_filter.h>
#include <netkit/http/server.h>

#include <cstdlib>
#include <unordered_map>

using namespace netkit;

class AuthorizationFilter : public http::Filter {
 public:
  const char* name() const noexcept override { return "AuthFilter"; }

  Result OnIncomingRequest(const http::Context::Ptr& ctx) override {
    auto& req = ctx->GetRequest();
    if (req.target().starts_with("/user/login")) {
      return Result::kPassed;
    }
    if (std::rand() % 100 < 30) {
      ctx->Unauthorized("Auth failed", "text/plain");
      return Result::kResponded;
    }
    return Result::kPassed;
  }
};

static std::uint64_t channel_id = 0;
static std::mutex mutex;
static std::unordered_map<std::uint64_t, std::string> channel_map;

static void UserLogin(const http::Context::Ptr& ctx) {
  ctx->set_user_data(true);
  bool* ud = ctx->try_get_user_data<bool>();
  assert(ud && *ud);
  ctx->Ok("Login success", "text/plain");
}

static void AddChannel(const http::Context::Ptr& ctx) {
  std::lock_guard lock(mutex);
  auto id = ++channel_id;
  channel_map[id] = ctx->GetRequest().body();
  ctx->Ok(std::to_string(id), "text/plain");
}

static void DeleteChannel(const http::Context::Ptr& ctx, std::uint64_t id) {
  std::lock_guard lock(mutex);
  channel_map.erase(id);
  ctx->Ok();
}

static void UpdateChannel(const http::Context::Ptr& ctx, std::uint64_t id) {
  std::lock_guard lock(mutex);
  auto it = channel_map.find(id);
  if (it != channel_map.end()) {
    it->second = ctx->GetRequest().body();
  }
  ctx->Ok();
}

static void GetChannelList(const http::Context::Ptr& ctx) {
  std::ostringstream oss;
  std::lock_guard lock(mutex);
  for (const auto& it : channel_map) {
    oss << it.first << ":" << it.second << ",";
  }
  auto body = oss.str();
  if (body.size() > 0) {
    body.pop_back();
  }
  ctx->Ok(std::move(body), "text/plain");
}

void TestHttpServer(std::stop_token st, IoContextPool& pool,
                    const std::string& address, std::uint16_t port) {
  boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12);
  auto server = std::make_shared<http::DetectServer>(pool, ssl_ctx);

  {
    auto filter = std::make_shared<http::CorsFilter>();
    filter->set_allow_any_origins(true)
        .set_allow_methods({"POST", "GET", "PUT", "DELETE", "OPTIONS"})
        .set_allow_any_headers(true)
        .set_expose_headers({"authorization"});
    server->settings().AddFilter(filter).AddFilter(
        std::make_shared<AuthorizationFilter>());
  }

  server->HandleFunc("/user/login", &UserLogin, {"POST"});
  server->HandleFunc("/channel", &AddChannel, {"POST"});
  server->HandleFunc("/channel/{id}", &DeleteChannel, {"DELETE"});
  server->HandleFunc("/channel/{id}", &UpdateChannel, {"PUT"});
  server->HandleFunc("/channel", &GetChannelList, {"GET"});

  std::srand((unsigned int)std::time(nullptr));

  server->ListenAndServe(address, port, true);

  while (!st.stop_requested()) {
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(100ms);
  }

  server->Close();
}