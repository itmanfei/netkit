# 测试编译器

- MSVC14.3  C++20
- GCC12.1  C++20

# HTTP服务种类

```c++
// Only for http
using PlainServer = BasicServer<PlainConnection>;
// Only for https
using SslServer = BasicServer<SslConnection>;
// Both http and https(Automatic detection of http or https)
using DetectServer = BasicServer<DetectConnection>;
```

# IoContextPool类

boost::asio::io_context的对象池，每个io_context对象运行在单独的线程，因此在同一个io_context对象上的操作不需要串行化。

使用方式如下：

```c++
// 2个io_context对象和线程，每个io_context对象分别运行的单独的线程
IoContextPool pool(2);
// 运行所有io_context对象（会调用io_context对象的run方法）
// 该接口会阻塞，直到调用pool.Stop
pool.Run();
// 停止所有io_context，调用Stop后，pool.Run方法会结束
pool.Stop();
```

# 如何定义过滤器Filter

- 基类定义如下：

```c++
class Filter {
 public:
  // kPassed：请求可通过过滤器，可以进行下一步处理
  // kResponsed：请求不能通过过滤器，并且已经对请求进行了回应
  enum class Result { kPassed, kResponded };
  virtual ~Filter() noexcept {}
  // 过滤器名称
  virtual const char* name() const noexcept = 0;
  // 对请求进行过滤处理
  virtual Result OnIncomingRequest(const Context::Ptr& ctx) = 0;
  // 对回应进行处理，只能回应头进行处理
  virtual void OnOutgingResponse(const Context::Ptr& ctx,
                                 boost::beast::http::response_header<>& resp) {}
  static const char* GetResultString(Result ret) noexcept {
    switch (ret) {
      case Result::kPassed:
        return "Passed";
      case Result::kResponded:
        return "Responsed";
    }
    return "";
  }
};
```

- 内置了跨域过滤器（CorsFilter）

- 这里以认证过滤器为例

```c++
class AuthorizationFilter : public http::Filter {
 public:
  const char* name() const noexcept override { return "AuthFilter"; }
  Result OnIncomingRequest(const http::Context::Ptr& ctx) override {
    const auto& req = ctx->parser().get();
    if (req.target() == "/user/login") {
      return Result::kPassed;
    }
    if (std::rand() % 100 < 30) {
      ctx->Unauthorized("Auth failed", "text/plain");
      return Result::kResponded;
    }
    return Result::kPassed;
  }
};
```

# Example

```c++
#include <netkit/http/cors_filter.h>
#include <netkit/http/server.h>

#include <boost/json.hpp>
#include <cstdlib>
#include <unordered_map>

using namespace netkit;

class AuthorizationFilter : public http::Filter {
 public:
  const char* name() const noexcept override { return "AuthFilter"; }

  Result OnIncomingRequest(const http::Context::Ptr& ctx) override {
    const auto& req = ctx->parser().get();
    if (req.target() == "/user/login") {
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
  ctx->Ok("Login success", "text/plain");
}

static void AddChannel(const http::Context::Ptr& ctx) {
  if (!ctx->parser().content_length()) {
    return ctx->LengthRequired();
  }
  const auto len = *ctx->parser().content_length();
  auto buf = std::make_shared<char[]>(len);
  ctx->ReadAll(buf.get(), len,
               [ctx, buf, len](const std::error_code& ec, std::size_t) {
                 if (ec) return;
                 std::lock_guard lock(mutex);
                 const auto id = ++channel_id;
                 channel_map[id] = std::string(buf.get(), len);
                 ctx->Ok(std::to_string(id), "text/plain");
               });
}

static void DeleteChannel(const http::Context::Ptr& ctx, std::uint64_t id) {
  std::lock_guard lock(mutex);
  channel_map.erase(id);
  ctx->Ok();
}

static void UpdateChannel(const http::Context::Ptr& ctx, std::uint64_t id) {
  if (!ctx->parser().content_length()) {
    return ctx->LengthRequired();
  }
  const auto len = *ctx->parser().content_length();
  auto buf = std::make_shared<char[]>(len);
  ctx->ReadAll(buf.get(), len,
               [ctx, buf, len, id](const std::error_code& ec, std::size_t) {
                 if (ec) return;
                 std::lock_guard lock(mutex);
                 const auto it = channel_map.find(id);
                 if (it != channel_map.end()) {
                   it->second = std::string(buf.get(), len);
                 }
                 ctx->Ok();
               });
}

static void GetChannelList(const http::Context::Ptr& ctx) {
  boost::json::array list;
  {
    std::lock_guard lock(mutex);
    list.reserve(channel_map.size());
    for (const auto& it : channel_map) {
      boost::json::object obj;
      obj["id"] = it.first;
      obj["name"] = it.second;
      list.emplace_back(std::move(obj));
    }
  }
  ctx->Ok(boost::json::serialize(list), "applicaion/json");
}

void main() {
  IoContextPool pool(2);
  boost::asio::ssl::context ssl_ctx(boost::asio::ssl::context::tlsv12);
  auto server = std::make_shared<http::DetectServer>(pool, ssl_ctx);

  auto filter = std::make_shared<http::CorsFilter>();
  filter->set_allow_any_origins(true)
      .set_allow_methods({"POST", "GET", "PUT", "DELETE", "OPTIONS"})
      .set_allow_any_headers(true)
      .set_expose_headers({"authorization"});
  server->settings().AddFilter(filter).AddFilter(
      std::make_shared<AuthorizationFilter>());

  server->HandleFunc("/user/login", &UserLogin, {"POST"});
  server->HandleFunc("/channel", &AddChannel, {"POST"});
  server->HandleFunc("/channel/{id}", &DeleteChannel, {"DELETE"});
  server->HandleFunc("/channel/{id}", &UpdateChannel, {"PUT"});
  server->HandleFunc("/channel", &GetChannelList, {"GET"});

  std::srand((unsigned int)std::time(nullptr));

  server->ListenAndServe("0.0.0.0", 8087, true);

  pool.Run();
}
```

