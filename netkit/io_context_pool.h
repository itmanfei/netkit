#pragma once
#include <netkit/trace_log.h>

#include <boost/asio.hpp>
#include <boost/core/noncopyable.hpp>
#include <memory>
#include <thread>
#include <vector>

namespace netkit {

class IoContextPool : boost::noncopyable {
  static constexpr const char* kTag = "IoContextPool";

 public:
  explicit IoContextPool(std::size_t size) : next_index_(0) {
    TRACE_OBJ(kTag) << "Create" << std::endl;
    for (std::size_t i = 0; i < size; ++i) {
      auto ctx = std::make_unique<boost::asio::io_context>(1);
      works_.emplace_back(boost::asio::make_work_guard(*ctx));
      contexts_.emplace_back(std::move(ctx));
    }
  }

  ~IoContextPool() noexcept { TRACE_OBJ(kTag) << "Destory" << std::endl; }

  void Run() {
    std::vector<std::unique_ptr<std::thread>> threads;
    for (const auto& ctx : contexts_) {
      auto thread = std::make_unique<std::thread>([&ctx]() { ctx->run(); });
      threads.emplace_back(std::move(thread));
    }
    TRACE_OBJ(kTag) << "Wait to stop" << std::endl;
    for (const auto& thread : threads) {
      thread->join();
    }
  }

  void Stop() {
    TRACE_OBJ(kTag) << "Stop" << std::endl;
    for (const auto& ctx : contexts_) {
      ctx->stop();
    }
  }

  boost::asio::io_context& Get() {
    const auto index = next_index_++ % contexts_.size();
    TRACE_OBJ(kTag) << "Get " << index << std::endl;
    return *contexts_[index];
  }

 private:
  std::vector<std::unique_ptr<boost::asio::io_context>> contexts_;
  std::vector<
      boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>
      works_;
  std::size_t next_index_;
};

}  // namespace netkit
