#pragma once
#include <netkit/http/context.h>

namespace netkit::http {

class Filter {
 public:
  enum class Result { kPassed, kResponded };

  virtual ~Filter() noexcept {}

  virtual const char* name() const noexcept = 0;

  virtual Result OnIncomingRequest(const Context::Ptr& ctx) = 0;

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

}  // namespace netkit::http
