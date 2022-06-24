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
};

}  // namespace netkit::http
