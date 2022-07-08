#pragma once
#include <netkit/http/settings.h>

#include <boost/beast.hpp>
#include <memory>
#include <variant>

namespace netkit::http {

class PlainConnection;
class SslConnection;

template <class T>
class BasicConnection;

using BodyType = boost::beast::http::string_body;

using Request = boost::beast::http::request<BodyType>;

class Context : public std::enable_shared_from_this<Context> {
  using Self = Context;

 public:
  using Ptr = std::shared_ptr<Self>;

  template <class T>
  Context(const std::shared_ptr<BasicConnection<T>>& conn,
          Request&& req) noexcept
      : conn_(conn), req_(std::move(req)) {}

  ~Context() noexcept {}

  const Request& GetRequest() const noexcept { return req_; }

  template <class Body>
  void Response(boost::beast::http::response<Body>&& resp) {
    std::visit(
        [this, &resp](const auto& conn) {
          conn->Response(shared_from_this(), std::move(resp));
        },
        conn_);
  }

  void Response(boost::beast::http::status status, bool keep_alive);

  void Response(boost::beast::http::status status);

  void Response(boost::beast::http::status status, std::string&& body,
                const char* content_type, bool keep_alive);

  void Response(boost::beast::http::status status, std::string&& body,
                const char* content_type);

#ifndef GENERATE_HTTP_RESPONSE_FUNC
#define GENERATE_HTTP_RESPONSE_FUNC(_name_, _status_)                          \
  void _name_() { Response(boost::beast::http::status::_status_); }            \
  void _name_(bool keep_alive) {                                               \
    Response(boost::beast::http::status::_status_, keep_alive);                \
  }                                                                            \
  void _name_(std::string&& body, const char* content_type, bool keep_alive) { \
    Response(boost::beast::http::status::_status_, std::move(body),            \
             content_type, keep_alive);                                        \
  }                                                                            \
  void _name_(std::string&& body, const char* content_type) {                  \
    Response(boost::beast::http::status::_status_, std::move(body),            \
             content_type);                                                    \
  }                                                                            \
  void _name_(const char* body, const char* content_type) {                    \
    Response(boost::beast::http::status::_status_, body, content_type);        \
  }
  // 1xx
  GENERATE_HTTP_RESPONSE_FUNC(Continue, continue_)
  GENERATE_HTTP_RESPONSE_FUNC(SwitchingProtocols, switching_protocols)
  GENERATE_HTTP_RESPONSE_FUNC(Processing, processing)
  // 2xx
  GENERATE_HTTP_RESPONSE_FUNC(Ok, ok)
  GENERATE_HTTP_RESPONSE_FUNC(Created, created)
  GENERATE_HTTP_RESPONSE_FUNC(Accepted, accepted)
  GENERATE_HTTP_RESPONSE_FUNC(NonAuthoritativeInformation,
                              non_authoritative_information)
  GENERATE_HTTP_RESPONSE_FUNC(NoContent, no_content)
  GENERATE_HTTP_RESPONSE_FUNC(ResetContent, reset_content)
  GENERATE_HTTP_RESPONSE_FUNC(PartialContent, partial_content)
  GENERATE_HTTP_RESPONSE_FUNC(MultiStatus, multi_status)
  GENERATE_HTTP_RESPONSE_FUNC(AlreadyReported, already_reported)
  GENERATE_HTTP_RESPONSE_FUNC(ImUsed, im_used)
  // 4xx
  GENERATE_HTTP_RESPONSE_FUNC(BadRequest, bad_request)
  GENERATE_HTTP_RESPONSE_FUNC(Unauthorized, unauthorized)
  GENERATE_HTTP_RESPONSE_FUNC(PaymentRequired, payment_required)
  GENERATE_HTTP_RESPONSE_FUNC(Forbidden, forbidden)
  GENERATE_HTTP_RESPONSE_FUNC(NotFound, not_found)
  GENERATE_HTTP_RESPONSE_FUNC(MethodNotAllowed, method_not_allowed)
  GENERATE_HTTP_RESPONSE_FUNC(NotAcceptable, not_acceptable)
  GENERATE_HTTP_RESPONSE_FUNC(ProxyAuthenticationRequired,
                              proxy_authentication_required)
  GENERATE_HTTP_RESPONSE_FUNC(RequestTimeout, request_timeout)
  GENERATE_HTTP_RESPONSE_FUNC(Conflict, conflict)
  GENERATE_HTTP_RESPONSE_FUNC(Gone, gone)
  GENERATE_HTTP_RESPONSE_FUNC(LengthRequired, length_required)
  GENERATE_HTTP_RESPONSE_FUNC(PreconditionFailed, precondition_failed)
  GENERATE_HTTP_RESPONSE_FUNC(PayloadTooLarge, payload_too_large)
  GENERATE_HTTP_RESPONSE_FUNC(UriTooLong, uri_too_long)
  GENERATE_HTTP_RESPONSE_FUNC(UnsupportedMediaType, unsupported_media_type)
  GENERATE_HTTP_RESPONSE_FUNC(RangeNotSatisfiable, range_not_satisfiable)
  GENERATE_HTTP_RESPONSE_FUNC(ExpectationFailed, expectation_failed)
  GENERATE_HTTP_RESPONSE_FUNC(MisdirectedRequest, misdirected_request)
  GENERATE_HTTP_RESPONSE_FUNC(UnprocessableEntity, unprocessable_entity)
  GENERATE_HTTP_RESPONSE_FUNC(Locked, locked)
  GENERATE_HTTP_RESPONSE_FUNC(FailedDependency, failed_dependency)
  GENERATE_HTTP_RESPONSE_FUNC(UpgradeRequired, upgrade_required)
  GENERATE_HTTP_RESPONSE_FUNC(PreconditionRequired, precondition_required)
  GENERATE_HTTP_RESPONSE_FUNC(TooManyRequests, too_many_requests)
  GENERATE_HTTP_RESPONSE_FUNC(RequestHeaderFieldsTooLarge,
                              request_header_fields_too_large)
  GENERATE_HTTP_RESPONSE_FUNC(ConnectionClosedWithoutResponse,
                              connection_closed_without_response)
  GENERATE_HTTP_RESPONSE_FUNC(UnavailableForLegalReasons,
                              unavailable_for_legal_reasons)
  GENERATE_HTTP_RESPONSE_FUNC(ClientClosedRequest, client_closed_request)
  // 5xx
  GENERATE_HTTP_RESPONSE_FUNC(InternalServerError, internal_server_error)
  GENERATE_HTTP_RESPONSE_FUNC(NotImplemented, not_implemented)
  GENERATE_HTTP_RESPONSE_FUNC(BadGateway, bad_gateway)
  GENERATE_HTTP_RESPONSE_FUNC(ServiceUnavailable, service_unavailable)
  GENERATE_HTTP_RESPONSE_FUNC(GatewayTimeout, gateway_timeout)
  GENERATE_HTTP_RESPONSE_FUNC(HttpVersionNotSupported,
                              http_version_not_supported)
  GENERATE_HTTP_RESPONSE_FUNC(VariantAlsoNegotiates, variant_also_negotiates)
  GENERATE_HTTP_RESPONSE_FUNC(InsufficientStorage, insufficient_storage)
  GENERATE_HTTP_RESPONSE_FUNC(LoopDetected, loop_detected)
  GENERATE_HTTP_RESPONSE_FUNC(NotExtended, not_extended)
  GENERATE_HTTP_RESPONSE_FUNC(NetworkAuthenticationRequired,
                              network_authentication_required)
  GENERATE_HTTP_RESPONSE_FUNC(NetworkConnectTimeoutError,
                              network_connect_timeout_error)
#undef GENERATE_HTTP_RESPONSE_FUNC
#endif

 private:
  void set_origin(const std::string& origin) noexcept { origin_ = origin; }

  const std::string& origin() const noexcept { return origin_; }

 private:
  friend class CorsFilter;
  std::string origin_;
  std::variant<std::shared_ptr<BasicConnection<PlainConnection>>,
               std::shared_ptr<BasicConnection<SslConnection>>>
      conn_;
  Request req_;
};

}  // namespace netkit::http
