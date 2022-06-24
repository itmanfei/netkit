#pragma once
#include <netkit/utility.h>

#include <boost/algorithm/string.hpp>
#include <boost/date_time.hpp>
#include <boost/lexical_cast.hpp>
#include <memory>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace netkit::http {

inline namespace detail {

template <class T>
struct IsOptional {
  static constexpr bool kValue = false;
};

template <class T>
struct IsOptional<std::optional<T>> {
  static constexpr bool kValue = true;
};

template <class S, class K, class V>
static bool SplitKeyValue(const S& src, K& key, V& val) noexcept {
  const auto pos = src.find('=');
  if (pos != S::npos) {
    key = src.substr(0, pos);
    val = src.substr(pos + 1);
    return true;
  }
  return false;
}

template <class S>
static bool IsNeedDecode(const S& str) noexcept {
  return std::find_if(str.begin(), str.end(), [](const char c) {
           return c == '%' || c == '+';
         }) != str.end();
}

template <class S>
static std::string DecodeData(const S& str) noexcept {
  std::string result;
  const auto len = str.size();
  result.reserve(len);
  for (std::size_t i = 0; i < len; ++i) {
    switch (str[i]) {
      case '+': {
        result += ' ';
        break;
      }
      case '%': {
        if (i + 2 < len) {
          char c1 = str[i + 1];
          char c2 = str[i + 2];
          if (c1 >= '0' && c1 <= '9' && c2 >= '0' && c2 <= '9') {
            c1 -= '0';
            c2 -= '0';
          } else if (c1 >= 'a' && c1 <= 'f' && c2 >= 'a' && c2 <= 'f') {
            c1 = c1 - 'a' + 10;
            c2 = c2 - 'a' + 10;
          } else if (c1 >= 'A' && c1 <= 'F' && c2 >= 'A' && c2 <= 'F') {
            c1 = c1 - 'A' + 10;
            c2 = c2 - 'A' + 10;
          } else {
            result += '%';
            break;
          }
          result += char(c1 * 16 + c2);
          i += 2;
        } else {
          result += '%';
        }
        break;
      }
      default: {
        result += str[i];
        break;
      }
    }
  }
  return result;
}

}  // namespace detail

template <class Ret, class... PreArgs>
class BasicRouter {
 public:
  using MethodList = std::vector<std::string>;
  using ParamList = std::vector<std::string>;
  using ArgumentMap = std::unordered_map<std::string, std::string>;

  template <class>
  struct FunctionTraits;

  // traits for lambda, std::function, functor
  template <class Function>
  struct FunctionTraits
      : FunctionTraits<
            decltype(&std::remove_reference<Function>::type::operator())> {
    using ClassType = void;
  };

  // traits for class method of const object
  template <class ClsType, class... Args>
  struct FunctionTraits<Ret (ClsType::*)(Args...) const>
      : FunctionTraits<Ret (*)(Args...)> {
    using ClassType = ClsType;
  };

  // traits for class method of non-const object
  template <class ClsType, class... Args>
  struct FunctionTraits<Ret (ClsType::*)(Args...)>
      : FunctionTraits<Ret (*)(Args...)> {
    using ClassType = ClsType;
  };

  // for router invoke
  template <class... Args>
  struct FunctionTraits<Ret (*)(PreArgs&&..., Args...)>
      : FunctionTraits<Ret (*)(Args...)> {
    using ClassType = void;
  };

  // final traits for argument size and value type
  template <class... Args>
  struct FunctionTraits<Ret (*)(Args...)> {
    using ClassType = void;
    template <std::size_t Index>
    using ValueType = std::tuple_element_t<Index, std::tuple<Args...>>;
    static constexpr std::size_t kArgNum = sizeof...(Args);
  };

  class BaseBinder {
   public:
    virtual ~BaseBinder() noexcept = default;

    virtual bool IsMatched(std::size_t path_arg_num,
                           const ArgumentMap& arg_map) const noexcept = 0;

    virtual Ret Invoke(PreArgs&&... pre_args, std::cmatch& results,
                       ArgumentMap& arg_map) = 0;
  };

  template <class Function>
  class RouteBinder : public BaseBinder {
   public:
    using Traits = FunctionTraits<Function>;

    RouteBinder(std::size_t path_arg_num, ParamList capture_params,
                Function&& func)
        : path_arg_num_(path_arg_num),
          capture_params_(std::move(capture_params)),
          func_(std::forward<Function>(func)) {
      if (capture_params_.size() + path_arg_num_ != Traits::kArgNum) {
        throw std::runtime_error("Number of parameters does not match");
      }
    }

    bool IsMatched(std::size_t path_arg_num,
                   const ArgumentMap& arg_map) const noexcept override {
      if (path_arg_num != path_arg_num_) {
        return false;
      }
      return IsMatched<0>(arg_map);
    }

    template <size_t N>
    std::enable_if_t<N != Traits::kArgNum, bool> IsMatched(
        const ArgumentMap& arg_map) const noexcept {
      if (path_arg_num_ > N) {
        return IsMatched<N + 1>(arg_map);
      }
      using ValueType = std::remove_cv_t<
          std::remove_reference_t<typename Traits::template ValueType<N>>>;
      if constexpr (!IsOptional<ValueType>::kValue) {
        if (!arg_map.contains(capture_params_[N - path_arg_num_])) {
          return false;
        }
      }
      return IsMatched<N + 1>(arg_map);
    }

    template <size_t N>
    std::enable_if_t<N == Traits::kArgNum, bool> IsMatched(
        const ArgumentMap&) const noexcept {
      return true;
    }

    Ret Invoke(PreArgs&&... pre_args, std::cmatch& results,
               ArgumentMap& arg_map) override {
      return DoInvoke(std::forward<PreArgs>(pre_args)..., results, arg_map);
    }

    template <class Value>
    static constexpr void SetValue(Value& val, std::string&& str) {
      if constexpr (std::is_same_v<std::string, Value>) {
        val = std::move(str);
      } else if constexpr (std::is_same_v<boost::gregorian::date, Value>) {
        val = boost::gregorian::from_simple_string(str);
      } else if constexpr (std::is_same_v<boost::posix_time::ptime, Value>) {
        val = boost::posix_time::from_iso_extended_string(str);
      } else {
        val = boost::lexical_cast<Value>(str);
      }
    }

    template <class Value>
    static constexpr void SetValue(std::optional<Value>& val,
                                   std::string&& str) {
      if constexpr (std::is_same_v<std::string, Value>) {
        val = std::make_optional<Value>(std::move(str));
      } else if constexpr (std::is_same_v<boost::gregorian::date, Value>) {
        val = std::make_optional<Value>(
            boost::gregorian::from_simple_string(str));
      } else if constexpr (std::is_same_v<boost::posix_time::ptime, Value>) {
        val = std::make_optional<Value>(
            boost::posix_time::from_iso_extended_string(str));
      } else {
        val = std::make_optional<Value>(boost::lexical_cast<Value>(str));
      }
    }

    template <class... Values>
    std::enable_if_t<sizeof...(Values) < Traits::kArgNum, Ret> DoInvoke(
        PreArgs&&... pre_args, std::cmatch& results, ArgumentMap& arg_map,
        Values&&... values) {
      constexpr auto index = sizeof...(Values);
      using ValueType = std::remove_cv_t<
          std::remove_reference_t<typename Traits::template ValueType<index>>>;
      ValueType value;
      if (path_arg_num_ > index) {
        SetValue(value, results[index + 1].str());
      } else {
        auto it = arg_map.find(capture_params_[index - path_arg_num_]);
        if constexpr (IsOptional<ValueType>::kValue) {
          if (it != arg_map.end()) {
            SetValue(value, std::move(it->second));
          }
        } else {
          assert(it != arg_map.end());
          SetValue(value, std::move(it->second));
        }
      }
      return DoInvoke(std::forward<PreArgs>(pre_args)..., results, arg_map,
                      std::forward<Values>(values)..., std::move(value));
    }

    template <class... Values>
    std::enable_if_t<sizeof...(Values) == Traits::kArgNum, Ret> DoInvoke(
        PreArgs&&... pre_args, std::cmatch&, ArgumentMap&, Values&&... values) {
      if constexpr (std::is_same_v<typename Traits::ClassType, void>) {
        return func_(std::forward<PreArgs>(pre_args)...,
                     std::forward<Values>(values)...);
      } else {
        auto obj = std::make_shared<typename Traits::ClassType>();
        return (*obj.*func_)(std::forward<PreArgs>(pre_args)...,
                             std::forward<Values>(values)...);
      }
    }

   private:
    std::size_t path_arg_num_;
    ParamList capture_params_;
    Function func_;
  };

  class RouteItem {
   public:
    using BinderList = std::vector<std::shared_ptr<BaseBinder>>;

    RouteItem() noexcept = default;

    explicit RouteItem(const std::string& regex_path) noexcept
        : regex_path_(regex_path) {
      regex_ = std::regex(regex_path, std::regex_constants::icase);
    }

    const std::regex& regex() const noexcept { return regex_; }

    const std::string& regex_path() const noexcept { return regex_path_; }

    template <class Function>
    void AddHandleFunc(std::size_t path_arg_num, MethodList allowed_methods,
                       ParamList capture_params, Function&& func) {
      auto binder = std::make_shared<RouteBinder<Function>>(
          path_arg_num, capture_params, std::forward<Function>(func));
      for (const auto& method : allowed_methods) {
        const auto it = allowed_method_binders_.find(method);
        if (it == allowed_method_binders_.end()) {
          BinderList list;
          list.emplace_back(binder);
          allowed_method_binders_.insert(
              std::make_pair(method, std::move(list)));
        } else {
          it->second.emplace_back(binder);
        }
      }
    }

    bool IsAllowedMethod(const std::string& method) const noexcept {
      return allowed_method_binders_.contains(method);
    }

    Ret Invoke(PreArgs&&... pre_args, const std::string& method,
               std::cmatch& results, ArgumentMap&& arg_map) {
      std::size_t path_arg_num = 0;
      if (results.size() > 1) {
        path_arg_num = results.size() - 1;
      }
      const auto it = allowed_method_binders_.find(method);
      assert(it != allowed_method_binders_.end());
      for (const auto& binder : it->second) {
        if (binder->IsMatched(path_arg_num, arg_map)) {
          return binder->Invoke(std::forward<PreArgs>(pre_args)..., results,
                                arg_map);
        }
      }
      throw std::runtime_error("Parameter mismatch");
      return Ret();
    }

   private:
    std::regex regex_;
    std::string regex_path_;
    std::unordered_map<std::string, BinderList> allowed_method_binders_;
  };

  template <class Function>
  void AddRoute(const std::string& target, Function&& func,
                MethodList allowed_methods) {
    std::string path;
    ParamList capture_params;
    const auto pos = target.find('?');
    if (pos != std::string::npos) {
      auto query = target.substr(pos + 1);
      path = target.substr(0, pos);
      std::vector<std::string> vec;
      boost::split(vec, query, boost::is_any_of("&"));
      for (auto& str : vec) {
        std::string k, v;
        if (SplitKeyValue(str, k, v)) {
          ToLower(k);
          capture_params.emplace_back(k);
        } else {
          ToLower(str);
          capture_params.emplace_back(str);
        }
      }
    } else {
      path = target;
    }

    ToLower(path);
    const std::regex regex("\\{([^/]*)\\}");

    std::size_t path_arg_num = 0;
    {
      std::smatch results;
      std::string temp_path = path;
      while (std::regex_search(temp_path, results, regex)) {
        ++path_arg_num;
        temp_path = results.suffix();
      }
    }

    const auto replaced_path = std::regex_replace(path, regex, "([^/]*)");
    RouteItem* item_ptr = nullptr;
    bool is_regex = (replaced_path != path);
    if (is_regex) {
      for (auto& item : route_vec_) {
        if (item.regex_path() == replaced_path) {
          item_ptr = &item;
          break;
        }
      }
    } else {
      auto it = route_map_.find(path);
      if (it != route_map_.end()) item_ptr = &it->second;
    }

    if (!item_ptr) {
      if (is_regex) {
        RouteItem item(replaced_path);
        route_vec_.emplace_back(std::move(item));
        item_ptr = &route_vec_.back();
      } else {
        RouteItem item;
        route_map_[path] = std::move(item);
        item_ptr = &route_map_[path];
      }
    }

    for (auto& method : allowed_methods) {
      ToUpper(method);
    }

    item_ptr->AddHandleFunc(path_arg_num, allowed_methods, capture_params,
                            std::forward<Function>(func));
  }

  RouteItem* FindRoute(const char* path, std::size_t size,
                       std::cmatch& results) noexcept {
    RouteItem* item_ptr = nullptr;
    std::string lowered_path(path, size);
    ToLower(lowered_path);
    auto it = route_map_.find(lowered_path);
    if (it != route_map_.end()) {
      item_ptr = &it->second;
    } else {
      for (auto& item : route_vec_) {
        if (std::regex_match(path, path + size, results, item.regex())) {
          item_ptr = &item;
          break;
        }
      }
    }
    return item_ptr;
  }

  Ret Routing(PreArgs&&... pre_args, const std::string& method,
              std::string_view target) {
    std::string_view path_sv, param_sv;
    const auto pos = target.find('?');
    if (pos != std::string_view::npos) {
      path_sv = target.substr(0, pos);
      param_sv = target.substr(pos + 1);
    } else {
      path_sv = target;
    }
    std::cmatch results;
    RouteItem* route = nullptr;
    std::string decoded_path;
    if (IsNeedDecode(path_sv)) {
      decoded_path = DecodeData(path_sv);
      route = FindRoute(decoded_path.c_str(), decoded_path.size(), results);
    } else {
      route = FindRoute(path_sv.data(), path_sv.size(), results);
    }
    if (!route) {
      throw std::runtime_error("Route not found");
    }
    if (!route->IsAllowedMethod(method)) {
      throw std::runtime_error("Method not allowed");
    }
    ArgumentMap arg_map;
    while (param_sv.size() > 0) {
      std::string_view kv_sv;
      const auto pos = param_sv.find('&');
      if (pos != std::string_view::npos) {
        kv_sv = param_sv.substr(0, pos);
        param_sv.remove_prefix(pos + 1);
      } else {
        kv_sv = param_sv;
        param_sv = "";
      }
      std::string key, val;
      if (SplitKeyValue(kv_sv, key, val)) {
        if (IsNeedDecode(key)) {
          key = DecodeData(key);
        }
        if (IsNeedDecode(val)) {
          val = DecodeData(val);
        }
        ToLower(key);
        arg_map.insert(std::make_pair(std::move(key), std::move(val)));
      }
    }
    return route->Invoke(std::forward<PreArgs>(pre_args)..., method, results,
                         std::move(arg_map));
  }

 private:
  std::vector<RouteItem> route_vec_;
  std::unordered_map<std::string, RouteItem> route_map_;
};

class Context;
using Router = BasicRouter<void, const std::shared_ptr<Context>&>;

}  // namespace netkit::http
