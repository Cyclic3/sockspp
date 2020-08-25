#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/spawn.hpp>

#include <cppthings/movable_ptr.hpp>

namespace sockspp {
  // Used so we can have a single ep type
  using ip_endpoint = boost::asio::ip::tcp::endpoint;

  class request_failure : public std::exception {
  public:
    std::string err;

  public:
    const char* what() const noexcept override {
      return err.c_str();
    }

  public:
    request_failure() = default;
    inline request_failure(std::string err_) : err{std::move(err_)} {}
  };

  inline std::ostream& operator<<(std::ostream& os, request_failure const& e) {
    return os << "Request failure: " << e;
  }

  enum class command : uint8_t {
    Connect = 0x01,
    Bind = 0x02,
    Associate = 0x03,
  };
  constexpr std::string_view command_tostring(command cmd) {
    constexpr std::array<const char*, 3> msgs = {
      "connect",
      "bind",
      "associate"
    };

    uint8_t val = static_cast<uint8_t>(cmd);

    if (val >= std::tuple_size_v<decltype(msgs)>)
      return "Unknown command";

    return msgs[val];
  }

  enum class status_code : uint8_t {
    RequestGranted = 0x00,
    GeneralFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TTLExpired,
    CommandNotSupported,
    AddressTypeNotSupported
  };
  constexpr std::string_view status_code_msg(status_code code) {
    constexpr std::array<const char*, 9> msgs = {
      "Request granted",
      "General failure",
      "Connection not allowed by ruleset",
      "Network unreachable",
      "Host unreachable",
      "Connection refused by remote host",
      "TTL expired",
      "Command not supported / protocol error",
      "Address type not supported"
    };

    uint8_t val = static_cast<uint8_t>(code);

    if (val >= std::tuple_size_v<decltype(msgs)>)
      return "Unknown error";

    return msgs[val];
  }

  struct status_error : std::exception {
    status_code code;

    inline char const* what() const noexcept override {
      return status_code_msg(code).data();
    }

    inline status_error(status_code code_) : code{code_} {}
  };

  ip_endpoint connect  (boost::asio::ip::tcp::socket& sock, ip_endpoint const& target, boost::asio::yield_context yield);
  ip_endpoint bind     (boost::asio::ip::tcp::socket& sock, ip_endpoint const& target, boost::asio::yield_context yield);
  ip_endpoint associate(boost::asio::ip::tcp::socket& sock, ip_endpoint const& target, boost::asio::yield_context yield);

  class server {
  public:
    /// Must be constructed uniquely for each socks_server
    struct impl {
      virtual void connect  (boost::asio::ip::tcp::socket&& sock, ip_endpoint const& target,
                             std::function<void(boost::asio::ip::tcp::socket&, status_code, ip_endpoint const&)> ready,
                             boost::asio::yield_context yield) = 0;
      virtual void bind     (boost::asio::ip::tcp::socket&& sock, ip_endpoint const& target,
                             std::function<void(boost::asio::ip::tcp::socket&, status_code, ip_endpoint const&)> ready,
                             boost::asio::yield_context yield) = 0;
      virtual void associate(boost::asio::ip::tcp::socket&& sock, ip_endpoint const& target,
                             std::function<void(boost::asio::ip::tcp::socket&, status_code, ip_endpoint const&)> ready,
                             boost::asio::yield_context yield) = 0;
    };

  private:
    boost::asio::ip::tcp::acceptor srv;
    cppthings::movable_ptr<impl> _impl;
    std::function<void(std::string_view)> warn_log;

  private:
    void accept_one(boost::system::error_code, boost::asio::ip::tcp::socket);

  public:
    inline server(boost::asio::io_context* io_ctx,
                  ip_endpoint const& ep,
                  impl* impl_,
                  decltype(warn_log) warn_log_ = {}) : srv{*io_ctx, ep}, _impl{impl_}, warn_log{std::move(warn_log_)} {
      srv.listen();
      srv.async_accept([this](auto&&... args){ accept_one(std::forward<decltype(args)>(args)...); });
    }
  };

//  boost::asio::ip::udp::socket associate(boost::asio::ip::tcp::socket& sock, boost::asio::ip:::udp::endpoint const& target);
}
