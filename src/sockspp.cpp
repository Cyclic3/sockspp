#include <sockspp.hpp>

#include <boost/asio/completion_condition.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/spawn.hpp>

#include <algorithm>

namespace sockspp {
  // TODO: Implement domain address type
  //
  // TODO: Make sure to check domain size is <= 255 (once impl'd ofc)

  constexpr size_t buffer_size = 512;
  using buffer_t = std::shared_ptr<std::array<uint8_t, buffer_size>>;
  buffer_t make_buffer() { return std::make_shared<std::array<uint8_t, buffer_size>>(); }

  constexpr uint8_t socks_version = 5;

  enum class ep_type : uint8_t {
    IPv4 = 0x01,
    IPv6 = 0x04,
    Domain = 0x03
  };

  template<typename Iter>
  Iter pack_addr(Iter iter, boost::asio::ip::address_v4 const& addr) {
    *iter++ = static_cast<uint8_t>(ep_type::IPv4);
    auto b = addr.to_bytes();
    return std::copy(b.begin(), b.end(), iter);
  }
  template<typename Iter>
  Iter pack_addr(Iter iter, boost::asio::ip::address_v6 const& addr) {
    *iter++ = static_cast<uint8_t>(ep_type::IPv6);
    auto b = addr.to_bytes();
    return std::copy(b.begin(), b.end(), iter);
  }
  template<typename Iter>
  Iter pack_addr(Iter iter, boost::asio::ip::address const& addr) {
    if (addr.is_v4())
      return pack_addr(iter, addr.to_v4());
    else
      return pack_addr(iter, addr.to_v6());
  }
  template<typename Iter>
  Iter pack_addr(Iter iter, std::string_view const& domain) {
    *iter++ = static_cast<uint8_t>(ep_type::Domain);
    return std::copy(domain.begin(), domain.end(), iter);
  }
  template<typename Iter, typename Ep>
  Iter pack_ep(Iter iter, Ep const& ep) {
    iter = pack_addr(iter, ep.address());
    auto port = ep.port();
    *iter++ = port >> 8;
    *iter++ = port & 0xFF;
    return iter;
  }

  template<typename Stream>
  ip_endpoint unpack_ep(Stream& stream, boost::asio::yield_context yield) {
    uint8_t type;
    boost::asio::async_read(stream, boost::asio::mutable_buffer(&type, 1),
                            boost::asio::transfer_exactly(1), yield);

    switch(static_cast<ep_type>(type)) {
      case ep_type::IPv4: {
        std::array<uint8_t, 4 + 2> buf;

        boost::asio::async_read(stream, boost::asio::mutable_buffer(buf.data(), buf.size()),
                                boost::asio::transfer_exactly(buf.size()), yield);
        uint32_t ip_addr = 0;
        for (size_t i = 0; i < 4; ++i) {
          ip_addr <<= 8;
          ip_addr |= buf[i];
        }

        return {
          boost::asio::ip::address_v4(ip_addr),
          static_cast<uint16_t>((buf[4] << 8) | buf[5])
        };
      } break;
      case ep_type::IPv6: {
        std::array<uint8_t, 16 + 2> buf;

        boost::asio::async_read(stream, boost::asio::mutable_buffer(buf.data(), buf.size()),
                                boost::asio::transfer_exactly(buf.size()), yield);

        return {
          boost::asio::ip::address_v6(*reinterpret_cast<std::array<uint8_t, 16>*>(buf.data())),
          static_cast<uint16_t>((buf[4] << 8) | buf[5])
        };
      } break;

      case ep_type::Domain: {
        throw request_failure{"Domain ep type not implemented"};
      } break;

      default: throw request_failure{"Unknown ep type"};
    }
  }

  void client_initial_handshake(boost::asio::ip::tcp::socket& sock, boost::asio::yield_context yield) {
    static std::array<uint8_t, 3> initial_greeting{
      socks_version,
      /* one auth method supported*/ 1,
      /* no auth */ 0
    };
    static boost::asio::const_buffer initial_greeting_buf{initial_greeting.data(), initial_greeting.size()};
    boost::asio::async_write(sock, initial_greeting_buf, yield);

    std::array<uint8_t, 2> recv;
    boost::asio::async_read(sock, boost::asio::mutable_buffer(recv.data(), recv.size()), boost::asio::transfer_exactly(recv.size()), yield);

    if (recv[0] != socks_version)
      throw request_failure{"Server handshake was invalid"};
    else if (recv[1] != 0)
      throw request_failure{"Server requires authentication"};
  }
  void server_initial_handshake(boost::asio::ip::tcp::socket& sock, boost::asio::yield_context yield) {
    std::array<uint8_t, buffer_size> recv;
    // Get the remote version
    auto len = boost::asio::async_read(sock, boost::asio::mutable_buffer(recv.data(), recv.size()), boost::asio::transfer_at_least(3), yield);
    if (recv[0] != socks_version)
      throw request_failure{"Bad socks version"};

    size_t n = recv[1];

    // Grab the rest of the methods
    if (len - 2 < n)
      boost::asio::async_read(sock, boost::asio::mutable_buffer(recv.data(), recv.size()), boost::asio::transfer_exactly(n - len - 2), yield);

    if (std::find(recv.begin() + 2, recv.end(), 0) == recv.end())
      throw request_failure{"No auth unsupported"};

    static std::array<uint8_t, 2> initial_greeting{
      socks_version,
      /* no auth */ 0
    };
    static boost::asio::const_buffer initial_greeting_buf{initial_greeting.data(), initial_greeting.size()};
    boost::asio::async_write(sock, initial_greeting_buf, yield);
  }

  template<typename Addr>
  ip_endpoint send_connection_request(boost::asio::ip::tcp::socket& sock, command cmd,
                                                         Addr const& addr, uint16_t port,
                                                         boost::asio::yield_context yield) {

  }
  ip_endpoint send_connection_request(boost::asio::ip::tcp::socket& sock, command cmd,
                                                         ip_endpoint const& target,
                                                         boost::asio::yield_context yield) {
    std::array<uint8_t, buffer_size> buf;

    auto start = buf.begin();
    auto iter = start;
    *iter++ = socks_version;
    *iter++ = static_cast<uint8_t>(cmd);
    *iter++ = 0; // Reserved field
    iter = pack_ep(iter, target);

    boost::asio::async_write(sock, boost::asio::buffer(buf.data(), static_cast<size_t>(iter - start)), yield);

    boost::asio::async_read(sock, boost::asio::mutable_buffer(buf.data(), buf.size()), boost::asio::transfer_exactly(3), yield);

    if (buf[0] != socks_version)
      throw request_failure{"Server version was invalid"};

    if (buf[1]) // get the status code
      throw status_error{static_cast<status_code>(buf[1])};

    return unpack_ep(sock, yield);
  }
  std::pair<command, ip_endpoint> receive_connection_request(boost::asio::ip::tcp::socket& sock,
                                                             boost::asio::yield_context yield) {
    std::pair<command, ip_endpoint> ret;

    std::array<uint8_t, 3> buf;

    boost::asio::async_read(sock, boost::asio::mutable_buffer(buf.data(), buf.size()), boost::asio::transfer_exactly(3), yield);

    if (buf[0] != socks_version)
      throw request_failure{"Bad socks version"};
    ret.first = static_cast<command>(buf[1]);

    ret.second = unpack_ep(sock, yield);

    return ret;
  }
  void answer_connection_request(boost::asio::ip::tcp::socket& sock, status_code status,
                                 ip_endpoint const& ep,
                                 boost::asio::yield_context yield) {
    std::array<uint8_t, buffer_size> buf;
    auto start = buf.begin();
    auto iter = start;
    *iter++ = socks_version;
    *iter++ = static_cast<uint8_t>(status);
    *iter++ = 0; // Reserved field
    iter = pack_ep(iter, ep);

    boost::asio::async_write(sock, boost::asio::buffer(buf.data(), static_cast<size_t>(iter - start)), yield);
  }

  ip_endpoint connect(boost::asio::ip::tcp::socket& sock, ip_endpoint const& target,
                                         boost::asio::yield_context yield) {
    client_initial_handshake(sock, yield);
    return send_connection_request(sock, command::Connect, target, yield);
  }
  ip_endpoint bind(boost::asio::ip::tcp::socket& sock, ip_endpoint const& target,
                                      boost::asio::yield_context yield) {
    client_initial_handshake(sock, yield);
    return send_connection_request(sock, command::Bind, target, yield);
  }
  ip_endpoint associate(boost::asio::ip::tcp::socket& sock, ip_endpoint const& target,
                                           boost::asio::yield_context yield) {
    client_initial_handshake(sock, yield);
    return send_connection_request(sock, command::Associate, target, yield);
  }

  void server::accept_one(boost::system::error_code ec, boost::asio::ip::tcp::socket sock) {
    if (ec) {
      if (warn_log)
        warn_log("SOCKS5 server encountered system error code " + ec.message());
    }
    else
      boost::asio::spawn(sock.get_executor(), [sock{std::move(sock)}, this](auto yield) mutable {
        server_initial_handshake(sock, yield);
        auto req = receive_connection_request(sock, yield);
        switch (req.first) {
          case command::Connect: {
             _impl->connect (std::move(sock), std::move(req.second),
                             [=](auto&&... x) { answer_connection_request(x..., yield); },
                             yield);
          } break;
          case command::Bind: {
            _impl->bind     (std::move(sock), std::move(req.second),
                             [=](auto&&... x) { answer_connection_request(x..., yield); },
                             yield);
          } break;
          case command::Associate: {
            _impl->associate(std::move(sock), std::move(req.second),
                             [=](auto&&... x) { answer_connection_request(x..., yield); },
                             yield);
          } break;
          default:
            if (warn_log)
              warn_log("SOCKS5 server encountered system error code " + std::to_string(static_cast<int>(req.first)));
        }
      });

    srv.async_accept([this](auto&&... args){ accept_one(std::forward<decltype(args)>(args)...); });
  }
}
