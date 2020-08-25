#include <gtest/gtest.h>

#include <sockspp.hpp>

#include <boost/asio/read.hpp>
#include <boost/asio/completion_condition.hpp>

TEST(sockspp, basic) {
  using buf_data_t = std::array<uint8_t, 6> ;

  struct basic_impl : sockspp::server::impl {
    std::pair<sockspp::command, boost::asio::ip::tcp::endpoint> last;
    buf_data_t buf_data = {1,2,3,4,5,6};
    boost::asio::const_buffer buf{buf_data.data(), buf_data.size()};

    // Crappy RNG to stop repetition looking like success
    boost::asio::const_buffer const& new_data() {
      for (auto& i : buf_data) {
        i += i*9;
        i += 1; // Stop 0 cycles
      }

      return buf;
    }

    void connect  (boost::asio::ip::tcp::socket&& sock, sockspp::ip_endpoint const& ep,
                   std::function<void(boost::asio::ip::tcp::socket&, sockspp::status_code, sockspp::ip_endpoint const&)> report,
                   boost::asio::yield_context yield) override {
      last = {sockspp::command::Connect, ep};
      report(sock, sockspp::status_code::RequestGranted, ep);
      sock.write_some(new_data());
    }
    void bind     (boost::asio::ip::tcp::socket&& sock, sockspp::ip_endpoint const& ep,
                   std::function<void(boost::asio::ip::tcp::socket&, sockspp::status_code, sockspp::ip_endpoint const&)> report,
                   boost::asio::yield_context yield) override {
      last = {sockspp::command::Bind, ep};
      report(sock, sockspp::status_code::RequestGranted, ep);
      sock.write_some(new_data());
    }
    void associate(boost::asio::ip::tcp::socket&& sock, sockspp::ip_endpoint const& ep,
                   std::function<void(boost::asio::ip::tcp::socket&, sockspp::status_code, sockspp::ip_endpoint const&)> report,
                   boost::asio::yield_context yield) override {
      last = {sockspp::command::Associate, ep};
      report(sock, sockspp::status_code::RequestGranted, ep);
      sock.write_some(new_data());
    }
  };

  boost::asio::io_context io_ctx;

  // 65123 is not generally used
  boost::asio::ip::tcp::endpoint socks_ep{boost::asio::ip::make_address("127.0.0.1"), 65123};
  // This is not actually acted upon properly, so this can be anything
  boost::asio::ip::tcp::endpoint target{boost::asio::ip::make_address("127.0.0.1"), 8192};

  basic_impl impl;
  sockspp::server socks_srv{&io_ctx, socks_ep, &impl, [](auto x) { std::cout << "SERVER WARN: " << x << std::endl; }};

  boost::asio::spawn(io_ctx, [&](auto yield) {
    decltype(sockspp::connect)* cmds[4] = {nullptr, &sockspp::connect, &sockspp::bind, &sockspp::associate};
    for (auto command : {sockspp::command::Connect, sockspp::command::Bind, sockspp::command::Associate}) {
      target.port(target.port() + 1);
      boost::asio::ip::tcp::socket sock(io_ctx);
      sock.connect(socks_ep);

      try {
        cmds[static_cast<uint8_t>(command)](sock, target, yield);
        EXPECT_EQ(command, impl.last.first);
        EXPECT_EQ(target, impl.last.second);
        buf_data_t buf_data;
        boost::asio::async_read(sock, boost::asio::mutable_buffer(buf_data.data(), buf_data.size()),
                                boost::asio::transfer_exactly(buf_data.size()));
        EXPECT_EQ(buf_data, impl.buf_data);
      }
      catch (std::exception const& e) {
        EXPECT_TRUE(false) << sockspp::command_tostring(command) << " failed with err " << e.what();
      }
    }

    io_ctx.stop();
  });

  io_ctx.run();
}
