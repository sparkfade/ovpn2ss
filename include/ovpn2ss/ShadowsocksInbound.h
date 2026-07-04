#pragma once

#include "ovpn2ss/InstanceConfig.h"
#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/ShadowsocksAead.h"
#include "ovpn2ss/UdpRelaySession.h"

#include <asio.hpp>

#include <memory>

namespace ovpn2ss {

class ShadowsocksInbound final {
public:
    ShadowsocksInbound(asio::io_context& io, LwipRuntime& lwip, ShadowsocksConfig config);

    void start();
    void stop();

private:
    void open_tcp_acceptor();
    void accept_loop();

    asio::ip::tcp::acceptor tcp_acceptor_;
    LwipRuntime& lwip_;
    ShadowsocksConfig config_;
    ShadowsocksAeadFactory crypto_;
    std::shared_ptr<UdpRelaySession> udp_;
    asio::io_context& io_;
    bool started_{false};
};

} // namespace ovpn2ss
