#include "ovpn2ss/ShadowsocksInbound.h"

#include "ovpn2ss/TcpRelaySession.h"

namespace ovpn2ss {

ShadowsocksInbound::ShadowsocksInbound(asio::io_context& io, LwipRuntime& lwip, ShadowsocksConfig config)
    : tcp_acceptor_(io), lwip_(lwip), config_(std::move(config)), crypto_(config_.password), io_(io) {
    asio::ip::tcp::endpoint ep(asio::ip::make_address(config_.listen_host), config_.tcp_port);
    tcp_acceptor_.open(ep.protocol());
    tcp_acceptor_.set_option(asio::socket_base::reuse_address(true));
    tcp_acceptor_.bind(ep);
    tcp_acceptor_.listen(asio::socket_base::max_listen_connections);
    if (config_.udp_port != 0) {
        udp_ = std::make_shared<UdpRelaySession>(io_, config_.listen_host, config_.udp_port, lwip_, crypto_);
    }
}

void ShadowsocksInbound::start() {
    accept_loop();
    if (udp_) {
        udp_->start();
    }
}

void ShadowsocksInbound::stop() {
    asio::error_code ignored;
    tcp_acceptor_.close(ignored);
    if (udp_) {
        udp_->stop();
    }
}

void ShadowsocksInbound::accept_loop() {
    tcp_acceptor_.async_accept([this](const asio::error_code& ec, asio::ip::tcp::socket socket) {
        if (!ec) {
            std::make_shared<TcpRelaySession>(std::move(socket), lwip_, crypto_)->start();
        }
        if (tcp_acceptor_.is_open()) {
            accept_loop();
        }
    });
}

} // namespace ovpn2ss
