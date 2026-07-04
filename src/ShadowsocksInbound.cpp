#include "ovpn2ss/ShadowsocksInbound.h"

#include "ovpn2ss/TcpRelaySession.h"

#include <iostream>

namespace ovpn2ss {

ShadowsocksInbound::ShadowsocksInbound(asio::io_context& io, LwipRuntime& lwip, ShadowsocksConfig config)
    : tcp_acceptor_(io), lwip_(lwip), config_(std::move(config)), crypto_(config_.password), io_(io) {
}

void ShadowsocksInbound::start() {
    if (started_) {
        return;
    }
    started_ = true;
    open_tcp_acceptor();
    accept_loop();
    if (config_.udp_port != 0 && !udp_) {
        udp_ = std::make_shared<UdpRelaySession>(io_, config_.listen_host, config_.udp_port, lwip_, crypto_);
    }
    if (udp_) {
        udp_->start();
    }
    std::clog << "ovpn2ss: shadowsocks listening tcp=" << config_.listen_host << ':' << config_.tcp_port
              << " udp=" << config_.listen_host << ':' << config_.udp_port << '\n';
}

void ShadowsocksInbound::stop() {
    started_ = false;
    asio::error_code ignored;
    tcp_acceptor_.close(ignored);
    if (udp_) {
        udp_->stop();
        udp_.reset();
    }
    std::clog << "ovpn2ss: shadowsocks stopped\n";
}

void ShadowsocksInbound::open_tcp_acceptor() {
    if (tcp_acceptor_.is_open()) {
        return;
    }
    asio::ip::tcp::endpoint ep(asio::ip::make_address(config_.listen_host), config_.tcp_port);
    tcp_acceptor_.open(ep.protocol());
    tcp_acceptor_.set_option(asio::socket_base::reuse_address(true));
    tcp_acceptor_.bind(ep);
    tcp_acceptor_.listen(asio::socket_base::max_listen_connections);
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
