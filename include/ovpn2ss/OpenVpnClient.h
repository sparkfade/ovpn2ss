#pragma once

#include "ovpn2ss/InstanceConfig.h"
#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/OpenVpnPacketSink.h"
#include "ovpn2ss/OpenVpnTunBuilder.h"

#include <asio.hpp>

#include <atomic>
#include <memory>
#include <thread>

namespace ovpn2ss {

class OpenVpnClient final : public OpenVpnPacketSink {
public:
    OpenVpnClient(asio::io_context& io, LwipRuntime& lwip, InstanceConfig config);
    ~OpenVpnClient() override;

    void start();
    void stop();
    void send_l3_packet(std::span<const std::byte> packet) override;

    [[nodiscard]] OpenVpnTunBuilder& tun_builder() noexcept { return tun_builder_; }

private:
    struct Impl;
    void run_connect_loop(std::stop_token stop_token);

    asio::io_context& io_;
    LwipRuntime& lwip_;
    InstanceConfig config_;
    OpenVpnTunBuilder tun_builder_;
    std::unique_ptr<Impl> impl_;
    std::jthread vpn_thread_;
    std::atomic_bool running_{false};
    std::atomic_bool needs_downgrade_{false};
};

} // namespace ovpn2ss
