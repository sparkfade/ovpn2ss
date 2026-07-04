#pragma once

#include "ovpn2ss/InstanceConfig.h"
#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/OpenVpnPacketSink.h"

#include <cstddef>
#include <span>
#include <string>

#include <openvpn/tun/builder/base.hpp>

namespace ovpn2ss {

class OpenVpnTunBuilder final : public openvpn::TunBuilderBase {
public:
    OpenVpnTunBuilder(LwipRuntime& lwip, OpenVpnPacketSink& vpn_sink);

    bool tun_builder_new() override;
    int tun_builder_establish() override;
    bool tun_builder_add_address(
        const std::string& address,
        int prefix_length,
        const std::string& gateway,
        bool ipv6,
        bool net30) override;
    bool tun_builder_set_mtu(int mtu) override;
    bool tun_builder_set_dns_options(const openvpn::DnsOptions& dns) override;
    bool tun_builder_add_dns_server(const std::string& address, bool ipv6);
    bool tun_builder_add_route(
        const std::string& address,
        int prefix_length,
        int metric,
        bool ipv6) override;
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override;
    bool tun_builder_exclude_route(
        const std::string& address,
        int prefix_length,
        int metric,
        bool ipv6) override;
    bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override;
    bool tun_builder_set_session_name(const std::string& name) override;
    bool tun_builder_add_proxy_bypass(const std::string& bypass_host) override;
    bool tun_builder_set_proxy_auto_config_url(const std::string& url) override;
    bool tun_builder_set_proxy_http(const std::string& host, int port) override;
    bool tun_builder_set_proxy_https(const std::string& host, int port) override;
    void tun_builder_teardown(bool disconnect) override;

    void inject_from_openvpn(std::span<const std::byte> packet);
    void send_from_lwip(std::span<const std::byte> packet);

private:
    LwipRuntime& lwip_;
    OpenVpnPacketSink& vpn_sink_;
    TunConfig pending_;
};

} // namespace ovpn2ss
