#include "ovpn2ss/OpenVpnTunBuilder.h"

#include <exception>

namespace ovpn2ss {

OpenVpnTunBuilder::OpenVpnTunBuilder(LwipRuntime& lwip, OpenVpnPacketSink& vpn_sink)
    : lwip_(lwip), vpn_sink_(vpn_sink) {}

bool OpenVpnTunBuilder::tun_builder_new() {
    pending_ = TunConfig{};
    return true;
}

int OpenVpnTunBuilder::tun_builder_establish() {
    try {
        lwip_.apply_tun_config_and_output(pending_, [this](std::span<const std::byte> packet) {
            send_from_lwip(packet);
        });
        return 0;
    } catch (...) {
        return -1;
    }
}

bool OpenVpnTunBuilder::tun_builder_add_address(
    const std::string& address,
    int prefix_length,
    const std::string& gateway,
    bool ipv6,
    bool net30) {
    pending_.addresses.push_back(TunAddress{address, gateway, prefix_length, ipv6, net30});
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_mtu(int mtu) {
    pending_.mtu = mtu;
    return true;
}

bool OpenVpnTunBuilder::tun_builder_add_dns_server(const std::string& address, bool ipv6) {
    if (ipv6) {
        pending_.ipv6_dns.push_back(address);
    } else {
        pending_.ipv4_dns.push_back(address);
    }
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_dns_options(const openvpn::DnsOptions& dns) {
    for (const auto& [_, server] : dns.servers) {
        for (const auto& address : server.addresses) {
            const bool ipv6 = address.address.find(':') != std::string::npos;
            tun_builder_add_dns_server(address.address, ipv6);
        }
    }
    return true;
}

bool OpenVpnTunBuilder::tun_builder_add_route(const std::string&, int, int, bool) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_reroute_gw(bool, bool, unsigned int) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_exclude_route(const std::string&, int, int, bool) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_remote_address(const std::string&, bool) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_session_name(const std::string&) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_add_proxy_bypass(const std::string&) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_proxy_auto_config_url(const std::string&) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_proxy_http(const std::string&, int) {
    return true;
}

bool OpenVpnTunBuilder::tun_builder_set_proxy_https(const std::string&, int) {
    return true;
}

void OpenVpnTunBuilder::tun_builder_teardown(bool) {
    lwip_.set_packet_output({});
}

void OpenVpnTunBuilder::inject_from_openvpn(std::span<const std::byte> packet) {
    try {
        lwip_.inject_l3_packet(packet);
    } catch (...) {
    }
}

void OpenVpnTunBuilder::send_from_lwip(std::span<const std::byte> packet) {
    try {
        vpn_sink_.send_l3_packet(packet);
    } catch (...) {
    }
}

} // namespace ovpn2ss
