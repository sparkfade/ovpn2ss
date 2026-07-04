#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace ovpn2ss {

struct ShadowsocksConfig {
    std::string listen_host{"127.0.0.1"};
    std::uint16_t tcp_port{};
    std::uint16_t udp_port{};
    std::string method{"chacha20-ietf-poly1305"};
    std::string password;
};

struct InstanceConfig {
    std::string name;
    std::filesystem::path ovpn_path;
    ShadowsocksConfig shadowsocks;
    bool udp_enabled{true};
};

struct ManagerConfig {
    std::filesystem::path json_path;
    std::vector<InstanceConfig> instances;
};

struct TunAddress {
    std::string address;
    std::string gateway;
    int prefix_length{};
    bool ipv6{};
    bool net30{};
};

struct TunConfig {
    std::vector<TunAddress> addresses;
    std::vector<std::string> ipv4_dns;
    std::vector<std::string> ipv6_dns;
    int mtu{1500};
};

enum class AddressType : std::uint8_t {
    Ipv4 = 1,
    Domain = 3,
    Ipv6 = 4,
};

struct TargetAddress {
    AddressType type{};
    std::string host;
    std::uint16_t port{};
};

} // namespace ovpn2ss
