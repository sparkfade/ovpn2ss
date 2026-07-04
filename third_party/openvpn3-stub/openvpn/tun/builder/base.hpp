#pragma once

#include <string>
#include <map>
#include <vector>

namespace openvpn {

struct DnsAddress {
    std::string address;
};

struct DnsServer {
    std::vector<DnsAddress> addresses;
};

struct DnsOptions {
    std::map<int, DnsServer> servers;
};

class TunBuilderBase {
public:
    virtual ~TunBuilderBase() = default;

    virtual bool tun_builder_new() { return true; }
    virtual int tun_builder_establish() { return 0; }

    virtual bool tun_builder_add_address(
        const std::string& address,
        int prefix_length,
        const std::string& gateway,
        bool ipv6,
        bool net30) {
        (void)address;
        (void)prefix_length;
        (void)gateway;
        (void)ipv6;
        (void)net30;
        return true;
    }

    virtual bool tun_builder_set_mtu(int mtu) {
        (void)mtu;
        return true;
    }

    virtual bool tun_builder_set_dns_options(const DnsOptions& dns) {
        (void)dns;
        return true;
    }

    virtual bool tun_builder_add_route(
        const std::string& address,
        int prefix_length,
        int metric,
        bool ipv6) {
        (void)address;
        (void)prefix_length;
        (void)metric;
        (void)ipv6;
        return true;
    }

    virtual bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) {
        (void)ipv4;
        (void)ipv6;
        (void)flags;
        return true;
    }

    virtual bool tun_builder_exclude_route(
        const std::string& address,
        int prefix_length,
        int metric,
        bool ipv6) {
        (void)address;
        (void)prefix_length;
        (void)metric;
        (void)ipv6;
        return true;
    }

    virtual bool tun_builder_set_remote_address(const std::string& address, bool ipv6) {
        (void)address;
        (void)ipv6;
        return true;
    }

    virtual bool tun_builder_set_session_name(const std::string& name) {
        (void)name;
        return true;
    }

    virtual bool tun_builder_add_proxy_bypass(const std::string& bypass_host) {
        (void)bypass_host;
        return true;
    }

    virtual bool tun_builder_set_proxy_auto_config_url(const std::string& url) {
        (void)url;
        return true;
    }

    virtual bool tun_builder_set_proxy_http(const std::string& host, int port) {
        (void)host;
        (void)port;
        return true;
    }

    virtual bool tun_builder_set_proxy_https(const std::string& host, int port) {
        (void)host;
        (void)port;
        return true;
    }

    virtual void tun_builder_teardown(bool disconnect) {
        (void)disconnect;
    }
};

} // namespace openvpn
