#include "ovpn2ss/MultiInstanceManager.h"
#include "ovpn2ss/ShadowsocksAead.h"

#include <cassert>
#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>

namespace {

std::span<const std::byte> bytes_of(const std::string& s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

void test_address_codec() {
    ovpn2ss::TargetAddress target{ovpn2ss::AddressType::Domain, "example.com", 443};
    auto encoded = ovpn2ss::encode_ss_address(target);
    auto view = std::span<const std::byte>(encoded.data(), encoded.size());
    auto parsed = ovpn2ss::parse_ss_address(view);
    assert(parsed.has_value());
    assert(parsed->type == ovpn2ss::AddressType::Domain);
    assert(parsed->host == "example.com");
    assert(parsed->port == 443);
    assert(view.empty());
}

void test_ip_address_codec() {
    {
        ovpn2ss::TargetAddress target{ovpn2ss::AddressType::Ipv4, "192.0.2.1", 53};
        auto encoded = ovpn2ss::encode_ss_address(target);
        auto view = std::span<const std::byte>(encoded.data(), encoded.size());
        auto parsed = ovpn2ss::parse_ss_address(view);
        assert(parsed.has_value());
        assert(parsed->type == ovpn2ss::AddressType::Ipv4);
        assert(parsed->host == "192.0.2.1");
        assert(parsed->port == 53);
        assert(view.empty());
    }
    {
        ovpn2ss::TargetAddress target{ovpn2ss::AddressType::Ipv6, "2001:db8::1", 853};
        auto encoded = ovpn2ss::encode_ss_address(target);
        auto view = std::span<const std::byte>(encoded.data(), encoded.size());
        auto parsed = ovpn2ss::parse_ss_address(view);
        assert(parsed.has_value());
        assert(parsed->type == ovpn2ss::AddressType::Ipv6);
        assert(parsed->port == 853);
        assert(view.empty());
    }
}

void test_aead_tcp() {
    ovpn2ss::ShadowsocksAeadFactory factory("password");
    auto client = factory.make_session();
    auto server = factory.make_session();
    auto salt = client.client_salt();
    server.set_client_salt(salt.span());
    auto encrypted = client.encrypt_tcp_chunk(bytes_of("hello"));
    auto view = std::span<const std::byte>(encrypted.data(), encrypted.size());
    auto plain = server.decrypt_tcp_chunk(view);
    assert(plain.has_value());
    assert(std::string(reinterpret_cast<const char*>(plain->data()), plain->size()) == "hello");
    assert(view.empty());
}

void test_aead_udp() {
    ovpn2ss::ShadowsocksAeadFactory factory("password");
    auto sender = factory.make_session();
    auto receiver = factory.make_session();
    auto encrypted = sender.encrypt_udp_packet(bytes_of("packet"));
    auto plain = receiver.decrypt_udp_packet(encrypted.span());
    assert(plain.has_value());
    assert(std::string(reinterpret_cast<const char*>(plain->data()), plain->size()) == "packet");
}

void test_aead_salts_are_unique() {
    ovpn2ss::ShadowsocksAeadFactory factory("password");
    auto first = factory.make_session().client_salt();
    auto second = factory.make_session().client_salt();
    assert(first.size() == ovpn2ss::ShadowsocksAeadSession::SaltSize);
    assert(second.size() == ovpn2ss::ShadowsocksAeadSession::SaltSize);
    assert(!std::equal(first.span().begin(), first.span().end(), second.span().begin(), second.span().end()));
}

void test_json_config() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test";
    std::filesystem::create_directories(dir);
    const auto ovpn = dir / "test.ovpn";
    const auto config = dir / "config.json";
    { std::ofstream out(ovpn); out << "client\n"; }
    {
        std::ofstream out(config);
        out << R"({"instances":[{"name":"test","ovpn":")" << ovpn.string()
            << R"(","listen_host":"127.0.0.1","tcp_port":31081,"udp_port":31082,"password":"pw","method":"chacha20-ietf-poly1305"}]})";
    }
    auto loaded = ovpn2ss::MultiInstanceManager::load_json_config(config);
    assert(loaded.instances.size() == 1);
    assert(loaded.instances[0].name == "test");
    assert(loaded.instances[0].shadowsocks.tcp_port == 31081);
    assert(loaded.instances[0].shadowsocks.udp_port == 31082);
}

void test_json_config_allows_tcp_udp_same_port() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test-same-port";
    std::filesystem::create_directories(dir);
    const auto ovpn = dir / "test.ovpn";
    const auto config = dir / "config.json";
    { std::ofstream out(ovpn); out << "client\n"; }
    {
        std::ofstream out(config);
        out << R"({"instances":[{"name":"test","ovpn":")" << ovpn.string()
            << R"(","listen_host":"127.0.0.1","tcp_port":31083,"password":"pw"}]})";
    }
    auto loaded = ovpn2ss::MultiInstanceManager::load_json_config(config);
    assert(loaded.instances.size() == 1);
    assert(loaded.instances[0].shadowsocks.tcp_port == 31083);
    assert(loaded.instances[0].shadowsocks.udp_port == 31083);
}

void test_json_config_rejects_duplicate_tcp_port() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test-dup-tcp";
    std::filesystem::create_directories(dir);
    const auto ovpn1 = dir / "one.ovpn";
    const auto ovpn2 = dir / "two.ovpn";
    const auto config = dir / "config.json";
    { std::ofstream out(ovpn1); out << "client\n"; }
    { std::ofstream out(ovpn2); out << "client\n"; }
    {
        std::ofstream out(config);
        out << R"({"instances":[{"name":"one","ovpn":")" << ovpn1.string()
            << R"(","tcp_port":31084,"udp_port":31085,"password":"pw"},{"name":"two","ovpn":")"
            << ovpn2.string() << R"(","tcp_port":31084,"udp_port":31086,"password":"pw"}]})";
    }
    bool rejected = false;
    try {
        (void)ovpn2ss::MultiInstanceManager::load_json_config(config);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

void test_json_config_rejects_duplicate_udp_port() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test-dup-udp";
    std::filesystem::create_directories(dir);
    const auto ovpn1 = dir / "one.ovpn";
    const auto ovpn2 = dir / "two.ovpn";
    const auto config = dir / "config.json";
    { std::ofstream out(ovpn1); out << "client\n"; }
    { std::ofstream out(ovpn2); out << "client\n"; }
    {
        std::ofstream out(config);
        out << R"({"instances":[{"name":"one","ovpn":")" << ovpn1.string()
            << R"(","tcp_port":31087,"udp_port":31089,"password":"pw"},{"name":"two","ovpn":")"
            << ovpn2.string() << R"(","tcp_port":31088,"udp_port":31089,"password":"pw"}]})";
    }
    bool rejected = false;
    try {
        (void)ovpn2ss::MultiInstanceManager::load_json_config(config);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

void test_json_config_allows_cross_protocol_port_reuse() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test-cross-protocol";
    std::filesystem::create_directories(dir);
    const auto ovpn1 = dir / "one.ovpn";
    const auto ovpn2 = dir / "two.ovpn";
    const auto config = dir / "config.json";
    { std::ofstream out(ovpn1); out << "client\n"; }
    { std::ofstream out(ovpn2); out << "client\n"; }
    {
        std::ofstream out(config);
        out << R"({"instances":[{"name":"one","ovpn":")" << ovpn1.string()
            << R"(","tcp_port":31090,"udp_port":31091,"password":"pw"},{"name":"two","ovpn":")"
            << ovpn2.string() << R"(","tcp_port":31091,"udp_port":31090,"password":"pw"}]})";
    }
    auto loaded = ovpn2ss::MultiInstanceManager::load_json_config(config);
    assert(loaded.instances.size() == 2);
}

void test_json_config_rejects_empty_instances() {
    const auto dir = std::filesystem::temp_directory_path() / "ovpn2ss-test-empty";
    std::filesystem::create_directories(dir);
    const auto config = dir / "config.json";
    { std::ofstream out(config); out << R"({"instances":[]})"; }
    bool rejected = false;
    try {
        (void)ovpn2ss::MultiInstanceManager::load_json_config(config);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

} // namespace

int main() {
    test_address_codec();
    test_ip_address_codec();
    test_aead_tcp();
    test_aead_udp();
    test_aead_salts_are_unique();
    test_json_config();
    test_json_config_allows_tcp_udp_same_port();
    test_json_config_rejects_duplicate_tcp_port();
    test_json_config_rejects_duplicate_udp_port();
    test_json_config_allows_cross_protocol_port_reuse();
    test_json_config_rejects_empty_instances();
    return 0;
}
