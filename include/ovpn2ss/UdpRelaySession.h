#pragma once

#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/ShadowsocksAead.h"

#include <asio.hpp>

#include <memory>
#include <unordered_map>

namespace ovpn2ss {

class UdpRelaySession final : public std::enable_shared_from_this<UdpRelaySession> {
public:
    UdpRelaySession(asio::io_context& io, const std::string& listen_host, std::uint16_t listen_port,
        LwipRuntime& lwip, const ShadowsocksAeadFactory& crypto);
    ~UdpRelaySession();

    void start();
    void stop();

private:
    struct Mapping {
        UdpRelaySession* owner{};
        udp_pcb* pcb{};
        asio::ip::udp::endpoint client;
        TargetAddress target;
        std::string key;
        std::unique_ptr<asio::steady_timer> idle_timer;
    };

    static void on_udp_recv(void* arg, udp_pcb* pcb, pbuf* p, const ip_addr_t* addr, u16_t port);

    void receive_loop();
    void send_to_lwip(std::span<const std::byte> datagram, const asio::ip::udp::endpoint& client);
    void send_payload_to_ip(std::span<const std::byte> payload, const asio::ip::udp::endpoint& client,
        const TargetAddress& target, const ip_addr_t& ip);
    void resolve_domain_then_send(std::span<const std::byte> payload, const asio::ip::udp::endpoint& client,
        const TargetAddress& target);
    void send_to_client(Mapping& mapping, std::span<const std::byte> payload, const ip_addr_t* addr, u16_t port);
    Mapping* mapping_for(const asio::ip::udp::endpoint& client, const TargetAddress& target);
    void arm_idle_timer(Mapping& mapping);
    void erase_mapping(const std::string& key);

    asio::ip::udp::socket socket_;
    LwipRuntime& lwip_;
    ShadowsocksAeadFactory crypto_;
    std::array<std::byte, 65536> recv_buf_{};
    asio::ip::udp::endpoint recv_endpoint_;
    std::unordered_map<std::string, std::unique_ptr<Mapping>> mappings_;
    std::shared_ptr<bool> lifetime_token_{std::make_shared<bool>(true)};
    bool running_{false};
};

} // namespace ovpn2ss
