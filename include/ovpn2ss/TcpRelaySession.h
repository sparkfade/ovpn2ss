#pragma once

#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/PacketBuffer.h"
#include "ovpn2ss/ShadowsocksAead.h"

#include <asio.hpp>

#include <deque>
#include <memory>

namespace ovpn2ss {

class TcpRelaySession final : public std::enable_shared_from_this<TcpRelaySession> {
public:
    TcpRelaySession(asio::ip::tcp::socket socket, LwipRuntime& lwip, const ShadowsocksAeadFactory& crypto);
    ~TcpRelaySession();

    void start();

private:
    static err_t on_connected(void* arg, tcp_pcb* pcb, err_t err);
    static err_t on_recv(void* arg, tcp_pcb* pcb, pbuf* p, err_t err);
    static err_t on_sent(void* arg, tcp_pcb* pcb, u16_t len);
    static void on_err(void* arg, err_t err);

    void read_salt();
    void read_encrypted_stream();
    void process_decrypted_chunk(PacketBuffer chunk);
    void connect_target(const TargetAddress& target);
    void connect_ip(const ip_addr_t& ip, std::uint16_t port);
    void resolve_domain_then_connect(const TargetAddress& target);
    void flush_to_lwip();
    void enqueue_client_payload(std::span<const std::byte> bytes);
    void flush_to_client();
    void maybe_resume_client_read();
    void handle_client_eof();
    void handle_remote_fin();
    void detach_pcb_callbacks();
    void release_active_self();
    void close_client_only();
    void close();

    asio::ip::tcp::socket socket_;
    LwipRuntime& lwip_;
    ShadowsocksAeadSession crypto_;
    std::shared_ptr<TcpRelaySession> active_self_;
    tcp_pcb* pcb_{nullptr};

    std::array<std::byte, 8192> read_buf_{};
    PacketBuffer encrypted_in_;
    std::deque<PacketBuffer> pending_lwip_;
    std::deque<PacketBuffer> pending_client_;
    std::size_t client_queue_bytes_{0};
    std::size_t deferred_tcp_recved_{0};
    bool got_target_{false};
    bool sent_response_salt_{false};
    bool client_read_paused_{false};
    bool writing_client_{false};
    bool client_eof_{false};
    bool remote_eof_{false};
    bool closing_{false};
};

} // namespace ovpn2ss
