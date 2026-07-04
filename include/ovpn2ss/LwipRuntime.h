#pragma once

#include "ovpn2ss/InstanceConfig.h"

#include <asio.hpp>

extern "C" {
#include <lwip/err.h>
#include <lwip/init.h>
#include <lwip/ip_addr.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/udp.h>
}

#include <cstddef>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <unordered_map>

namespace ovpn2ss {

class LwipRuntime final {
public:
    class StackUse final {
    public:
        StackUse(StackUse&&) noexcept = default;
        StackUse& operator=(StackUse&&) noexcept = delete;
        StackUse(const StackUse&) = delete;
        StackUse& operator=(const StackUse&) = delete;

    private:
        friend class LwipRuntime;
        explicit StackUse(LwipRuntime& runtime);

        LwipRuntime& runtime_;
        std::unique_lock<std::recursive_mutex> lock_;
    };

    explicit LwipRuntime(asio::io_context& io);
    ~LwipRuntime();

    LwipRuntime(const LwipRuntime&) = delete;
    LwipRuntime& operator=(const LwipRuntime&) = delete;

    void start();
    void stop();
    void poll_timeouts();

    void apply_tun_config(const TunConfig& config);
    void apply_tun_config_and_output(const TunConfig& config, std::function<void(std::span<const std::byte>)> output);
    void inject_l3_packet(std::span<const std::byte> packet);
    void set_packet_output(std::function<void(std::span<const std::byte>)> output);
    [[nodiscard]] StackUse acquire_stack();

    using ResolveHandler = std::function<void(err_t, std::optional<ip_addr_t>)>;
    void async_resolve(std::string host, ResolveHandler handler);

    [[nodiscard]] tcp_pcb* tcp_new_pcb();
    [[nodiscard]] udp_pcb* udp_new_pcb();
    [[nodiscard]] netif* netif_handle() noexcept { return &netif_; }

private:
    static err_t netif_init(netif* n);
    static err_t linkoutput(netif* n, pbuf* p);
    static err_t output_ipv4(netif* n, pbuf* p, const ip4_addr_t* addr);
    static err_t output_ipv6(netif* n, pbuf* p, const ip6_addr_t* addr);
    static void dns_recv(void* arg, udp_pcb* pcb, pbuf* p, const ip_addr_t* addr, u16_t port);

    void arm_timer();
    void apply_tun_config_locked(const TunConfig& config);
    err_t emit_packet(pbuf* p);
    void complete_dns_query(std::uint16_t id, err_t err, std::optional<ip_addr_t> ip);
    [[nodiscard]] std::optional<ip_addr_t> dns_server() const;
    static std::recursive_mutex& global_mutex();

    struct DnsQuery;

    asio::io_context& io_;
    asio::steady_timer timer_;
    netif netif_{};
    TunConfig active_config_;
    std::function<void(std::span<const std::byte>)> packet_output_;
    std::unordered_map<std::uint16_t, std::shared_ptr<DnsQuery>> dns_queries_;
    std::shared_ptr<bool> lifetime_token_{std::make_shared<bool>(true)};
    bool running_{false};
};

} // namespace ovpn2ss
