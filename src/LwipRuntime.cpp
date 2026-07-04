#include "ovpn2ss/LwipRuntime.h"

#include "ovpn2ss/PacketBuffer.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <vector>

extern "C" unsigned int ovpn2ss_lwip_rand() {
    struct RandContext {
        RandContext() {
            mbedtls_entropy_init(&entropy);
            mbedtls_ctr_drbg_init(&ctr_drbg);
            constexpr unsigned char personalization[] = "ovpn2ss-lwip-rand";
            if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                    personalization, sizeof(personalization) - 1) != 0) {
                mbedtls_ctr_drbg_free(&ctr_drbg);
                mbedtls_entropy_free(&entropy);
                initialized = false;
                return;
            }
            initialized = true;
        }

        ~RandContext() {
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
        }

        mbedtls_entropy_context entropy{};
        mbedtls_ctr_drbg_context ctr_drbg{};
        bool initialized{false};
    };

    static thread_local RandContext rng;
    unsigned int out = 0;
    if (!rng.initialized || mbedtls_ctr_drbg_random(&rng.ctr_drbg,
            reinterpret_cast<unsigned char*>(&out), sizeof(out)) != 0) {
        std::terminate();
    }
    return out;
}

namespace ovpn2ss {
namespace {

constexpr std::uint16_t DnsPort = 53;
constexpr std::uint16_t DnsTypeA = 1;
constexpr std::uint16_t DnsTypeAaaa = 28;
constexpr std::uint16_t DnsClassIn = 1;

ip_addr_t parse_ip_addr(const std::string& text, bool ipv6) {
    ip_addr_t out{};
    const auto ok = ipv6 ? ipaddr_aton(text.c_str(), &out) : ipaddr_aton(text.c_str(), &out);
    if (ok == 0) {
        throw std::runtime_error("invalid IP address: " + text);
    }
    return out;
}

ip4_addr_t prefix_to_netmask(int prefix) {
    if (prefix < 0 || prefix > 32) {
        throw std::runtime_error("invalid IPv4 prefix length");
    }
    const std::uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
    ip4_addr_t out{};
    ip4_addr_set_u32(&out, lwip_htonl(mask));
    return out;
}

void append_u16(std::vector<std::byte>& out, std::uint16_t value) {
    out.push_back(static_cast<std::byte>(value >> 8));
    out.push_back(static_cast<std::byte>(value & 0xff));
}

std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint16_t>(bytes[offset]) << 8) | static_cast<std::uint16_t>(bytes[offset + 1]);
}

std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(read_u16(bytes, offset)) << 16) | read_u16(bytes, offset + 2);
}

bool skip_dns_name(std::span<const std::byte> packet, std::size_t& offset) {
    std::size_t jumps = 0;
    while (offset < packet.size()) {
        const auto len = static_cast<unsigned char>(packet[offset]);
        if ((len & 0xc0) == 0xc0) {
            if (offset + 1 >= packet.size()) {
                return false;
            }
            offset += 2;
            return true;
        }
        if ((len & 0xc0) != 0) {
            return false;
        }
        ++offset;
        if (len == 0) {
            return true;
        }
        if (offset + len > packet.size() || ++jumps > 255) {
            return false;
        }
        offset += len;
    }
    return false;
}

std::vector<std::byte> make_dns_query(std::uint16_t id, const std::string& host, std::uint16_t qtype) {
    std::vector<std::byte> out;
    append_u16(out, id);
    append_u16(out, 0x0100); // recursion desired
    append_u16(out, 1);
    append_u16(out, 0);
    append_u16(out, 0);
    append_u16(out, 0);

    std::size_t start = 0;
    while (start < host.size()) {
        const auto dot = host.find('.', start);
        const auto end = dot == std::string::npos ? host.size() : dot;
        const auto len = end - start;
        if (len == 0 || len > 63) {
            throw std::runtime_error("invalid DNS label");
        }
        out.push_back(static_cast<std::byte>(len));
        out.insert(out.end(), reinterpret_cast<const std::byte*>(host.data() + start),
            reinterpret_cast<const std::byte*>(host.data() + end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    out.push_back(std::byte{0});
    append_u16(out, qtype);
    append_u16(out, DnsClassIn);
    return out;
}

std::optional<ip_addr_t> parse_dns_response(std::span<const std::byte> packet, std::uint16_t id, std::uint16_t qtype) {
    if (packet.size() < 12 || read_u16(packet, 0) != id) {
        return std::nullopt;
    }
    const auto flags = read_u16(packet, 2);
    if ((flags & 0x8000) == 0 || (flags & 0x000f) != 0) {
        return std::nullopt;
    }

    const auto qdcount = read_u16(packet, 4);
    const auto ancount = read_u16(packet, 6);
    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < qdcount; ++i) {
        if (!skip_dns_name(packet, offset) || offset + 4 > packet.size()) {
            return std::nullopt;
        }
        offset += 4;
    }

    for (std::uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(packet, offset) || offset + 10 > packet.size()) {
            return std::nullopt;
        }
        const auto type = read_u16(packet, offset);
        const auto klass = read_u16(packet, offset + 2);
        const auto rdlen = read_u16(packet, offset + 8);
        offset += 10;
        if (offset + rdlen > packet.size()) {
            return std::nullopt;
        }
        if (klass == DnsClassIn && type == qtype) {
            ip_addr_t ip{};
            if (type == DnsTypeA && rdlen == 4) {
                IP_ADDR4(&ip,
                    static_cast<unsigned char>(packet[offset]),
                    static_cast<unsigned char>(packet[offset + 1]),
                    static_cast<unsigned char>(packet[offset + 2]),
                    static_cast<unsigned char>(packet[offset + 3]));
                return ip;
            }
#if LWIP_IPV6
            if (type == DnsTypeAaaa && rdlen == 16) {
                IP_ADDR6(&ip,
                    read_u32(packet, offset), read_u32(packet, offset + 4),
                    read_u32(packet, offset + 8), read_u32(packet, offset + 12));
                return ip;
            }
#endif
        }
        offset += rdlen;
    }
    return std::nullopt;
}

} // namespace

struct LwipRuntime::DnsQuery {
    LwipRuntime* runtime{};
    udp_pcb* pcb{};
    std::uint16_t id{};
    std::uint16_t qtype{};
    ResolveHandler handler;
    asio::steady_timer timer;

    DnsQuery(LwipRuntime& runtime_arg, std::uint16_t id_arg, std::uint16_t qtype_arg, ResolveHandler handler_arg)
        : runtime(&runtime_arg), id(id_arg), qtype(qtype_arg), handler(std::move(handler_arg)), timer(runtime_arg.io_) {}
};

LwipRuntime::StackUse::StackUse(LwipRuntime& runtime)
    : runtime_(runtime), lock_(LwipRuntime::global_mutex()) {}

LwipRuntime::LwipRuntime(asio::io_context& io)
    : io_(io), timer_(io) {
    std::lock_guard lock(global_mutex());
    static std::once_flag init_once;
    std::call_once(init_once, [] { lwip_init(); });

    ip4_addr_t zero{};
    netif_add(&netif_, &zero, &zero, &zero, this, &LwipRuntime::netif_init, ip_input);
    netif_.output = &LwipRuntime::output_ipv4;
    netif_.output_ip6 = &LwipRuntime::output_ipv6;
    netif_.linkoutput = &LwipRuntime::linkoutput;
    netif_set_up(&netif_);
    netif_set_link_up(&netif_);
}

LwipRuntime::~LwipRuntime() {
    stop();
    std::lock_guard lock(global_mutex());
    netif_remove(&netif_);
}

void LwipRuntime::start() {
    if (running_) {
        return;
    }
    running_ = true;
    arm_timer();
}

void LwipRuntime::stop() {
    running_ = false;
    if (lifetime_token_) {
        *lifetime_token_ = false;
    }
    timer_.cancel();
    std::vector<std::shared_ptr<DnsQuery>> queries;
    {
        auto stack = acquire_stack();
        for (auto& [_, query] : dns_queries_) {
            queries.push_back(std::move(query));
        }
        dns_queries_.clear();
        for (auto& query : queries) {
            query->timer.cancel();
            if (query->pcb != nullptr) {
                udp_recv(query->pcb, nullptr, nullptr);
                udp_remove(query->pcb);
                query->pcb = nullptr;
            }
        }
    }
}

void LwipRuntime::poll_timeouts() {
    auto stack = acquire_stack();
    try {
        sys_check_timeouts();
    } catch (...) {
        stop();
        throw;
    }
}

void LwipRuntime::apply_tun_config(const TunConfig& config) {
    auto stack = acquire_stack();
    active_config_ = config;
    netif_.mtu = static_cast<u16_t>(config.mtu > 0 ? config.mtu : 1500);

    for (const auto& address : config.addresses) {
        if (address.ipv6) {
#if LWIP_IPV6
            ip_addr_t ip = parse_ip_addr(address.address, true);
            netif_ip6_addr_set(&netif_, 0, ip_2_ip6(&ip));
            netif_ip6_addr_set_state(&netif_, 0, IP6_ADDR_PREFERRED);
#endif
            continue;
        }

        ip_addr_t ip = parse_ip_addr(address.address, false);
        ip4_addr_t mask = prefix_to_netmask(address.prefix_length);
        ip4_addr_t gw{};
        if (!address.gateway.empty()) {
            ip_addr_t gateway = parse_ip_addr(address.gateway, false);
            gw = *ip_2_ip4(&gateway);
        }
        netif_set_addr(&netif_, ip_2_ip4(&ip), &mask, &gw);
    }

}

void LwipRuntime::inject_l3_packet(std::span<const std::byte> packet) {
    auto stack = acquire_stack();
    if (packet.empty()) {
        return;
    }

    pbuf* p = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(packet.size()), PBUF_POOL);
    if (p == nullptr) {
        return;
    }

    if (pbuf_take(p, packet.data(), static_cast<u16_t>(packet.size())) != ERR_OK) {
        pbuf_free(p);
        return;
    }

    const auto err = netif_.input(p, &netif_);
    if (err != ERR_OK) {
        pbuf_free(p);
    }
}

void LwipRuntime::set_packet_output(std::function<void(std::span<const std::byte>)> output) {
    auto stack = acquire_stack();
    packet_output_ = std::move(output);
}

LwipRuntime::StackUse LwipRuntime::acquire_stack() {
    return StackUse(*this);
}

tcp_pcb* LwipRuntime::tcp_new_pcb() {
    auto stack = acquire_stack();
    auto* pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (pcb != nullptr) {
        tcp_bind_netif(pcb, &netif_);
    }
    return pcb;
}

udp_pcb* LwipRuntime::udp_new_pcb() {
    auto stack = acquire_stack();
    auto* pcb = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (pcb != nullptr) {
        udp_bind_netif(pcb, &netif_);
    }
    return pcb;
}

void LwipRuntime::async_resolve(std::string host, ResolveHandler handler) {
    if (!lifetime_token_ || !*lifetime_token_) {
        lifetime_token_ = std::make_shared<bool>(true);
    }
    ip_addr_t literal{};
    if (ipaddr_aton(host.c_str(), &literal) != 0) {
        asio::post(io_, [handler = std::move(handler), literal] { handler(ERR_OK, literal); });
        return;
    }

    auto server = dns_server();
    if (!server) {
        asio::post(io_, [handler = std::move(handler)] { handler(ERR_RTE, std::nullopt); });
        return;
    }

    static std::atomic_uint next_id{1};
    const auto id = static_cast<std::uint16_t>(next_id.fetch_add(1));
    const auto qtype = IP_IS_V6(&*server) ? DnsTypeAaaa : DnsTypeA;
    std::shared_ptr<DnsQuery> query;
    err_t send_error = ERR_OK;
    {
        auto stack = acquire_stack();
        query = std::make_shared<DnsQuery>(*this, id, qtype, std::move(handler));
        query->pcb = udp_new_pcb();
        if (query->pcb == nullptr) {
            query->timer.expires_after(std::chrono::milliseconds(0));
        }
    }

    if (query->pcb == nullptr) {
        auto cb = std::move(query->handler);
        asio::post(io_, [cb = std::move(cb)] { cb(ERR_MEM, std::nullopt); });
        return;
    }

    {
        auto stack = acquire_stack();
        udp_recv(query->pcb, &LwipRuntime::dns_recv, query.get());
        dns_queries_.emplace(id, query);

        auto packet = make_dns_query(id, host, qtype);
        pbuf* p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(packet.size()), PBUF_POOL);
        if (p == nullptr) {
            send_error = ERR_MEM;
        } else {
            pbuf_take(p, packet.data(), static_cast<u16_t>(packet.size()));
            send_error = udp_sendto(query->pcb, p, &*server, DnsPort);
            pbuf_free(p);
        }
    }

    if (send_error != ERR_OK) {
        complete_dns_query(id, send_error, std::nullopt);
        return;
    }

    query->timer.expires_after(std::chrono::seconds(5));
    std::weak_ptr<bool> lifetime = lifetime_token_;
    query->timer.async_wait([this, id, lifetime](const asio::error_code& ec) {
        if (!ec) {
            auto token = lifetime.lock();
            if (token && *token) {
                complete_dns_query(id, ERR_TIMEOUT, std::nullopt);
            }
        }
    });
}

err_t LwipRuntime::netif_init(netif* n) {
    n->name[0] = 'o';
    n->name[1] = 'v';
    n->hwaddr_len = 0;
    n->mtu = 1500;
    n->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

err_t LwipRuntime::linkoutput(netif* n, pbuf* p) {
    return static_cast<LwipRuntime*>(n->state)->emit_packet(p);
}

err_t LwipRuntime::output_ipv4(netif* n, pbuf* p, const ip4_addr_t*) {
    return static_cast<LwipRuntime*>(n->state)->emit_packet(p);
}

err_t LwipRuntime::output_ipv6(netif* n, pbuf* p, const ip6_addr_t*) {
    return static_cast<LwipRuntime*>(n->state)->emit_packet(p);
}

void LwipRuntime::dns_recv(void* arg, udp_pcb*, pbuf* p, const ip_addr_t*, u16_t) {
    auto* query = static_cast<DnsQuery*>(arg);
    if (query == nullptr || p == nullptr) {
        if (p != nullptr) {
            pbuf_free(p);
        }
        return;
    }

    PacketBuffer bytes(p->tot_len);
    pbuf_copy_partial(p, bytes.data(), p->tot_len, 0);
    pbuf_free(p);
    const auto ip = parse_dns_response(bytes.span(), query->id, query->qtype);
    query->runtime->complete_dns_query(query->id, ip ? ERR_OK : ERR_VAL, ip);
}

void LwipRuntime::arm_timer() {
    timer_.expires_after(std::chrono::milliseconds(10));
    timer_.async_wait([this](const asio::error_code& ec) {
        if (ec || !running_) {
            return;
        }
        poll_timeouts();
        arm_timer();
    });
}

err_t LwipRuntime::emit_packet(pbuf* p) {
    auto stack = acquire_stack();
    if (!packet_output_) {
        return ERR_RTE;
    }

    std::vector<std::byte> bytes(p->tot_len);
    if (pbuf_copy_partial(p, bytes.data(), p->tot_len, 0) != p->tot_len) {
        return ERR_BUF;
    }

    packet_output_(std::span<const std::byte>(bytes.data(), bytes.size()));
    return ERR_OK;
}

void LwipRuntime::complete_dns_query(std::uint16_t id, err_t err, std::optional<ip_addr_t> ip) {
    std::shared_ptr<DnsQuery> query;
    {
        auto stack = acquire_stack();
        auto it = dns_queries_.find(id);
        if (it == dns_queries_.end()) {
            return;
        }
        query = std::move(it->second);
        dns_queries_.erase(it);
        query->timer.cancel();
        if (query->pcb != nullptr) {
            udp_recv(query->pcb, nullptr, nullptr);
            udp_remove(query->pcb);
            query->pcb = nullptr;
        }
    }
    asio::post(io_, [query, err, ip] {
        query->handler(err, ip);
    });
}

std::optional<ip_addr_t> LwipRuntime::dns_server() const {
    if (!active_config_.ipv4_dns.empty()) {
        return parse_ip_addr(active_config_.ipv4_dns.front(), false);
    }
    if (!active_config_.ipv6_dns.empty()) {
        return parse_ip_addr(active_config_.ipv6_dns.front(), true);
    }
    return std::nullopt;
}

std::recursive_mutex& LwipRuntime::global_mutex() {
    static std::recursive_mutex mutex;
    return mutex;
}

} // namespace ovpn2ss
