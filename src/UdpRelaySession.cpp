#include "ovpn2ss/UdpRelaySession.h"

#include <chrono>
#include <sstream>

namespace ovpn2ss {
namespace {

constexpr auto UdpMappingIdle = std::chrono::minutes(2);

std::string mapping_key(const asio::ip::udp::endpoint& client, const TargetAddress& target) {
    std::ostringstream os;
    os << client.address().to_string() << ':' << client.port() << '|' << target.host << ':' << target.port;
    return os.str();
}

ip_addr_t parse_ip(const std::string& host) {
    ip_addr_t ip{};
    if (ipaddr_aton(host.c_str(), &ip) == 0) {
        throw std::runtime_error("invalid UDP target IP: " + host);
    }
    return ip;
}

} // namespace

UdpRelaySession::UdpRelaySession(asio::io_context& io, const std::string& listen_host, std::uint16_t listen_port,
    LwipRuntime& lwip, const ShadowsocksAeadFactory& crypto)
    : socket_(io, asio::ip::udp::endpoint(asio::ip::make_address(listen_host), listen_port)), lwip_(lwip), crypto_(crypto) {}

UdpRelaySession::~UdpRelaySession() {
    stop();
}

void UdpRelaySession::start() {
    if (!lifetime_token_) {
        lifetime_token_ = std::make_shared<bool>(true);
    }
    running_ = true;
    receive_loop();
}

void UdpRelaySession::stop() {
    running_ = false;
    if (lifetime_token_) {
        *lifetime_token_ = false;
        lifetime_token_.reset();
    }
    asio::error_code ignored;
    socket_.close(ignored);
    for (auto& [_, mapping] : mappings_) {
        if (mapping->pcb != nullptr) {
            auto stack = lwip_.acquire_stack();
            udp_remove(mapping->pcb);
            mapping->pcb = nullptr;
        }
    }
    mappings_.clear();
}

void UdpRelaySession::receive_loop() {
    if (!running_) {
        return;
    }
    auto self = shared_from_this();
    socket_.async_receive_from(asio::buffer(recv_buf_), recv_endpoint_, [self](const asio::error_code& ec, std::size_t n) {
        if (!ec) {
            self->send_to_lwip(std::span<const std::byte>(self->recv_buf_.data(), n), self->recv_endpoint_);
        }
        self->receive_loop();
    });
}

void UdpRelaySession::send_to_lwip(std::span<const std::byte> datagram, const asio::ip::udp::endpoint& client) {
    try {
        auto session = crypto_.make_session();
        auto plain = session.decrypt_udp_packet(datagram);
        if (!plain) {
            return;
        }
        auto bytes = std::span<const std::byte>(plain->data(), plain->size());
        auto target = parse_ss_address(bytes);
        if (!target) {
            return;
        }
        if (target->type == AddressType::Domain) {
            resolve_domain_then_send(bytes, client, *target);
            return;
        }
        send_payload_to_ip(bytes, client, *target, parse_ip(target->host));
    } catch (...) {
    }
}

void UdpRelaySession::send_payload_to_ip(std::span<const std::byte> payload, const asio::ip::udp::endpoint& client,
    const TargetAddress& target, const ip_addr_t& ip) {
    try {
        Mapping* mapping = mapping_for(client, target);
        arm_idle_timer(*mapping);
        auto stack = lwip_.acquire_stack();
        pbuf* p = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_POOL);
        if (p == nullptr) {
            return;
        }
        pbuf_take(p, payload.data(), static_cast<u16_t>(payload.size()));
        udp_sendto(mapping->pcb, p, &ip, target.port);
        pbuf_free(p);
    } catch (...) {
    }
}

void UdpRelaySession::resolve_domain_then_send(std::span<const std::byte> payload, const asio::ip::udp::endpoint& client,
    const TargetAddress& target) {
    auto weak = weak_from_this();
    auto token = lifetime_token_;
    auto owned_payload = std::make_shared<PacketBuffer>(Bytes(payload.begin(), payload.end()));
    lwip_.async_resolve(target.host, [weak, token, owned_payload, client, target](err_t err, std::optional<ip_addr_t> ip) {
        auto self = weak.lock();
        if (!self || !token || !*token || !self->running_ || err != ERR_OK || !ip) {
            return;
        }
        self->send_payload_to_ip(owned_payload->span(), client, target, *ip);
    });
}

void UdpRelaySession::send_to_client(Mapping& mapping, std::span<const std::byte> payload, const ip_addr_t* addr, u16_t port) {
    TargetAddress target = mapping.target;
    target.port = port;
    if (mapping.target.type != AddressType::Domain) {
        target.host = ipaddr_ntoa(addr);
        target.type = IP_IS_V6(addr) ? AddressType::Ipv6 : AddressType::Ipv4;
    }
    auto plain = encode_ss_address(target);
    plain.append(payload);
    auto session = crypto_.make_session();
    auto encrypted = std::make_shared<PacketBuffer>(session.encrypt_udp_packet(plain.span()));
    socket_.async_send_to(asio::buffer(encrypted->data(), encrypted->size()), mapping.client,
        [encrypted](const asio::error_code&, std::size_t) {});
}

UdpRelaySession::Mapping* UdpRelaySession::mapping_for(const asio::ip::udp::endpoint& client, const TargetAddress& target) {
    const auto key = mapping_key(client, target);
    if (auto it = mappings_.find(key); it != mappings_.end()) {
        return it->second.get();
    }
    auto mapping = std::make_unique<Mapping>();
    mapping->owner = this;
    mapping->client = client;
    mapping->target = target;
    mapping->key = key;
    mapping->idle_timer = std::make_unique<asio::steady_timer>(socket_.get_executor());
    auto stack = lwip_.acquire_stack();
    mapping->pcb = lwip_.udp_new_pcb();
    if (mapping->pcb == nullptr) {
        throw std::runtime_error("udp_new failed");
    }
    udp_recv(mapping->pcb, &UdpRelaySession::on_udp_recv, mapping.get());
    auto* raw = mapping.get();
    mappings_.emplace(key, std::move(mapping));
    return raw;
}

void UdpRelaySession::arm_idle_timer(Mapping& mapping) {
    mapping.idle_timer->expires_after(UdpMappingIdle);
    auto weak = weak_from_this();
    mapping.idle_timer->async_wait([weak, key = mapping.key](const asio::error_code& ec) {
        if (!ec) {
            if (auto self = weak.lock()) {
                self->erase_mapping(key);
            }
        }
    });
}

void UdpRelaySession::erase_mapping(const std::string& key) {
    auto it = mappings_.find(key);
    if (it == mappings_.end()) {
        return;
    }
    if (it->second->pcb != nullptr) {
        auto stack = lwip_.acquire_stack();
        udp_remove(it->second->pcb);
        it->second->pcb = nullptr;
    }
    mappings_.erase(it);
}

void UdpRelaySession::on_udp_recv(void* arg, udp_pcb*, pbuf* p, const ip_addr_t* addr, u16_t port) {
    auto* mapping = static_cast<Mapping*>(arg);
    if (mapping == nullptr || p == nullptr) {
        if (p != nullptr) {
            pbuf_free(p);
        }
        return;
    }
    auto stack = mapping->owner->lwip_.acquire_stack();
    PacketBuffer payload(p->tot_len);
    pbuf_copy_partial(p, payload.data(), p->tot_len, 0);
    mapping->owner->send_to_client(*mapping, payload.span(), addr, port);
    pbuf_free(p);
}

} // namespace ovpn2ss
