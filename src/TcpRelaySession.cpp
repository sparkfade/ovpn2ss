#include "ovpn2ss/TcpRelaySession.h"

#include <cstring>
#include <iostream>
#include <stdexcept>

namespace ovpn2ss {
namespace {

constexpr std::size_t ClientQueueHighWater = 1 << 20;
constexpr std::size_t ClientQueueLowWater = 256 << 10;
constexpr u16_t LwipSndLowWater = 8 * TCP_MSS;
constexpr u16_t LwipSndQueueHighWater = TCP_SND_QUEUELEN * 3 / 4;

ip_addr_t parse_lwip_ip(const std::string& host) {
    ip_addr_t ip{};
    if (ipaddr_aton(host.c_str(), &ip) == 0) {
        throw std::runtime_error("invalid target IP: " + host);
    }
    return ip;
}

void free_pbuf(pbuf* p) {
    if (p != nullptr) {
        pbuf_free(p);
    }
}

} // namespace

TcpRelaySession::TcpRelaySession(asio::ip::tcp::socket socket, LwipRuntime& lwip, const ShadowsocksAeadFactory& crypto)
    : socket_(std::move(socket)), lwip_(lwip), crypto_(crypto.make_session()) {}

TcpRelaySession::~TcpRelaySession() {
    if (pcb_ != nullptr) {
        auto stack = lwip_.acquire_stack();
        detach_pcb_callbacks();
        tcp_abort(pcb_);
        pcb_ = nullptr;
    }
}

void TcpRelaySession::start() {
    read_salt();
}

void TcpRelaySession::read_salt() {
    auto self = shared_from_this();
    asio::async_read(socket_, asio::buffer(read_buf_.data(), ShadowsocksAeadSession::SaltSize),
        [this, self](const asio::error_code& ec, std::size_t) {
            if (ec) {
                close();
                return;
            }
            try {
                crypto_.set_client_salt(std::span<const std::byte>(read_buf_.data(), ShadowsocksAeadSession::SaltSize));
                read_encrypted_stream();
            } catch (...) {
                close();
            }
        });
}

void TcpRelaySession::read_encrypted_stream() {
    if (closing_ || client_read_paused_) {
        return;
    }
    auto self = shared_from_this();
    socket_.async_read_some(asio::buffer(read_buf_), [this, self](const asio::error_code& ec, std::size_t n) {
        if (ec) {
            if (ec == asio::error::eof || ec == asio::error::connection_reset) {
                handle_client_eof();
                return;
            }
            close();
            return;
        }
        encrypted_in_.append(std::span<const std::byte>(read_buf_.data(), n));
        try {
            auto stream = encrypted_in_.span();
            std::span<const std::byte> view(stream.data(), stream.size());
            std::size_t consumed = 0;
            while (auto chunk = crypto_.decrypt_tcp_chunk(view)) {
                consumed = encrypted_in_.size() - view.size();
                process_decrypted_chunk(std::move(*chunk));
            }
            if (consumed != 0) {
                Bytes rest(view.begin(), view.end());
                encrypted_in_ = PacketBuffer(std::move(rest));
            }
            flush_to_lwip();
            read_encrypted_stream();
        } catch (...) {
            close();
        }
    });
}

void TcpRelaySession::process_decrypted_chunk(PacketBuffer chunk) {
    auto bytes = std::span<const std::byte>(chunk.data(), chunk.size());
    if (!got_target_) {
        auto target = parse_ss_address(bytes);
        if (!target) {
            close();
            return;
        }
        got_target_ = true;
        std::clog << "ovpn2ss: tcp target " << target->host << ':' << target->port << '\n';
        connect_target(*target);
    }
    if (!bytes.empty()) {
        pending_lwip_.emplace_back(Bytes(bytes.begin(), bytes.end()));
    }
}

void TcpRelaySession::connect_target(const TargetAddress& target) {
    if (target.type == AddressType::Domain) {
        resolve_domain_then_connect(target);
        return;
    }

    connect_ip(parse_lwip_ip(target.host), target.port);
}

void TcpRelaySession::connect_ip(const ip_addr_t& ip, std::uint16_t port) {
    auto stack = lwip_.acquire_stack();
    pcb_ = lwip_.tcp_new_pcb();
    if (pcb_ == nullptr) {
        close();
        return;
    }
    tcp_arg(pcb_, this);
    tcp_recv(pcb_, &TcpRelaySession::on_recv);
    tcp_sent(pcb_, &TcpRelaySession::on_sent);
    tcp_err(pcb_, &TcpRelaySession::on_err);
    active_self_ = shared_from_this();
    if (tcp_connect(pcb_, &ip, port, &TcpRelaySession::on_connected) != ERR_OK) {
        std::clog << "ovpn2ss: lwip tcp_connect failed\n";
        close();
    }
}

void TcpRelaySession::resolve_domain_then_connect(const TargetAddress& target) {
    auto weak = weak_from_this();
    lwip_.async_resolve(target.host, [weak, port = target.port](err_t err, std::optional<ip_addr_t> ip) {
        if (auto session = weak.lock()) {
            if (err != ERR_OK || !ip || session->closing_) {
                session->close();
                return;
            }
            session->connect_ip(*ip, port);
        }
    });
}

void TcpRelaySession::flush_to_lwip() {
    if (pcb_ == nullptr) {
        return;
    }
    auto stack = lwip_.acquire_stack();
    while (!pending_lwip_.empty()) {
        auto& pkt = pending_lwip_.front();
        if (tcp_sndbuf(pcb_) < pkt.size() || tcp_sndbuf(pcb_) < LwipSndLowWater ||
            tcp_sndqueuelen(pcb_) >= LwipSndQueueHighWater) {
            client_read_paused_ = true;
            return;
        }
        const auto err = tcp_write(pcb_, pkt.data(), static_cast<u16_t>(pkt.size()), TCP_WRITE_FLAG_COPY);
        if (err == ERR_MEM) {
            client_read_paused_ = true;
            return;
        }
        if (err != ERR_OK) {
            close();
            return;
        }
        pending_lwip_.pop_front();
    }
    tcp_output(pcb_);
}

void TcpRelaySession::enqueue_client_payload(std::span<const std::byte> bytes) {
    if (bytes.empty()) {
        return;
    }
    if (!sent_response_salt_) {
        auto salt = crypto_.client_salt();
        client_queue_bytes_ += salt.size();
        pending_client_.push_back(std::move(salt));
        sent_response_salt_ = true;
    }
    auto encrypted = crypto_.encrypt_tcp_chunk(bytes);
    client_queue_bytes_ += encrypted.size();
    pending_client_.push_back(std::move(encrypted));
    flush_to_client();
}

void TcpRelaySession::flush_to_client() {
    if (writing_client_ || pending_client_.empty()) {
        return;
    }
    writing_client_ = true;
    auto self = shared_from_this();
    auto& front = pending_client_.front();
    asio::async_write(socket_, asio::buffer(front.data(), front.size()),
        [this, self](const asio::error_code& ec, std::size_t n) {
            writing_client_ = false;
            if (ec) {
                close();
                return;
            }
            client_queue_bytes_ -= n;
            pending_client_.pop_front();
            if (pcb_ != nullptr && client_queue_bytes_ < ClientQueueLowWater && deferred_tcp_recved_ != 0) {
                auto stack = lwip_.acquire_stack();
                while (deferred_tcp_recved_ != 0) {
                    const auto nrecved = static_cast<u16_t>(std::min<std::size_t>(deferred_tcp_recved_, 0xffff));
                    tcp_recved(pcb_, nrecved);
                    deferred_tcp_recved_ -= nrecved;
                }
            }
            flush_to_client();
        });
}

void TcpRelaySession::maybe_resume_client_read() {
    auto stack = lwip_.acquire_stack();
    if (!client_read_paused_ || pcb_ == nullptr || tcp_sndbuf(pcb_) < LwipSndLowWater) {
        return;
    }
    client_read_paused_ = false;
    flush_to_lwip();
    read_encrypted_stream();
}

void TcpRelaySession::handle_client_eof() {
    client_eof_ = true;
    {
        auto stack = lwip_.acquire_stack();
        if (pcb_ != nullptr) {
            switch (pcb_->state) {
            case SYN_RCVD:
            case ESTABLISHED:
            case CLOSE_WAIT:
                if (tcp_shutdown(pcb_, 0, 1) != ERR_OK) {
                    detach_pcb_callbacks();
                    tcp_abort(pcb_);
                    pcb_ = nullptr;
                    release_active_self();
                }
                break;
            default:
                detach_pcb_callbacks();
                tcp_abort(pcb_);
                pcb_ = nullptr;
                release_active_self();
                break;
            }
        }
    }
    if (remote_eof_ || pcb_ == nullptr) {
        close();
    }
}

void TcpRelaySession::handle_remote_fin() {
    remote_eof_ = true;
    asio::error_code ignored;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_send, ignored);
    if (pcb_ != nullptr) {
        auto stack = lwip_.acquire_stack();
        detach_pcb_callbacks();
        if (tcp_close(pcb_) != ERR_OK) {
            tcp_abort(pcb_);
        }
        pcb_ = nullptr;
        release_active_self();
    }
    if (client_eof_) {
        close();
    }
}

void TcpRelaySession::detach_pcb_callbacks() {
    if (pcb_ == nullptr) {
        return;
    }
    tcp_arg(pcb_, nullptr);
    tcp_recv(pcb_, nullptr);
    tcp_sent(pcb_, nullptr);
    tcp_err(pcb_, nullptr);
}

void TcpRelaySession::release_active_self() {
    auto keep_until_return = std::move(active_self_);
}

void TcpRelaySession::close_client_only() {
    if (!closing_) {
        closing_ = true;
        asio::error_code ignored;
        socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
    }
    release_active_self();
}

void TcpRelaySession::close() {
    if (closing_) {
        return;
    }
    closing_ = true;
    asio::error_code ignored;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    if (pcb_ != nullptr) {
        auto stack = lwip_.acquire_stack();
        detach_pcb_callbacks();
        if (tcp_close(pcb_) != ERR_OK) {
            tcp_abort(pcb_);
        }
        pcb_ = nullptr;
    }
    release_active_self();
}

err_t TcpRelaySession::on_connected(void* arg, tcp_pcb*, err_t err) {
    auto* self = static_cast<TcpRelaySession*>(arg);
    auto stack = self->lwip_.acquire_stack();
    if (err != ERR_OK) {
        std::clog << "ovpn2ss: lwip tcp connected callback error=" << static_cast<int>(err) << '\n';
        self->close();
        return err;
    }
    std::clog << "ovpn2ss: lwip tcp connected\n";
    self->flush_to_lwip();
    return ERR_OK;
}

err_t TcpRelaySession::on_recv(void* arg, tcp_pcb* pcb, pbuf* p, err_t err) {
    auto* self = static_cast<TcpRelaySession*>(arg);
    auto stack = self->lwip_.acquire_stack();
    if (err != ERR_OK) {
        free_pbuf(p);
        self->close();
        return ERR_OK;
    }
    if (p == nullptr) {
        self->handle_remote_fin();
        return ERR_OK;
    }

    PacketBuffer bytes(p->tot_len);
    pbuf_copy_partial(p, bytes.data(), p->tot_len, 0);
    const auto received = p->tot_len;
    pbuf_free(p);

    try {
        self->enqueue_client_payload(bytes.span());
    } catch (...) {
        self->close();
        return ERR_OK;
    }

    if (self->client_queue_bytes_ > ClientQueueHighWater) {
        self->deferred_tcp_recved_ += received;
    } else {
        tcp_recved(pcb, received);
    }
    return ERR_OK;
}

err_t TcpRelaySession::on_sent(void* arg, tcp_pcb*, u16_t) {
    auto* self = static_cast<TcpRelaySession*>(arg);
    auto stack = self->lwip_.acquire_stack();
    self->maybe_resume_client_read();
    return ERR_OK;
}

void TcpRelaySession::on_err(void* arg, err_t) {
    if (arg != nullptr) {
        auto* self = static_cast<TcpRelaySession*>(arg);
        self->pcb_ = nullptr;
        self->close_client_only();
    }
}

} // namespace ovpn2ss
