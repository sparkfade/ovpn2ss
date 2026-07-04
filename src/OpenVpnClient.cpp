#include "ovpn2ss/OpenVpnClient.h"

#include <fstream>
#include <iostream>
#include <chrono>
#include <cstring>
#include <iterator>
#include <mutex>
#include <stdexcept>
#include <string>

#ifdef OVPN2SS_REAL_OPENVPN3
#include <sstream>
#include <regex>
#include <set>
#ifndef OPENVPN_LOG
#define OPENVPN_LOG(args) do { std::ostringstream ovpn2ss_openvpn_log; ovpn2ss_openvpn_log << args; std::clog << "openvpn3: " << ovpn2ss_openvpn_log.str() << '\n'; } while (false)
#define OPENVPN_LOG_NTNL(args) do { std::ostringstream ovpn2ss_openvpn_log; ovpn2ss_openvpn_log << args; std::clog << "openvpn3: " << ovpn2ss_openvpn_log.str(); } while (false)
#define OPENVPN_LOG_STRING(str) do { std::clog << "openvpn3: " << str; } while (false)
#endif
#include <client/ovpncli.hpp>
#include <openvpn/buffer/buffer.hpp>
#include <openvpn/tun/client/tunbase.hpp>
#include <openvpn/tun/client/tunprop.hpp>
#include <openvpn/tun/extern/config.hpp>
#endif

namespace ovpn2ss {

#ifdef OVPN2SS_REAL_OPENVPN3
namespace {

openvpn::BufferAllocated make_openvpn_buffer(std::span<const std::byte> packet) {
    constexpr std::size_t HEADROOM = 512;
    openvpn::BufferAllocated buf(packet.size() + HEADROOM, openvpn::BufAllocFlags::GROW);
    buf.reset_offset(HEADROOM);
    std::memcpy(buf.write_alloc(packet.size()), packet.data(), packet.size());
    return buf;
}

static const std::set<std::string> AEAD_CIPHERS = {
    "AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"
};

static bool scan_ovpn_for_non_aead_cipher(const std::string& content) {
    std::regex re(R"(^\s*(?:data-)?cipher\s+(\S+))", std::regex::icase | std::regex::multiline);
    std::sregex_iterator it(content.begin(), content.end(), re), end;
    for (; it != end; ++it) {
        std::string cipher = (*it)[1];
        cipher.erase(std::remove(cipher.begin(), cipher.end(), '\r'), cipher.end());
        if (cipher != "none" && AEAD_CIPHERS.find(cipher) == AEAD_CIPHERS.end()) {
            OPENVPN_LOG("detected non-AEAD data cipher '" << cipher << "', enabling non-preferred DC algorithms");
            return true;
        }
    }
    return false;
}

} // namespace

struct OpenVpnClient::Impl {
    struct CoreClient;

    explicit Impl(OpenVpnClient& owner_arg) : core(owner_arg) {}

    struct MemoryTunClient final : openvpn::TunClient {
        using Ptr = openvpn::RCPtr<MemoryTunClient>;

        MemoryTunClient(OpenVpnClient& owner_arg, openvpn_io::io_context& openvpn_io_arg,
            openvpn::TunClientParent& parent_arg, const openvpn::ExternalTun::Config& conf_arg)
            : owner(owner_arg), openvpn_io(openvpn_io_arg), parent(parent_arg), conf(conf_arg) {}

        void tun_start(const openvpn::OptionList& opt, openvpn::TransportClient& transcli,
            openvpn::CryptoDCSettings&) override {
            if (!owner.tun_builder_.tun_builder_new()) {
                parent.tun_error(openvpn::Error::TUN_SETUP_FAILED, "memory tun builder reset failed");
                return;
            }

            state = new openvpn::TunProp::State;
            try {
                openvpn::TunProp::configure_builder(&owner.tun_builder_, state.get(), conf.stats.get(),
                    transcli.server_endpoint_addr(), conf.tun_prop, opt, nullptr, true);
                if (owner.tun_builder_.tun_builder_establish() != 0) {
                    parent.tun_error(openvpn::Error::TUN_IFACE_CREATE, "memory tun establish failed");
                    return;
                }
                connected = true;
                parent.tun_connected();
            } catch (const std::exception& e) {
                parent.tun_error(openvpn::Error::TUN_SETUP_FAILED, e.what());
            }
        }

        void stop() override {
            connected = false;
            owner.tun_builder_.tun_builder_teardown(true);
        }

        void set_disconnect() override {
            connected = false;
        }

        bool tun_send(openvpn::BufferAllocated& buf) override {
            if (buf.empty()) {
                return true;
            }
            owner.tun_builder_.inject_from_openvpn(std::span<const std::byte>(
                reinterpret_cast<const std::byte*>(buf.c_data()), buf.size()));
            return true;
        }

        std::string tun_name() const override { return "ovpn2ss-memory-tun"; }
        std::string vpn_ip4() const override { return state && state->vpn_ip4_addr.specified() ? state->vpn_ip4_addr.to_string() : std::string(); }
        std::string vpn_ip6() const override { return state && state->vpn_ip6_addr.specified() ? state->vpn_ip6_addr.to_string() : std::string(); }
        std::string vpn_gw4() const override { return state && state->vpn_ip4_gw.specified() ? state->vpn_ip4_gw.to_string() : std::string(); }
        std::string vpn_gw6() const override { return state && state->vpn_ip6_gw.specified() ? state->vpn_ip6_gw.to_string() : std::string(); }
        int vpn_mtu() const override { return state ? state->mtu : conf.tun_prop.mtu; }
        bool supports_epoch_data() { return true; }

        void inject_l3_packet(std::span<const std::byte> packet) {
            if (!connected || packet.empty()) {
                return;
            }
            auto buf = std::make_shared<openvpn::BufferAllocated>(make_openvpn_buffer(packet));
            MemoryTunClient::Ptr self = this;
            openvpn_io::post(openvpn_io, [self, buf] {
                if (self->connected) {
                    self->parent.tun_recv(*buf);
                }
            });
        }

        OpenVpnClient& owner;
        openvpn_io::io_context& openvpn_io;
        openvpn::TunClientParent& parent;
        openvpn::ExternalTun::Config conf;
        openvpn::TunProp::State::Ptr state;
        bool connected{false};
    };

    struct MemoryTunFactory final : openvpn::TunClientFactory {
        MemoryTunFactory(OpenVpnClient& owner_arg, CoreClient& core_arg, const openvpn::ExternalTun::Config& conf_arg)
            : owner(owner_arg), core(core_arg), conf(conf_arg) {}

        openvpn::TunClient::Ptr new_tun_client_obj(openvpn_io::io_context& openvpn_io,
            openvpn::TunClientParent& parent, openvpn::TransportClient*) override;

        bool supports_epoch_data() override { return true; }

        OpenVpnClient& owner;
        CoreClient& core;
        openvpn::ExternalTun::Config conf;
    };

    struct CoreClient final : openvpn::ClientAPI::OpenVPNClient {
        explicit CoreClient(OpenVpnClient& owner_arg) : owner(owner_arg) {}

        openvpn::TunClientFactory* new_tun_factory(const openvpn::ExternalTun::Config& conf,
            const openvpn::OptionList&) override {
            return new MemoryTunFactory(owner, *this, conf);
        }

        bool pause_on_connection_timeout() override { return false; }
        bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) override { return true; }
        void event(const openvpn::ClientAPI::Event& ev) override {
            if (ev.name == "DISCONNECTED") {
                std::lock_guard lock(mutex);
                memory_tun = nullptr;
            }
        }
        void acc_event(const openvpn::ClientAPI::AppCustomControlMessageEvent&) override {}
        void log(const openvpn::ClientAPI::LogInfo& info) override {
            if (!info.text.empty()) {
                std::clog << "openvpn3: " << info.text << '\n';
                if (!owner.needs_downgrade_.load() &&
                    (info.text.find("bad cipher for data channel") != std::string::npos ||
                     info.text.find("server-pushed cipher") != std::string::npos ||
                     info.text.find("Problem accepting server-pushed cipher") != std::string::npos)) {
                    owner.needs_downgrade_ = true;
                    std::clog << "openvpn3: cipher negotiation failed, will retry with non-preferred DC algorithms\n";
                    stop();
                }
            }
        }
        void external_pki_cert_request(openvpn::ClientAPI::ExternalPKICertRequest& req) override {
            req.error = true;
            req.errorText = "external PKI is not configured";
        }
        void external_pki_sign_request(openvpn::ClientAPI::ExternalPKISignRequest& req) override {
            req.error = true;
            req.errorText = "external PKI is not configured";
        }

        bool tun_builder_new() override { return owner.tun_builder_.tun_builder_new(); }
        int tun_builder_establish() override { return owner.tun_builder_.tun_builder_establish(); }
        bool tun_builder_add_address(const std::string& address, int prefix_length, const std::string& gateway, bool ipv6, bool net30) override {
            return owner.tun_builder_.tun_builder_add_address(address, prefix_length, gateway, ipv6, net30);
        }
        bool tun_builder_set_mtu(int mtu) override { return owner.tun_builder_.tun_builder_set_mtu(mtu); }
        bool tun_builder_set_dns_options(const openvpn::DnsOptions& dns) override { return owner.tun_builder_.tun_builder_set_dns_options(dns); }
        bool tun_builder_add_route(const std::string& address, int prefix_length, int metric, bool ipv6) override {
            return owner.tun_builder_.tun_builder_add_route(address, prefix_length, metric, ipv6);
        }
        bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int flags) override {
            return owner.tun_builder_.tun_builder_reroute_gw(ipv4, ipv6, flags);
        }
        bool tun_builder_exclude_route(const std::string& address, int prefix_length, int metric, bool ipv6) override {
            return owner.tun_builder_.tun_builder_exclude_route(address, prefix_length, metric, ipv6);
        }
        bool tun_builder_set_remote_address(const std::string& address, bool ipv6) override {
            return owner.tun_builder_.tun_builder_set_remote_address(address, ipv6);
        }
        void tun_builder_teardown(bool disconnect) override { owner.tun_builder_.tun_builder_teardown(disconnect); }

        void set_memory_tun(const MemoryTunClient::Ptr& tun) {
            std::lock_guard lock(mutex);
            memory_tun = tun;
        }

        void inject_l3_packet(std::span<const std::byte> packet) {
            MemoryTunClient::Ptr tun;
            {
                std::lock_guard lock(mutex);
                tun = memory_tun;
            }
            if (tun) {
                tun->inject_l3_packet(packet);
            }
        }

        OpenVpnClient& owner;
        std::mutex mutex;
        MemoryTunClient::Ptr memory_tun;
    };

    CoreClient core;
};

openvpn::TunClient::Ptr OpenVpnClient::Impl::MemoryTunFactory::new_tun_client_obj(
    openvpn_io::io_context& openvpn_io, openvpn::TunClientParent& parent, openvpn::TransportClient*) {
    MemoryTunClient::Ptr tun = new MemoryTunClient(owner, openvpn_io, parent, conf);
    core.set_memory_tun(tun);
    return tun;
}

#else
struct OpenVpnClient::Impl {
    explicit Impl(OpenVpnClient&) {}
};
#endif

OpenVpnClient::OpenVpnClient(asio::io_context& io, LwipRuntime& lwip, InstanceConfig config)
    : io_(io), lwip_(lwip), config_(std::move(config)), tun_builder_(lwip_, *this), impl_(std::make_unique<Impl>(*this)) {}

OpenVpnClient::~OpenVpnClient() {
    stop();
}

void OpenVpnClient::start() {
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;
    }
    std::ifstream ovpn(config_.ovpn_path);
    if (!ovpn) {
        running_ = false;
        throw std::runtime_error("cannot open ovpn config: " + config_.ovpn_path.string());
    }
#ifdef OVPN2SS_REAL_OPENVPN3
    const std::string content{std::istreambuf_iterator<char>(ovpn), std::istreambuf_iterator<char>()};

    bool non_preferred = scan_ovpn_for_non_aead_cipher(content) || needs_downgrade_.exchange(false);

    auto make_config = [content](bool enable_np) {
        openvpn::ClientAPI::Config c;
        c.content = content;
        c.guiVersion = "ovpn2ss 0";
        c.clockTickMS = 1000;
        c.enableLegacyAlgorithms = true;
        c.dco = false;
        c.enableNonPreferredDCAlgorithms = enable_np;
        return c;
    };

    auto config = make_config(non_preferred);
    auto eval = impl_->core.eval_config(config);
    if (eval.error) {
        running_ = false;
        throw std::runtime_error("openvpn config eval failed: " + eval.message);
    }

    vpn_thread_ = std::jthread([this, non_preferred, make_config](std::stop_token stop_token) {
        bool using_non_preferred = non_preferred;

        while (running_ && !stop_token.stop_requested()) {
            try {
                const auto status = impl_->core.connect();

                if (needs_downgrade_.exchange(false) && !using_non_preferred && running_) {
                    using_non_preferred = true;
                    impl_->core.stop();
                    impl_.reset(new Impl(*this));
                    auto new_config = make_config(true);
                    auto new_eval = impl_->core.eval_config(new_config);
                    if (new_eval.error) {
                        std::clog << "openvpn3: downgrade eval_config failed: " << new_eval.message << '\n';
                        running_ = false;
                        return;
                    }
                    std::clog << "openvpn3: reconnecting with non-preferred DC algorithms enabled...\n";
                    continue;
                }

                if (status.error && running_ && !stop_token.stop_requested()) {
                    std::clog << "openvpn3: connect exited: " << status.message << '\n';
                }
            } catch (const std::exception& e) {
                if (running_ && !stop_token.stop_requested()) {
                    std::clog << "openvpn3: unhandled exception: " << e.what() << '\n';
                }
            }

            if (running_ && !stop_token.stop_requested()) {
                for (int i = 0; i < 10 && running_ && !stop_token.stop_requested(); ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
        }
        running_ = false;
    });
#else
    (void)ovpn;
#endif
}

void OpenVpnClient::stop() {
    const bool was_running = running_.exchange(false);
#ifdef OVPN2SS_REAL_OPENVPN3
    if (was_running) {
        vpn_thread_.request_stop();
        impl_->core.stop();
    }
#endif
}

void OpenVpnClient::send_l3_packet(std::span<const std::byte> packet) {
    if (!running_.load() || packet.empty()) {
        return;
    }

#ifdef OVPN2SS_REAL_OPENVPN3
    impl_->core.inject_l3_packet(packet);
#endif
}

} // namespace ovpn2ss
