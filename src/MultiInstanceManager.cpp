#include "ovpn2ss/MultiInstanceManager.h"

#include "ovpn2ss/LwipRuntime.h"
#include "ovpn2ss/OpenVpnClient.h"
#include "ovpn2ss/ShadowsocksInbound.h"

#include <json.hpp>

#include <chrono>
#include <fstream>
#include <future>
#include <set>
#include <stdexcept>

namespace ovpn2ss {
namespace {

using Json = nlohmann::json;

std::uint16_t checked_port(int value, const std::string& key) {
    if (value <= 0 || value > 65535) {
        throw std::runtime_error("invalid port for key: " + key);
    }
    return static_cast<std::uint16_t>(value);
}

std::string required_string(const Json& object, const char* key) {
    if (!object.contains(key) || !object.at(key).is_string() || object.at(key).get<std::string>().empty()) {
        throw std::runtime_error(std::string("instance requires non-empty string: ") + key);
    }
    return object.at(key).get<std::string>();
}

std::string optional_string(const Json& object, const char* key, std::string fallback) {
    if (!object.contains(key)) {
        return fallback;
    }
    if (!object.at(key).is_string()) {
        throw std::runtime_error(std::string("config key must be string: ") + key);
    }
    return object.at(key).get<std::string>();
}

} // namespace

MultiInstanceManager::MultiInstanceManager(ManagerConfig config) : config_(std::move(config)) {}

MultiInstanceManager::~MultiInstanceManager() {
    stop();
}

ManagerConfig MultiInstanceManager::load_json_config(const std::filesystem::path& path) {
    ManagerConfig config;
    config.json_path = path;
    std::ifstream in(path);
    if (!in) {
        throw std::runtime_error("cannot open config: " + path.string());
    }
    const auto json = Json::parse(in, nullptr, true, true);
    if (!json.contains("instances") || !json.at("instances").is_array()) {
        throw std::runtime_error("config requires instances array");
    }
    if (json.at("instances").empty()) {
        throw std::runtime_error("config must contain at least one instance");
    }
    std::set<std::uint16_t> tcp_ports;
    std::set<std::uint16_t> udp_ports;

    for (const auto& object : json.at("instances")) {
        if (!object.is_object()) {
            throw std::runtime_error("instances entries must be objects");
        }
        InstanceConfig instance;
        instance.name = required_string(object, "name");
        instance.ovpn_path = required_string(object, "ovpn");
        instance.shadowsocks.listen_host = optional_string(object, "listen_host", "127.0.0.1");
        if (!object.contains("tcp_port") || !object.at("tcp_port").is_number_integer()) {
            throw std::runtime_error("instance requires integer tcp_port");
        }
        instance.shadowsocks.tcp_port = checked_port(object.at("tcp_port").get<int>(), "tcp_port");
        instance.shadowsocks.udp_port = object.contains("udp_port")
            ? checked_port(object.at("udp_port").get<int>(), "udp_port")
            : instance.shadowsocks.tcp_port;
        instance.shadowsocks.method = optional_string(object, "method", "chacha20-ietf-poly1305");
        instance.shadowsocks.password = required_string(object, "password");

        if (!std::filesystem::is_regular_file(instance.ovpn_path)) {
            throw std::runtime_error("ovpn file does not exist: " + instance.ovpn_path.string());
        }
        if (instance.shadowsocks.method != "chacha20-ietf-poly1305") {
            throw std::runtime_error("only chacha20-ietf-poly1305 is supported");
        }
        if (!tcp_ports.insert(instance.shadowsocks.tcp_port).second ||
            (instance.shadowsocks.udp_port != 0 && !udp_ports.insert(instance.shadowsocks.udp_port).second)) {
            throw std::runtime_error("duplicate Shadowsocks listen port for the same protocol");
        }
        config.instances.push_back(std::move(instance));
    }
    return config;
}

void MultiInstanceManager::start() {
    if (running_.exchange(true)) {
        return;
    }
    for (const auto& cfg : config_.instances) {
        auto instance = std::make_unique<InstanceRuntime>();
        instance->config = cfg;
        instance->io = std::make_unique<asio::io_context>();
        instance->work = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(instance->io->get_executor());
        instance->lwip = std::make_unique<LwipRuntime>(*instance->io);
        instance->vpn = std::make_unique<OpenVpnClient>(*instance->io, *instance->lwip, cfg);
        instance->ss = std::make_unique<ShadowsocksInbound>(*instance->io, *instance->lwip, cfg.shadowsocks);
        start_instance(*instance);
        instances_.push_back(std::move(instance));
    }
}

void MultiInstanceManager::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    for (auto& instance : instances_) {
        if (instance->io) {
            auto* runtime = instance.get();
            auto stopped = std::make_shared<std::promise<void>>();
            auto done = stopped->get_future();
            asio::post(*instance->io, [runtime, stopped] {
                runtime->ss->stop();
                runtime->vpn->stop();
                runtime->lwip->stop();
                stopped->set_value();
            });
            instance->work.reset();
            done.wait_for(std::chrono::seconds(2));
            instance->io->stop();
        }
    }
    instances_.clear();
}

void MultiInstanceManager::start_instance(InstanceRuntime& instance) {
    auto* runtime = &instance;
    asio::post(*runtime->io, [runtime] {
        try {
            runtime->lwip->start();
            runtime->vpn->start();
            runtime->ss->start();
        } catch (...) {
            runtime->lwip->stop();
        }
    });
    instance.thread = std::jthread([io = instance.io.get()] {
        try {
            io->run();
        } catch (...) {
        }
    });
}

} // namespace ovpn2ss
