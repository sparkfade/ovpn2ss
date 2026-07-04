#pragma once

#include "ovpn2ss/InstanceConfig.h"

#include <asio.hpp>

#include <atomic>
#include <memory>
#include <thread>
#include <vector>

namespace ovpn2ss {

class LwipRuntime;
class OpenVpnClient;
class ShadowsocksInbound;

class MultiInstanceManager final {
public:
    explicit MultiInstanceManager(ManagerConfig config);
    ~MultiInstanceManager();

    static ManagerConfig load_json_config(const std::filesystem::path& path);

    void start();
    void stop();

private:
    struct InstanceRuntime {
        InstanceConfig config;
        std::unique_ptr<asio::io_context> io;
        std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;
        std::unique_ptr<LwipRuntime> lwip;
        std::unique_ptr<OpenVpnClient> vpn;
        std::unique_ptr<ShadowsocksInbound> ss;
        std::jthread thread;
    };

    void start_instance(InstanceRuntime& instance);

    ManagerConfig config_;
    std::vector<std::unique_ptr<InstanceRuntime>> instances_;
    std::atomic_bool running_{false};
};

} // namespace ovpn2ss
