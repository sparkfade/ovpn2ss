#include "ovpn2ss/MultiInstanceManager.h"

#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

namespace {
volatile std::sig_atomic_t stopped = 0;
void on_signal(int) { stopped = 1; }
}

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: ovpn2ss_app /path/to/config.json\n";
        return 2;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    try {
        auto config = ovpn2ss::MultiInstanceManager::load_json_config(argv[1]);
        ovpn2ss::MultiInstanceManager manager(std::move(config));
        manager.start();
        while (!stopped) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        manager.stop();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
