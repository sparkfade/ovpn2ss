#pragma once

#include <cstddef>
#include <span>

namespace ovpn2ss {

class OpenVpnPacketSink {
public:
    virtual ~OpenVpnPacketSink() = default;
    virtual void send_l3_packet(std::span<const std::byte> packet) = 0;
};

} // namespace ovpn2ss
