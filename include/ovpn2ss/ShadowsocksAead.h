#pragma once

#include "ovpn2ss/InstanceConfig.h"
#include "ovpn2ss/PacketBuffer.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace ovpn2ss {

class ShadowsocksAeadSession final {
public:
    static constexpr std::size_t KeySize = 32;
    static constexpr std::size_t SaltSize = 32;
    static constexpr std::size_t TagSize = 16;
    static constexpr std::size_t NonceSize = 12;

    explicit ShadowsocksAeadSession(std::array<std::byte, KeySize> master_key);

    [[nodiscard]] PacketBuffer client_salt();
    void set_client_salt(std::span<const std::byte> salt);

    [[nodiscard]] PacketBuffer encrypt_tcp_chunk(std::span<const std::byte> plain);
    [[nodiscard]] std::optional<PacketBuffer> decrypt_tcp_chunk(std::span<const std::byte>& encrypted_stream);

    [[nodiscard]] PacketBuffer encrypt_udp_packet(std::span<const std::byte> plain);
    [[nodiscard]] std::optional<PacketBuffer> decrypt_udp_packet(std::span<const std::byte> encrypted);

private:
    void derive_subkey(std::span<const std::byte> salt, std::array<std::byte, KeySize>& out) const;
    void crypt(std::span<const std::byte> key, std::array<std::byte, NonceSize>& nonce,
        std::span<const std::byte> input, std::span<std::byte> output, std::span<std::byte, TagSize> tag);
    bool decrypt(std::span<const std::byte> key, std::array<std::byte, NonceSize>& nonce,
        std::span<const std::byte> input, std::span<const std::byte, TagSize> tag, std::span<std::byte> output);
    static void increment_nonce(std::array<std::byte, NonceSize>& nonce);

    std::array<std::byte, KeySize> master_key_{};
    std::array<std::byte, KeySize> send_key_{};
    std::array<std::byte, KeySize> recv_key_{};
    std::array<std::byte, NonceSize> send_nonce_{};
    std::array<std::byte, NonceSize> recv_nonce_{};
    bool have_recv_key_{false};
    bool sent_salt_{false};
};

class ShadowsocksAeadFactory final {
public:
    explicit ShadowsocksAeadFactory(std::string password);

    [[nodiscard]] ShadowsocksAeadSession make_session() const;
    [[nodiscard]] const std::array<std::byte, ShadowsocksAeadSession::KeySize>& master_key() const noexcept;

private:
    std::array<std::byte, ShadowsocksAeadSession::KeySize> master_key_{};
};

[[nodiscard]] std::optional<TargetAddress> parse_ss_address(std::span<const std::byte>& bytes);
[[nodiscard]] PacketBuffer encode_ss_address(const TargetAddress& target);

} // namespace ovpn2ss
