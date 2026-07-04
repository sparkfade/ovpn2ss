#include "ovpn2ss/ShadowsocksAead.h"

#include <mbedtls/chachapoly.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>

#include <asio/ip/address.hpp>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string_view>

namespace ovpn2ss {
namespace {

class Csprng final {
public:
    Csprng() {
        mbedtls_entropy_init(&entropy_);
        mbedtls_ctr_drbg_init(&ctr_drbg_);
        constexpr unsigned char personalization[] = "ovpn2ss-shadowsocks-aead";
        if (mbedtls_ctr_drbg_seed(&ctr_drbg_, mbedtls_entropy_func, &entropy_,
                personalization, sizeof(personalization) - 1) != 0) {
            mbedtls_ctr_drbg_free(&ctr_drbg_);
            mbedtls_entropy_free(&entropy_);
            throw std::runtime_error("mbedTLS CTR_DRBG seed failed");
        }
    }

    ~Csprng() {
        mbedtls_ctr_drbg_free(&ctr_drbg_);
        mbedtls_entropy_free(&entropy_);
    }

    void fill(std::span<std::byte> out) {
        if (out.empty()) {
            return;
        }
        if (mbedtls_ctr_drbg_random(&ctr_drbg_, reinterpret_cast<unsigned char*>(out.data()), out.size()) != 0) {
            throw std::runtime_error("mbedTLS CTR_DRBG random failed");
        }
    }

private:
    mbedtls_entropy_context entropy_{};
    mbedtls_ctr_drbg_context ctr_drbg_{};
};

void random_bytes(std::span<std::byte> out) {
    static thread_local Csprng rng;
    rng.fill(out);
}

std::array<std::byte, ShadowsocksAeadSession::KeySize> evp_bytes_to_key(const std::string& password) {
    std::array<std::byte, ShadowsocksAeadSession::KeySize> key{};
    std::array<unsigned char, 16> digest{};
    std::size_t produced = 0;

    while (produced < key.size()) {
        mbedtls_md5_context ctx;
        mbedtls_md5_init(&ctx);
        mbedtls_md5_starts(&ctx);
        if (produced != 0) {
            mbedtls_md5_update(&ctx, digest.data(), digest.size());
        }
        mbedtls_md5_update(&ctx, reinterpret_cast<const unsigned char*>(password.data()), password.size());
        mbedtls_md5_finish(&ctx, digest.data());
        mbedtls_md5_free(&ctx);

        const auto n = std::min(digest.size(), key.size() - produced);
        std::memcpy(key.data() + produced, digest.data(), n);
        produced += n;
    }
    return key;
}

std::uint16_t read_be16(std::span<const std::byte> bytes) {
    return (static_cast<std::uint16_t>(bytes[0]) << 8) | static_cast<std::uint16_t>(bytes[1]);
}

void append_be16(PacketBuffer& out, std::uint16_t value) {
    const std::array<std::byte, 2> b{static_cast<std::byte>(value >> 8), static_cast<std::byte>(value & 0xff)};
    out.append(b);
}

} // namespace

ShadowsocksAeadSession::ShadowsocksAeadSession(std::array<std::byte, KeySize> master_key)
    : master_key_(master_key) {}

PacketBuffer ShadowsocksAeadSession::client_salt() {
    PacketBuffer salt(SaltSize);
    random_bytes(salt.span());
    derive_subkey(salt.span(), send_key_);
    send_nonce_.fill(std::byte{0});
    sent_salt_ = true;
    return salt;
}

void ShadowsocksAeadSession::set_client_salt(std::span<const std::byte> salt) {
    if (salt.size() != SaltSize) {
        throw std::runtime_error("invalid Shadowsocks AEAD salt size");
    }
    derive_subkey(salt, recv_key_);
    recv_nonce_.fill(std::byte{0});
    have_recv_key_ = true;
}

PacketBuffer ShadowsocksAeadSession::encrypt_tcp_chunk(std::span<const std::byte> plain) {
    if (!sent_salt_) {
        throw std::runtime_error("send salt not initialized");
    }
    if (plain.size() > 0x3fff) {
        throw std::runtime_error("Shadowsocks AEAD TCP chunk too large");
    }

    std::array<std::byte, 2> len_plain{static_cast<std::byte>(plain.size() >> 8), static_cast<std::byte>(plain.size() & 0xff)};
    std::array<std::byte, 2> len_cipher{};
    std::array<std::byte, TagSize> len_tag{};
    crypt(send_key_, send_nonce_, len_plain, len_cipher, len_tag);

    PacketBuffer out;
    out.append(len_cipher);
    out.append(len_tag);

    PacketBuffer payload_cipher(plain.size());
    std::array<std::byte, TagSize> payload_tag{};
    crypt(send_key_, send_nonce_, plain, payload_cipher.span(), payload_tag);
    out.append(payload_cipher.span());
    out.append(payload_tag);
    return out;
}

std::optional<PacketBuffer> ShadowsocksAeadSession::decrypt_tcp_chunk(std::span<const std::byte>& encrypted_stream) {
    if (!have_recv_key_ || encrypted_stream.size() < 2 + TagSize) {
        return std::nullopt;
    }

    auto trial_nonce = recv_nonce_;
    std::array<std::byte, 2> len_plain{};
    auto len_tag = std::span<const std::byte, TagSize>(encrypted_stream.subspan(2, TagSize));
    if (!decrypt(recv_key_, trial_nonce, encrypted_stream.first(2), len_tag, len_plain)) {
        throw std::runtime_error("invalid Shadowsocks AEAD TCP length tag");
    }

    const auto payload_len = read_be16(len_plain) & 0x3fff;
    const auto need = 2 + TagSize + payload_len + TagSize;
    if (encrypted_stream.size() < need) {
        return std::nullopt;
    }

    PacketBuffer plain(payload_len);
    auto payload = encrypted_stream.subspan(2 + TagSize, payload_len);
    auto payload_tag = std::span<const std::byte, TagSize>(encrypted_stream.subspan(2 + TagSize + payload_len, TagSize));
    if (!decrypt(recv_key_, trial_nonce, payload, payload_tag, plain.span())) {
        throw std::runtime_error("invalid Shadowsocks AEAD TCP payload tag");
    }
    recv_nonce_ = trial_nonce;
    encrypted_stream = encrypted_stream.subspan(need);
    return plain;
}

PacketBuffer ShadowsocksAeadSession::encrypt_udp_packet(std::span<const std::byte> plain) {
    PacketBuffer salt = client_salt();
    PacketBuffer out;
    out.append(salt.span());
    PacketBuffer cipher(plain.size());
    std::array<std::byte, TagSize> tag{};
    crypt(send_key_, send_nonce_, plain, cipher.span(), tag);
    out.append(cipher.span());
    out.append(tag);
    return out;
}

std::optional<PacketBuffer> ShadowsocksAeadSession::decrypt_udp_packet(std::span<const std::byte> encrypted) {
    if (encrypted.size() < SaltSize + TagSize) {
        return std::nullopt;
    }
    std::array<std::byte, KeySize> key{};
    derive_subkey(encrypted.first(SaltSize), key);
    std::array<std::byte, NonceSize> nonce{};
    const auto body_len = encrypted.size() - SaltSize - TagSize;
    PacketBuffer plain(body_len);
    auto body = encrypted.subspan(SaltSize, body_len);
    auto tag = std::span<const std::byte, TagSize>(encrypted.subspan(SaltSize + body_len, TagSize));
    if (!decrypt(key, nonce, body, tag, plain.span())) {
        return std::nullopt;
    }
    return plain;
}

void ShadowsocksAeadSession::derive_subkey(std::span<const std::byte> salt, std::array<std::byte, KeySize>& out) const {
    const auto* md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    constexpr std::string_view info = "ss-subkey";
    if (mbedtls_hkdf(md,
            reinterpret_cast<const unsigned char*>(salt.data()), salt.size(),
            reinterpret_cast<const unsigned char*>(master_key_.data()), master_key_.size(),
            reinterpret_cast<const unsigned char*>(info.data()), info.size(),
            reinterpret_cast<unsigned char*>(out.data()), out.size()) != 0) {
        throw std::runtime_error("mbedTLS HKDF failed");
    }
}

void ShadowsocksAeadSession::crypt(std::span<const std::byte> key, std::array<std::byte, NonceSize>& nonce,
    std::span<const std::byte> input, std::span<std::byte> output, std::span<std::byte, TagSize> tag) {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    if (mbedtls_chachapoly_setkey(&ctx, reinterpret_cast<const unsigned char*>(key.data())) != 0 ||
        mbedtls_chachapoly_encrypt_and_tag(&ctx,
            input.size(),
            reinterpret_cast<const unsigned char*>(nonce.data()),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(input.data()),
            reinterpret_cast<unsigned char*>(output.data()),
            reinterpret_cast<unsigned char*>(tag.data())) != 0) {
        mbedtls_chachapoly_free(&ctx);
        throw std::runtime_error("mbedTLS chachapoly encrypt failed");
    }
    mbedtls_chachapoly_free(&ctx);
    increment_nonce(nonce);
}

bool ShadowsocksAeadSession::decrypt(std::span<const std::byte> key, std::array<std::byte, NonceSize>& nonce,
    std::span<const std::byte> input, std::span<const std::byte, TagSize> tag, std::span<std::byte> output) {
    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);
    const int rc = mbedtls_chachapoly_setkey(&ctx, reinterpret_cast<const unsigned char*>(key.data())) == 0
        ? mbedtls_chachapoly_auth_decrypt(&ctx,
            input.size(),
            reinterpret_cast<const unsigned char*>(nonce.data()),
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(tag.data()),
            reinterpret_cast<const unsigned char*>(input.data()),
            reinterpret_cast<unsigned char*>(output.data()))
        : -1;
    mbedtls_chachapoly_free(&ctx);
    if (rc != 0) {
        return false;
    }
    increment_nonce(nonce);
    return true;
}

void ShadowsocksAeadSession::increment_nonce(std::array<std::byte, NonceSize>& nonce) {
    for (auto& b : nonce) {
        const auto next = static_cast<unsigned char>(b) + 1;
        b = static_cast<std::byte>(next);
        if (next != 0) {
            break;
        }
    }
}

ShadowsocksAeadFactory::ShadowsocksAeadFactory(std::string password)
    : master_key_(evp_bytes_to_key(password)) {}

ShadowsocksAeadSession ShadowsocksAeadFactory::make_session() const {
    return ShadowsocksAeadSession(master_key_);
}

const std::array<std::byte, ShadowsocksAeadSession::KeySize>& ShadowsocksAeadFactory::master_key() const noexcept {
    return master_key_;
}

std::optional<TargetAddress> parse_ss_address(std::span<const std::byte>& bytes) {
    if (bytes.empty()) {
        return std::nullopt;
    }
    const auto atyp = static_cast<AddressType>(bytes[0]);
    bytes = bytes.subspan(1);

    TargetAddress target{.type = atyp};
    if (atyp == AddressType::Ipv4) {
        if (bytes.size() < 6) return std::nullopt;
        target.host = std::to_string(static_cast<unsigned char>(bytes[0])) + "." +
            std::to_string(static_cast<unsigned char>(bytes[1])) + "." +
            std::to_string(static_cast<unsigned char>(bytes[2])) + "." +
            std::to_string(static_cast<unsigned char>(bytes[3]));
        bytes = bytes.subspan(4);
    } else if (atyp == AddressType::Domain) {
        if (bytes.empty()) return std::nullopt;
        const auto len = static_cast<unsigned char>(bytes[0]);
        bytes = bytes.subspan(1);
        if (bytes.size() < len + 2) return std::nullopt;
        target.host.assign(reinterpret_cast<const char*>(bytes.data()), len);
        bytes = bytes.subspan(len);
    } else if (atyp == AddressType::Ipv6) {
        if (bytes.size() < 18) return std::nullopt;
        char buf[40]{};
        std::snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
            static_cast<unsigned char>(bytes[0]), static_cast<unsigned char>(bytes[1]),
            static_cast<unsigned char>(bytes[2]), static_cast<unsigned char>(bytes[3]),
            static_cast<unsigned char>(bytes[4]), static_cast<unsigned char>(bytes[5]),
            static_cast<unsigned char>(bytes[6]), static_cast<unsigned char>(bytes[7]),
            static_cast<unsigned char>(bytes[8]), static_cast<unsigned char>(bytes[9]),
            static_cast<unsigned char>(bytes[10]), static_cast<unsigned char>(bytes[11]),
            static_cast<unsigned char>(bytes[12]), static_cast<unsigned char>(bytes[13]),
            static_cast<unsigned char>(bytes[14]), static_cast<unsigned char>(bytes[15]));
        target.host = buf;
        bytes = bytes.subspan(16);
    } else {
        return std::nullopt;
    }

    if (bytes.size() < 2) {
        return std::nullopt;
    }
    target.port = read_be16(bytes.first(2));
    bytes = bytes.subspan(2);
    return target;
}

PacketBuffer encode_ss_address(const TargetAddress& target) {
    PacketBuffer out;
    const auto atyp = static_cast<std::byte>(target.type);
    out.append(std::span<const std::byte>(&atyp, 1));
    asio::error_code ec;
    if (target.type == AddressType::Domain) {
        if (target.host.size() > 255) {
            throw std::runtime_error("domain too long");
        }
        const auto len = static_cast<std::byte>(target.host.size());
        out.append(std::span<const std::byte>(&len, 1));
        out.append({reinterpret_cast<const std::byte*>(target.host.data()), target.host.size()});
    } else if (target.type == AddressType::Ipv4) {
        const auto ip = asio::ip::make_address_v4(target.host, ec);
        if (ec) {
            throw std::runtime_error("invalid IPv4 address");
        }
        const auto bytes = ip.to_bytes();
        out.append(std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
    } else if (target.type == AddressType::Ipv6) {
        const auto ip = asio::ip::make_address_v6(target.host, ec);
        if (ec) {
            throw std::runtime_error("invalid IPv6 address");
        }
        const auto bytes = ip.to_bytes();
        out.append(std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
    } else {
        throw std::runtime_error("invalid Shadowsocks address type");
    }
    append_be16(out, target.port);
    return out;
}

} // namespace ovpn2ss
