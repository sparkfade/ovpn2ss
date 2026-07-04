#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace ovpn2ss {

using Bytes = std::vector<std::byte>;

class PacketBuffer final {
public:
    PacketBuffer() = default;
    explicit PacketBuffer(std::size_t size) : data_(size) {}
    explicit PacketBuffer(Bytes data) : data_(std::move(data)) {}

    [[nodiscard]] std::byte* data() noexcept { return data_.data(); }
    [[nodiscard]] const std::byte* data() const noexcept { return data_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] std::span<std::byte> span() noexcept { return data_; }
    [[nodiscard]] std::span<const std::byte> span() const noexcept { return data_; }

    void resize(std::size_t size) { data_.resize(size); }
    void clear() noexcept { data_.clear(); }
    void append(std::span<const std::byte> bytes);
    [[nodiscard]] Bytes release() noexcept { return std::move(data_); }

private:
    Bytes data_;
};

inline void PacketBuffer::append(std::span<const std::byte> bytes) {
    data_.insert(data_.end(), bytes.begin(), bytes.end());
}

[[nodiscard]] inline std::span<const std::byte> as_bytes(std::span<const std::uint8_t> in) noexcept {
    return {reinterpret_cast<const std::byte*>(in.data()), in.size()};
}

[[nodiscard]] inline std::span<std::byte> as_writable_bytes(std::span<std::uint8_t> in) noexcept {
    return {reinterpret_cast<std::byte*>(in.data()), in.size()};
}

} // namespace ovpn2ss
