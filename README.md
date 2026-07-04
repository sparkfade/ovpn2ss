# ovpn2ss

`ovpn2ss` 是一个单进程、用户态代理网关。它从 JSON 配置中加载多个 `.ovpn` 客户端配置，为每个配置创建独立的 OpenVPN/lwIP 运行实例，并为每个实例暴露独立的 Shadowsocks AEAD TCP/UDP 监听端口。

数据路径完全位于用户态：不创建宿主机 TUN/TAP 设备，不修改系统路由表，不调用 iptables，普通高端口监听不需要 `CAP_NET_ADMIN`。

## 功能

- 通过 JSON 显式配置多个 OpenVPN 实例。
- 每个实例拥有独立 Shadowsocks TCP/UDP 监听端口。
- Shadowsocks classic AEAD，固定支持 `chacha20-ietf-poly1305`。
- AEAD 使用 mbedTLS 实现，不引入 libsodium。
- 通过 lwIP `NO_SYS=1` Raw API 桥接 TCP/UDP。
- 通过自定义 OpenVPN3 `TunBuilderBase` 将 Tun 数据面拦截在内存中。
- 支持 OpenVPN3 stub 构建模式，便于本地测试。

## 依赖

- 支持 C++20 的编译器，例如 GCC 10+ 或 Clang 12+。
- CMake 3.20+。
- 启用 ChaCha20-Poly1305 和 HKDF 的 mbedTLS。
- Asio、lwIP、lwIP contrib、openvpn3-core、nlohmann/json。

默认依赖目录结构：

```text
third_party/asio/asio/include
third_party/lwip
third_party/lwip-contrib/contrib-2.1.0
third_party/openvpn3
third_party/openvpn3-stub
third_party/json.hpp
```

## 构建

stub OpenVPN3 模式用于开发和单元测试：

```sh
cmake -S . -B build \
  -DOVPN2SS_STUB_OPENVPN3=ON \
  -DOVPN2SS_BUILD_TESTS=ON

cmake --build build -j2
ctest --test-dir build --output-on-failure
```

真实 OpenVPN3 模式会编译 openvpn3-core：

```sh
cmake -S . -B build-real-openvpn \
  -DOVPN2SS_STUB_OPENVPN3=OFF \
  -DOVPN2SS_OPENVPN3_DIR=./third_party/openvpn3 \
  -DOVPN2SS_BUILD_TESTS=ON

cmake --build build-real-openvpn -j2
ctest --test-dir build-real-openvpn --output-on-failure
```

常用 CMake 选项：

| 选项 | 默认值 | 说明 |
| --- | --- | --- |
| `OVPN2SS_BUILD_APP` | `ON` | 构建 `ovpn2ss_app`。 |
| `OVPN2SS_BUILD_TESTS` | `ON` | 构建单元测试。 |
| `OVPN2SS_STUB_OPENVPN3` | `ON` | 使用 OpenVPN3 stub 头文件。 |
| `OVPN2SS_OPENVPN3_DIR` | `third_party/openvpn3` | openvpn3-core 源码路径。 |

## 配置

`ovpn2ss_app` 接收一个 JSON 配置文件路径：

```json
{
  "instances": [
    {
      "name": "office-vpn",
      "ovpn": "/absolute/path/to/office.ovpn",
      "listen_host": "127.0.0.1",
      "tcp_port": 10801,
      "udp_port": 10801,
      "method": "chacha20-ietf-poly1305",
      "password": "replace-with-a-strong-password",
      "vpn_username": "",
      "vpn_password": ""
    }
  ]
}
```

最小示例见 [config.example.json](config.example.json)，完整字段说明见 [docs/configuration.md](docs/configuration.md)。

如果 `.ovpn` 服务器需要用户名/密码认证（例如 VPN Gate / opengw.net，日志出现 `Creds: UsernameEmpty/PasswordEmpty` 后 `AUTH_FAILED`），请在实例中设置 `vpn_username` 与 `vpn_password`（VPN Gate 通常填 `vpn` / `vpn`）。留空则不提供凭据（适用于纯证书认证的配置）。

## 运行

完成真实 OpenVPN3 构建后运行：

```sh
./build-real-openvpn/ovpn2ss_app ./config.example.json
```

示例配置中的 `.ovpn` 路径和密码是占位值，运行真实实例前需要替换。

Shadowsocks 客户端参数需要与对应实例一致：

```text
server: 127.0.0.1
server_port: 10801
method: chacha20-ietf-poly1305
password: replace-with-a-strong-password
udp: enabled
```

## 文档

- [架构说明](docs/architecture.md)
- [配置说明](docs/configuration.md)
- [开发与排错](docs/development.md)
- [第三方许可证](docs/third-party-licenses.md)

## 许可证

本项目使用 Mozilla Public License 2.0。详见 [LICENSE](LICENSE)。

第三方依赖许可证摘要见 [docs/third-party-licenses.md](docs/third-party-licenses.md)。OpenVPN3 使用 `AGPL-3.0-only OR MPL-2.0`，本项目选择 MPL-2.0，以匹配 OpenVPN3 的 MPL 分发路径。
