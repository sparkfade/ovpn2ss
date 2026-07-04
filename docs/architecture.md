# 架构说明

`ovpn2ss` 在一个进程内运行多个 OpenVPN-backed Shadowsocks 网关。每个实例拥有自己的 Asio `io_context`、工作线程、lwIP `netif`、OpenVPN 客户端适配器，以及 Shadowsocks TCP/UDP 监听器。

## 数据路径

请求方向：

```text
Shadowsocks Client
    -> Shadowsocks Inbound + AEAD 解密
    -> lwIP Raw TCP/UDP PCB
    -> lwIP netif output
    -> OpenVPN3 memory Tun
    -> OpenVPN 加密数据通道
    -> OpenVPN Server
```

返回方向：

```text
OpenVPN Server
    -> OpenVPN3 解密后的 L3 packet
    -> lwIP netif input
    -> lwIP TCP/UDP callback
    -> Shadowsocks AEAD 加密
    -> Shadowsocks Client
```

## 核心模块

| 模块 | 职责 |
| --- | --- |
| `OpenVpnTunBuilder` | 重写 OpenVPN3 Tun 构建流程，将 Tun packet 保留在内存中。 |
| `LwipRuntime` | 初始化 lwIP `NO_SYS=1`，配置 `netif`、DNS 和 Asio 定时器。 |
| `ShadowsocksAead` | 使用 mbedTLS ChaCha20-Poly1305 实现 classic Shadowsocks AEAD。 |
| `TcpRelaySession` | 将 Shadowsocks TCP stream 桥接到 lwIP TCP PCB，并实现背压。 |
| `UdpRelaySession` | 将 Shadowsocks UDP packet 桥接到 lwIP UDP PCB，并维护 endpoint 映射。 |
| `MultiInstanceManager` | 加载 JSON 配置，为每个实例启动独立运行时。 |

## 无宿主机网络状态修改

项目刻意避免修改宿主机网络状态：

- 不创建 TUN/TAP 设备。
- 不修改宿主机路由表。
- 不创建 iptables 或 nftables 规则。
- 普通高端口监听不需要 `CAP_NET_ADMIN`。

## lwIP 隔离说明

每个运行实例拥有自己的 `netif`、PCB 所属关系和 Asio 线程。需要注意的是，lwIP 本身包含进程级全局状态，因此严格协议栈隔离取决于实际集成策略。生产环境如果要求硬隔离，应验证共享 lwIP 全局状态是否可接受，或改用进程级隔离。
