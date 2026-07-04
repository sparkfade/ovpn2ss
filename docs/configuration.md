# 配置说明

`ovpn2ss_app` 接收一个 JSON 文件路径。该文件必须包含非空 `instances` 数组。

## 示例

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

## 字段

| 字段 | 类型 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- | --- |
| `name` | string | 是 | 无 | 实例名称。 |
| `ovpn` | string | 是 | 无 | OpenVPN 客户端配置文件路径。 |
| `listen_host` | string | 否 | `127.0.0.1` | Shadowsocks 监听地址。 |
| `tcp_port` | integer | 是 | 无 | Shadowsocks TCP 监听端口。 |
| `udp_port` | integer | 否 | `tcp_port` | Shadowsocks UDP 监听端口。 |
| `method` | string | 否 | `chacha20-ietf-poly1305` | 当前只支持该 AEAD 方法。 |
| `password` | string | 是 | 无 | Shadowsocks 密码。 |
| `vpn_username` | string | 否 | 空 | OpenVPN 服务器用户名。服务器需要账号密码认证时填写（如 VPN Gate 填 `vpn`）。 |
| `vpn_password` | string | 否 | 空 | OpenVPN 服务器密码。与 `vpn_username` 配合使用。 |

## 校验规则

启动时会检查：

- `instances` 存在且非空。
- `name`、`ovpn`、`tcp_port`、`password` 存在。
- `.ovpn` 路径存在且是普通文件。
- 端口范围为 `1..65535`。
- TCP 端口之间不重复。
- UDP 端口之间不重复。
- `method` 必须为 `chacha20-ietf-poly1305`。

TCP 和 UDP 是不同协议，因此允许使用相同数字端口。

## OpenVPN 配置说明

`.ovpn` 文件必须能被 openvpn3-core 解析。推荐使用包含证书和密钥的 inline 配置，方便部署。

`.ovpn` 中可以保留 `dev tun`；`ovpn2ss` 会在内存中截获 OpenVPN Tun 路径，不会创建宿主机 Tun 设备。

如果服务器要求用户名/密码认证（日志出现 `Creds: UsernameEmpty/PasswordEmpty` 并在 `PUSH_REQUEST` 后返回 `AUTH_FAILED`），请填写 `vpn_username` / `vpn_password`。VPN Gate（`opengw.net`）等公共服务器通常接受任意非空凭据，填 `vpn` / `vpn` 即可。纯证书认证的配置保持两项为空。

如果 Shadowsocks 客户端访问域名目标，OpenVPN 服务端应推送可用 DNS，例如：

```text
push "dhcp-option DNS 10.8.0.1"
```
