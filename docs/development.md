# 开发与排错

## 目录结构

```text
include/ovpn2ss      项目头文件
src                  实现文件
third_party          第三方依赖或 stub
```

## 单元测试构建

```sh
cmake -S . -B build -DOVPN2SS_STUB_OPENVPN3=ON -DOVPN2SS_BUILD_TESTS=ON
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

## 真实 OpenVPN3 构建

```sh
cmake -S . -B build-real-openvpn \
  -DOVPN2SS_STUB_OPENVPN3=OFF \
  -DOVPN2SS_OPENVPN3_DIR=./third_party/openvpn3 \
  -DOVPN2SS_BUILD_TESTS=ON

cmake --build build-real-openvpn -j2
ctest --test-dir build-real-openvpn --output-on-failure
```

## mbedTLS 要求

mbedTLS 需要提供：

- `MBEDTLS_CHACHAPOLY_C`
- `MBEDTLS_HKDF_C`
- `MBEDTLS_MD_C`
- `MBEDTLS_MD5_C`
- `MBEDTLS_SHA1_C`

如果 CMake 找不到 mbedTLS，可以通过 `CMAKE_PREFIX_PATH` 指向安装前缀：

```sh
cmake -S . -B build -DCMAKE_PREFIX_PATH=/opt/mbedtls
```

## 常见问题

`openvpn3-core headers not found`

将 `OVPN2SS_OPENVPN3_DIR` 指向 openvpn3-core checkout，或启用 `OVPN2SS_STUB_OPENVPN3=ON`。

`ovpn file does not exist`

在 JSON 配置中使用绝对路径，并检查文件权限。

`method must be chacha20-ietf-poly1305`

当前只支持 classic Shadowsocks AEAD `chacha20-ietf-poly1305`。

端口绑定失败

检查是否已有其他进程占用了配置中的 TCP 或 UDP 端口。

域名目标访问失败

确认 OpenVPN 服务端推送了 DNS，且该 DNS 可通过隧道访问。

## 当前测试范围

已有测试覆盖：

- Shadowsocks 地址编解码。
- AEAD TCP chunk 加解密。
- AEAD UDP packet 加解密。
- JSON 配置校验和端口冲突检查。

生产验证还应覆盖真实 OpenVPN 服务端连接、多实例长时间运行、隧道内 DNS、TCP/UDP 压测等场景。
