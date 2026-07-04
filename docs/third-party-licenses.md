# 第三方许可证

本文档汇总 `ovpn2ss` 使用到的第三方依赖许可证。这里不是法律意见；发布或分发前应再次核对上游许可证文件。

| 依赖 | 许可证 | 说明 |
| --- | --- | --- |
| Asio | Boost Software License 1.0 | 位于 `third_party/asio/asio`。 |
| lwIP | BSD-style 3-clause license | 源文件保留上游版权声明。 |
| lwIP contrib | BSD-style / 文件级许可证声明 | 分发时应保留上游声明。 |
| openvpn3-core | `AGPL-3.0-only OR MPL-2.0` | 本项目选择匹配 MPL-2.0 路径。 |
| mbedTLS | `Apache-2.0 OR GPL-2.0-or-later` | 建议按 Apache-2.0 路径使用。 |
| nlohmann/json | MIT | 位于 `third_party/json.hpp`。 |

## 项目许可证选择

本项目使用 MPL-2.0。纯自有代码使用 MIT 也可以成立，但当前工程直接集成 openvpn3-core，而 openvpn3-core 的非 AGPL 选项是 MPL-2.0，因此顶层项目采用 MPL-2.0 更清晰。

发布二进制或源码包时，请保留所有第三方依赖要求的版权声明和许可证文本。
