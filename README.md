# 在线小工具合集（纯前端 · 数据不上传）

一组自己用着顺手、就顺手做成网页的小工具。全部在浏览器本地运行，不把你的数据传到任何服务器。

**在线直接用（不用装任何东西）：**

| 工具 | 在线地址 | 说明 |
|---|---|---|
| 代理链接转换 | https://yuantou.one/tools/proxy/ | 16 种协议互转 Clash / sing-box / Surge / Quantumult X / Loon / OpenClash / PassWall |
| 2FA 验证码生成器 | https://yuantou.one/tools/account-card/ | TOTP 动态口令 + 二维码 + 批量出码 + 账号信息卡 |
| 批量文本去重 | https://yuantou.one/tools/text-clean/ | 去重/排序/提取邮箱手机号/账号列表转 CSV、JSON、表格 |
| 二维码生成器 | https://yuantou.one/tools/qr-code/ | 文本 / 网址 / WiFi / 名片 vCard，可下载 PNG、SVG |

备用地址（同一个东西）：https://chuhao.shop/tools/

---

## 1. 代理链接转换

把任意的代理分享链接粘进去，转成客户端能直接吃的配置。

**输入支持 16 种协议**

```
VMess            base64 JSON（v2rayN 格式）
VLESS            reality / xtls-rprx-vision / ws / grpc
Shadowsocks      SIP002、旧版 base64、obfs、v2ray-plugin
ShadowsocksR     完整参数
Trojan           ws / grpc
Hysteria         原版与 Hysteria2（hy2://）
TUIC             v5
Juicity
AnyTLS
NaiveProxy       naive+https / naive+quic
Brook
SSH
Mieru
WireGuard        直接粘贴 .conf 文本
Socks5 / Socks4
HTTP / HTTPS
```

**输出 11 种格式**

```
Clash / Mihomo YAML     含 proxy-groups 与基础分流
sing-box JSON           含 tun/mixed 入站、dns、route
Surge
Quantumult X
Loon
OpenClash               路由器用，含 fake-ip 与 redir/tproxy 端口
PassWall / SSR Plus+    OpenWrt 批量导入的链接列表
WireGuard .conf
v2rayN 链接清单
Base64 订阅
解析明细                逐条列出所有字段，排查参数错
```

**特性**

- 批量粘贴，一行一条；整段 Base64 订阅自动识别解码
- 可以填订阅 URL 由服务端代取（后端有 SSRF 防护，见 `tools/proxy/fetch.php`）
- 目标格式不支持的协议会明确提示「已跳过 vless×1」，不会静默丢节点

## 2. 2FA 验证码生成器

输入 base32 密钥，立刻出 6 位动态口令，跟 Google Authenticator 显示的一致（RFC 6238）。

- 单个账号：验证码 + 倒计时环 + `otpauth://` 二维码（扫码即绑定）
- 批量模式：每行 `名称|密钥`，一次出所有号的码
- 信息卡：把手机号/密码/密钥排成一张可复制、可下载的卡片

密钥全程不离开浏览器（Web Crypto 计算 HMAC-SHA1）。

## 3. 批量文本去重

一行一条的数据处理：

- 清洗：去首尾空白、去重、去空行、转小写
- 排序：A→Z / Z→A / 按长度 / 随机打乱
- 提取：邮箱、手机号（中国大陆 + 国际）、链接、域名、纯数字
- 过滤：只保留含关键词 / 删掉含关键词
- 输出：换行、逗号、CSV（带 BOM，Excel 直接开）、JSON、Markdown 表格、SQL IN

**账号列表识别**：`手机号----密码----2FA`、`|`、逗号、制表符、` : ` 这几种分隔符都能自动判断，转成三列表格。

## 4. 二维码生成器

- 文本 / 网址
- WiFi（SSID + 密码 + 加密方式，手机扫码直接连网）
- 名片 vCard（姓名/电话/邮箱/公司/网址，扫码存联系人）
- 尺寸 200–600px，容错 L/M/Q/H
- 下载 PNG 或 SVG

---

## 为什么开源

这些工具本来就在网页上跑，代码是公开的 Web 技术，没什么可藏的。开源出来：

1. 你可以自己部署一份，不依赖我的服务器
2. 有人发现问题可以直接提 Issue / PR
3. 我也能借这个仓库认识一些同行

## 本地部署

全部是静态文件，扔进任意 nginx / Apache 的目录就能用。

```bash
git clone https://github.com/jhisjhand-code/web-tools-collection.git
cd web-tools-collection
# 复制 tools/ 到你的站点根目录即可
```

只有 `tools/proxy/fetch.php` 需要 PHP（用来代取订阅链接）。其余纯静态。

单文件部署也行：每个工具的 `index.html` 都是自包含的（二维码库已内联），单独拷走就能跑。

## 技术说明

- 无框架、无构建步骤、无外部 CDN 依赖（离线可用）
- 二维码用 Kazuhiko Arase 的 qrcode-generator（MIT）
- 代理解析器是手写的，支持往返转换（链接 → 对象 → 链接 结果一致）
- TOTP 用浏览器原生 Web Crypto，已用 RFC 6238 测试向量验证

## 许可

MIT。用得上就拿去用，改完愿意的话提个 PR 回来。

---

工具本身有问题（解析错误、格式不支持、界面难用）欢迎提 Issue。

- 相关主题：[ai-account-playbook](https://github.com/cointaboo/ai-account-playbook) · [apple-id-notes](https://github.com/cointaboo/apple-id-notes) · [telegram-account-notes](https://github.com/cointaboo/telegram-account-notes) · [payment-topup-notes](https://github.com/cointaboo/payment-topup-notes) · [overseas-account-buying-guide](https://github.com/cointaboo/overseas-account-buying-guide) · [account-guide-mcp](https://github.com/cointaboo/account-guide-mcp)
