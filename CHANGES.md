# CHANGES

## 2026-09-14 — 重构为公开代理池专用版

- 移除旧版 GitHub VLESS/VMess/Trojan 等节点订阅源。
- 仅保留 HTTP / HTTPS / SOCKS4 / SOCKS5 公开代理来源。
- 新增 HProxy、Stormsia、ProxyScrape、Proxmint、IPLocate、Thordata、Databay、Proxio。
- 每个来源文件最多稳定采样 500 个候选，控制 4 小时一轮的测试时间。
- 保留原有 sing-box 实测、出口 IP、ASN/ISP、Hosting、Broadcast/Anycast/CDN、MITM、稳定性、Scamalytics、ipapi.is 和家宽/非家宽分类能力。
- 保留 V2RayN、Clash/Mihomo、sing-box 以及国家/家宽/非家宽输出。

## 2026-09-14 — 纯公开代理池重构增强

- 彻底移除旧版 VLESS / VMess / Trojan 等免费订阅来源。
- 公开来源统一覆盖 HTTP / HTTPS / SOCKS4 / SOCKS5。
- 增加 Thordata `top-trusted` 与 `stable` 候选池。
- 每个来源稳定 hash 采样上限调整为 300，降低 GitHub Actions 单轮测活压力。
- 增加协议独立订阅：HTTP / HTTPS / SOCKS4 / SOCKS5。
- 增加 `top-trusted`、`stable`、`residential-top`、`non-residential-top`。
- 增加国家 + 协议独立订阅。
- 增加 `summary.json` 机器可读统计。
- 历史记录增加连续存活 `survival_streak`，用于稳定节点精选。
- 增加综合 `quality_score`，综合延迟、稳定率、IP 质量和网络类型。

## v3.0 — 多维信誉 / 家宽 / 匿名性增强

- 参考 Thordata / Proxmint 的 echo-header 匿名性检测思路，但不把单一来源视为真值。
- 新增 `anonymity_score`、`residential_score`、`risk_score`、`overall_score`。
- 新增多端点匿名性检测：`elite / anonymous / transparent / unknown`。
- 新增真实 IP 泄漏 Header 检查：`X-Forwarded-For`、`Forwarded`、`Via`、`X-Real-IP`、`Client-IP`、`True-Client-IP`、`CF-Connecting-IP` 等。
- 家宽判定增加 Hosting/Proxy 硬否决、IDC 关键词交叉验证、Fraud 分、稳定性和匿名性加权。
- 新增 `output/nodes.json`：保存每个节点的 IP、ASN、ISP、网络类型、匿名性、风险、欺诈、稳定性、速度和综合评分。
- 新增 `output/residential-premium.txt`、对应 Clash/Sing-box 订阅。
- `summary.json` 增加匿名性、网络类型、风险分桶和 Premium Residential 统计。
