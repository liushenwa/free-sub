# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box vv1.14.0` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `72` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `72` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `72` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/singbox.json) |

### 🖥️ 非家宽/原生 IDC 独立总订阅

> 仅包含最终分类中的非家宽节点；已排除明确的 Cloudflare Anycast、广播/任播特征和 CDN 出口。普通数据中心节点不会因为“非家宽”而被删除。

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 | 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN** | `70` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential.txt) |
| 🚀 **Clash** | `70` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential-clash.yaml) |
| 📦 **sing-box** | `70` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential-singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽采用多信号置信度评分，并以星级展示：★★★☆☆（≥60）及以上进入家宽专区，★★★★☆（≥75）为优质，★★★★★（≥90）为高质量家宽。明确 hosting/proxy/数据中心/CDN/广播/Anycast/fraud≥90 仍硬否决。★★★★★ 节点会动态保存到 `output/residential-pool.json`，下一轮优先重新测活，即使原公开源暂时消失也不会立即丢失。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 🇻🇳 越南 (Vietnam) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/VN.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/VN.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/clash-VN.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/clash-VN.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/singbox-VN.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/singbox-VN.json) |
| 🇨🇿 捷克 (Czech) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/CZ.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/CZ.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/clash-CZ.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/clash-CZ.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/singbox-CZ.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/singbox-CZ.json) |

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 🇺🇸 美国 (United States) | 17 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/US.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/US.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-US.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-US.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-US.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-US.json) |
| 🇧🇷 巴西 (Brazil) | 7 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BR.json) |
| 🇷🇺 俄罗斯 (Russia) | 6 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/RU.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/RU.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-RU.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-RU.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-RU.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-RU.json) |
| 🇫🇷 法国 (France) | 6 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/FR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/FR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-FR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-FR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-FR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-FR.json) |
| 🇧🇩 孟加拉 (Bangladesh) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BD.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BD.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BD.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BD.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BD.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BD.json) |
| 🇮🇳 印度 (India) | 3 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/IN.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/IN.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-IN.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-IN.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-IN.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-IN.json) |
| 🇵🇱 波兰 (Poland) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/PL.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/PL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-PL.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-PL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-PL.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-PL.json) |
| 🇯🇵 日本 (Japan) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/JP.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/JP.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-JP.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-JP.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-JP.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-JP.json) |
| 🇮🇩 印尼 (Indonesia) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/ID.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/ID.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-ID.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-ID.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-ID.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-ID.json) |
| 🇳🇱 荷兰 (Netherlands) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/NL.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/NL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-NL.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-NL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-NL.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-NL.json) |
| 🇰🇬 KG | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/KG.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/KG.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-KG.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-KG.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-KG.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-KG.json) |
| 🇻🇳 越南 (Vietnam) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/VN.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/VN.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-VN.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-VN.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-VN.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-VN.json) |
| 🇮🇷 IR | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/IR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/IR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-IR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-IR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-IR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-IR.json) |
| 🇧🇬 保加利亚 (Bulgaria) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BG.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BG.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BG.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BG.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BG.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BG.json) |
| 🇱🇻 拉脱维亚 (Latvia) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/LV.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/LV.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-LV.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-LV.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-LV.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-LV.json) |
| 🇧🇮 BI | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BI.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BI.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BI.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BI.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BI.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BI.json) |
| 🇦🇷 阿根廷 (Argentina) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/AR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/AR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-AR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-AR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-AR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-AR.json) |
| 🇨🇳 CN | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/CN.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/CN.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-CN.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-CN.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-CN.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-CN.json) |
| 🇹🇷 土耳其 (Turkey) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/TR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/TR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-TR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-TR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-TR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-TR.json) |
| 🇳🇵 尼泊尔 (Nepal) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/NP.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/NP.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-NP.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-NP.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-NP.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-NP.json) |
| 🇨🇴 哥伦比亚 (Colombia) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/CO.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/CO.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-CO.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-CO.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-CO.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-CO.json) |
| 🇸🇪 瑞典 (Sweden) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/SE.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/SE.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-SE.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-SE.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-SE.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-SE.json) |
| 🇸🇨 塞舌尔 (Seychelles) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/SC.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/SC.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-SC.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-SC.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-SC.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-SC.json) |
| 🇭🇳 HN | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/HN.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/HN.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-HN.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-HN.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-HN.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-HN.json) |
| 🇱🇹 立陶宛 (Lithuania) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/LT.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/LT.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-LT.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-LT.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-LT.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-LT.json) |
| 🇸🇬 新加坡 (Singapore) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/SG.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/SG.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-SG.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-SG.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-SG.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-SG.json) |
| 🇪🇸 西班牙 (Spain) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/ES.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/ES.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-ES.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-ES.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-ES.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-ES.json) |
| 🇲🇽 墨西哥 (Mexico) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/MX.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/MX.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-MX.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-MX.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-MX.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-MX.json) |
| 🇦🇹 奥地利 (Austria) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/AT.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/AT.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-AT.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-AT.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-AT.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-AT.json) |
| 🇷🇴 罗马尼亚 (Romania) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/RO.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/RO.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-RO.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-RO.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-RO.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-RO.json) |

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {
  async fetch(request) {
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "liushenwa";
    const REPO = "free-sub";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {
      headers: {
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }
    });

    if (!res.ok) {
      return new Response("Not Found", { status: 404 });
    }

    return new Response(await res.text(), {
      headers: {
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }
    });
  }
}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos=liushenwa/free-sub&type=Date)](https://star-history.com/#liushenwa/free-sub&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **测活标准**：节点必须通过 ① 端口预检 ② sing-box 实际隧道 3 个 generate_204 探测 ③ 真实出口 IP 穿透获取 ④ Cloudflare 5MB 限时下载 (吞吐 ≥ 70KB/s) ⑤ TLS 证书校验非 MITM, 方可入库。
3. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
