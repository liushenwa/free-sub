# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box vv1.14.0` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `15` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `15` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `15` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/singbox.json) |

### 🖥️ 非家宽 / 原生 IP + 低欺诈独立总订阅

> 仅保留非家宽中的原生出口 IP：`hosting=false`、`proxy=false`，排除 CDN/Anycast/广播出口，并要求 Scamalytics `fraud_score <= 30`。无法取得 fraud 分的节点也不会进入该专区。

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 | 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN** | `8` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential.txt) |
| 🚀 **Clash** | `8` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential-clash.yaml) |
| 📦 **sing-box** | `8` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/non-residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/non-residential-singbox.json) |

---

## 🏠 家宽全部节点统一总订阅

> 以下 3 个链接始终对应本轮筛选出的**全部家宽节点**，与按国家拆分的家宽订阅互补；五星持久池 `residential-pool` 是另一套独立资产。

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 | 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN** | `7` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential.txt) |
| 🚀 **Clash** | `7` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-clash.yaml) |
| 📦 **sing-box** | `7` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-singbox.json) |

---

## 📊 预检未过节点最终入选统计

> 本统计用于评估“端口预检”是否值得保留。预检未过节点当前仍会进入后续 sing-box 全流程，因此这里统计它们最终进入**家宽总订阅**和**非家宽总订阅**的数量与占比。

| 指标 | 数量 | 占预检未过 | 占最终该专区 |
| :--- | ---: | ---: | ---: |
| 预检未过 → 家宽总订阅 | `2` | `0.11%` | `28.57%` |
| 预检未过 → 非家宽总订阅 | `1` | `0.06%` | `12.5%` |
| 预检未过 → 最终任一总订阅 | `3` | `0.17%` | - |

> 💡 如果连续多轮数据显示“预检未过 → 家宽总订阅”的入选率长期极低，可以考虑将预检未过节点直接跳过，从而显著减少后续 sing-box 测活时间。建议至少观察 **3–5 轮** 再决定是否关闭，以免偶发的本地 TCP 误判导致漏掉可用家宽。

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽采用多信号置信度评分，并以星级展示：★★★☆☆（≥60）及以上进入家宽专区，★★★★☆（≥75）为优质，★★★★★（≥90）为高质量家宽。明确 hosting/proxy/数据中心/CDN/广播/Anycast/fraud≥90 仍硬否决。★★★★★ 节点会动态保存到 `output/residential-pool.json`，下一轮优先重新测活，即使原公开源暂时消失也不会立即丢失。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 🇷🇺 俄罗斯 (Russia) | 4 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/RU.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/RU.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/clash-RU.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/clash-RU.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/singbox-RU.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/singbox-RU.json) |
| 🇹🇭 泰国 (Thailand) | 2 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/TH.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/TH.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/clash-TH.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/clash-TH.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/singbox-TH.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/singbox-TH.json) |
| 🇳🇬 尼日利亚 (Nigeria) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/NG.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/NG.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/clash-NG.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/clash-NG.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/residential-by-country/singbox-NG.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/residential-by-country/singbox-NG.json) |

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
| 🇵🇱 波兰 (Poland) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/PL.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/PL.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-PL.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-PL.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-PL.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-PL.json) |
| 🇺🇸 美国 (United States) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/US.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/US.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-US.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-US.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-US.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-US.json) |
| 🇷🇺 俄罗斯 (Russia) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/RU.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/RU.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-RU.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-RU.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-RU.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-RU.json) |
| 🇿🇦 南非 (South Africa) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/ZA.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/ZA.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-ZA.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-ZA.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-ZA.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-ZA.json) |
| 🇧🇩 孟加拉 (Bangladesh) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BD.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BD.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BD.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BD.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BD.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BD.json) |
| 🇮🇩 印尼 (Indonesia) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/ID.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/ID.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-ID.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-ID.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-ID.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-ID.json) |
| 🇪🇨 EC | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/EC.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/EC.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-EC.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-EC.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-EC.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-EC.json) |
| 🇧🇷 巴西 (Brazil) | 1 | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/BR.txt) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/BR.txt) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/clash-BR.yaml) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/clash-BR.yaml) | [CDN 直链](https://cdn.jsdelivr.net/gh/liushenwa/free-sub@main/output/by-country/singbox-BR.json) · [Raw 直链](https://raw.githubusercontent.com/liushenwa/free-sub/main/output/by-country/singbox-BR.json) |

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
