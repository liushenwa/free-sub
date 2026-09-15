#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 多 URL 探测 (gstatic 204 / cloudflare trace) 
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (吞吐量不足)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
"""

import os
import re
import io
import sys
import json
import time
import uuid
import hashlib
import base64
import shutil
import socket
import zipfile
import tarfile
import platform
import subprocess
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

# 本项目仅使用公开代理池作为节点来源。
# 旧版 VLESS/VMess/Trojan 等 GitHub 免费订阅源已全部移除。
# 协议：HTTP / HTTPS(HTTP CONNECT over TLS) / SOCKS4 / SOCKS5
# 来源标签只用于追踪，不参与“家宽”判定；最终分类仍以实际出口 IP + ASN/ISP/Hosting/风险交叉验证为准。
PROXY_SOURCE_URLS = {
    # HProxy：实时 API，可直接按协议筛选；只取近期、高匿名候选，降低垃圾节点数量。
    "https://hproxy.com/api/proxy-list?format=txt&recent=true&protocol=http&anonymity=elite,anonymous&limit=5000": "http",
    "https://hproxy.com/api/proxy-list?format=txt&recent=true&protocol=https&anonymity=elite,anonymous&limit=5000": "https",
    "https://hproxy.com/api/proxy-list?format=txt&recent=true&protocol=socks4&anonymity=elite,anonymous&limit=5000": "socks4",
    "https://hproxy.com/api/proxy-list?format=txt&recent=true&protocol=socks5&anonymity=elite,anonymous&limit=5000": "socks5",

    # Stormsia：持续验证的公开池。http.txt 同时覆盖 HTTP/HTTPS CONNECT 候选。
    "https://raw.githubusercontent.com/stormsia/proxy-list/main/http.txt": "http",
    "https://raw.githubusercontent.com/stormsia/proxy-list/main/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/stormsia/proxy-list/main/socks5.txt": "socks5",

    # ProxyScrape 官方机器可读镜像。
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/http/data.txt": "http",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/https/data.txt": "https",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks4/data.txt": "socks4",
    "https://cdn.jsdelivr.net/gh/proxyscrape/free-proxy-list@main/proxies/protocols/socks5/data.txt": "socks5",

    # Proxmint。
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/http.txt": "http",
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/https.txt": "https",
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/proxmint/free-proxy-list/main/proxies/socks5.txt": "socks5",

    # IPLocate。
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/http.txt": "http",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/https.txt": "https",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/iplocate/free-proxy-list/main/protocols/socks5.txt": "socks5",

    # Thordata/awesome-free-proxy-list：每日 + 6 小时验证，并提供 top 子集。
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/http.txt": "http",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/https.txt": "https",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/socks5.txt": "socks5",
    # Thordata 精选/稳定集合：包含协议前缀，作为高质量补充，不绕过本项目自己的实测。
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/top-trusted.txt": "http",
    "https://raw.githubusercontent.com/Thordata/awesome-free-proxy-list/main/proxies/stable.txt": "http",

    # Databay：严格 SSL 验证的公开池；其 http.txt 是 CONNECT/HTTPS-capable。
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/http.txt": "http",
    "https://databay.com/api/v1/proxy-list?protocol=https&ssl=strict&format=txt&limit=1000": "https",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/socks5.txt": "socks5",

    # Proxio：约 20 分钟镜像更新。
    "https://raw.githubusercontent.com/proxio-io/proxy-list/main/http.txt": "http",
    "https://raw.githubusercontent.com/proxio-io/proxy-list/main/https.txt": "https",
    "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks4.txt": "socks4",
    "https://raw.githubusercontent.com/proxio-io/proxy-list/main/socks5.txt": "socks5",
}

# 公开代理池很容易达到数万候选；如果全部交给 sing-box 实测，4 小时一轮会非常慢。
# 因此每个“来源文件”最多进入这个数量，且采用稳定 hash 采样，避免每轮随机抖动。
MAX_PROXY_CANDIDATES_PER_SOURCE = 300

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# ══ 测活出口配置（可直接修改） ═══════════════════════════════════════
# 用途：让 GitHub Actions 测试候选代理时，先经过你指定的“测试节点/中转节点”。
#
# 留空 = GitHub Runner 直连测试。
# 填入完整节点 URI = GitHub → 测试节点 → 候选节点 → 测试目标。
# 支持项目已有解析器：VLESS / VMess / Trojan / SS / Hysteria2 / TUIC / AnyTLS。
# 也支持把 Base64 编码后的单条节点直接粘贴进来。
#
# 示例：
# TEST_RELAY_NODE_URI = "tuic://uuid:password@example.com:443?sni=example.com&alpn=h3"
# TEST_RELAY_NODE_URI = "vless://uuid@example.com:443?security=tls&sni=example.com&type=ws&path=%2F#relay"
# TEST_RELAY_NODE_URI = "vmess://BASE64_JSON"
#
# 注意：不要把真实带密码/UUID的节点提交到公开仓库；如果仓库是公开的，
# 推荐把此处改成从 GitHub Actions Secret 读取（后续也可以继续扩展）。
TEST_RELAY_NODE_URI = ""

# GitHub Actions Secret 优先：推荐在仓库 Settings → Secrets and variables → Actions
# 设置 TEST_RELAY_NODE；可选 TEST_RELAY_NODE_2 / TEST_RELAY_NODE_3 作为备用。
# Secret 支持完整 URI 或 Base64 单节点。代码中的 TEST_RELAY_NODE_URI 仅作为备用。
TEST_RELAY_NODE_SECRET_NAMES = ("TEST_RELAY_NODE", "TEST_RELAY_NODE_2", "TEST_RELAY_NODE_3")
_TEST_RELAY_SELECTED_URI = None

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
PROBE_TIMEOUT          = 12      # 活性首击超时 (秒) — 容纳慢启动节点
PROBE_RETRY_TIMEOUT    = 4       # 活性重试超时 (秒) — 死节点快速放弃
PORT_KNOCK_TIMEOUT     = 2.5     # 端口预检超时
IP_ECHO_TIMEOUT        = 6.0     # 出口 IP 检测超时
SPEED_TEST_BYTES       = 2_500_000   # 2.5MB 下载测速 (2.5MB 足以算准吞吐且 < 70KB/s 判定线不变)
SPEED_TEST_BUDGET      = 5.0         # 测速时间预算 (秒) — 2.5MB@70KB/s=36s 必断流, 5s 预算足够判型
SPEED_MIN_BYTES_PER_S  = 70_000      # 吞吐 < 70KB/s 判定断流/不可用 (标准不变)
IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
LIVENESS_URLS = [                    # 活性探测 URL (全部要求代理链路完整)
    "https://www.gstatic.com/generate_204",       # 实测 204 OK
    "https://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
]
SPEED_TEST_URLS = [               # 测速端点多路 (实测部分节点商屏蔽 speed.cloudflare.com)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点
MAX_WORKERS_TEST    = 48            # 同时 sing-box 实测节点数 (Azure 2C7G 实测 24→48 稳定; sing-box 单实例 < 30MB)
MAX_WORKERS_FETCH   = 8
MAX_WORKERS_CLASSIFY = 32

# --- IP 质量过滤 ---
# 分数越高代表出口 IP 越值得保留。家宽仍优先按原有严格规则判断。
MIN_IP_QUALITY_SCORE = 0       # 不再按质量分淘汰普通节点；质量分仅用于排序/参考
MAX_NODES_PER_EXIT_IP = 0     # 0=不限数量；保留所有已测活的非家宽节点
DROP_UNKNOWN_IP_QUALITY = True # 无法确认出口 IP 的节点直接不进入最终订阅
EXCLUDE_BROADCAST_IP = True      # 排除已确认的 BGP Anycast/广播 IP 与明确 CDN 任播出口

# --- 稳定性 / 历史质量 ---
STABILITY_RECHECKS = 2              # 首次活性通过后，再做 2 次轻量复测（共 3 次）
STABILITY_TIMEOUT = 4               # 复测单次超时
MIN_STABILITY_RATE = 0.66           # 稳定率低于 66% 的节点不进入最终订阅
HISTORY_FILE = os.path.join(OUTPUT_DIR, ".node_history.json")
HISTORY_MAX_ENTRIES = 12000
BLACKLIST_FAIL_COUNT = 3            # 连续失败达到 3 次进入冷却黑名单
BLACKLIST_COOLDOWN_HOURS = 24       # 黑名单冷却 24 小时，之后自动重新尝试

# ── 增强 IP/匿名性/风险评分 ──
# 参考 Thordata/Proxmint 的 echo-header 思路，但不把单一数据源当成真值。
ANONOMY_PROBE_URLS = [
    "https://httpbin.org/headers",
    "https://httpbingo.org/headers",
]
ANONOMY_PROBE_TIMEOUT = 6
ANONOMY_PROBE_CONCURRENCY = 12
# 普通节点只做轻量匿名性抽样；家宽候选全部深度检测，降低 Actions 用时。
ANONOMY_ORDINARY_SAMPLE = 100
IP_INTEL_CACHE_FILE = os.path.join(OUTPUT_DIR, "ip-intel-cache.json")
IP_INTEL_CACHE_TTL = 24 * 3600
SCAMALYTICS_CACHE_TTL = 24 * 3600
IPAPI_IS_CACHE_TTL = 24 * 3600
HIGH_RISK_FRAUD_SCORE = 75
VERY_HIGH_RISK_FRAUD_SCORE = 90
# 非家宽只保留“原生出口 IP + 低欺诈”节点。
# 原生 IP 定义：有真实出口 IP，且 ip-api 未标记 hosting/proxy，
# 同时排除 CDN / Anycast / broadcast；fraud 分必须可查询且不高于该阈值。
NONRESIDENTIAL_MAX_FRAUD_SCORE = 30
NONRESIDENTIAL_REQUIRE_NATIVE_IP = True
RESIDENTIAL_MIN_SCORE = 72
PREMIUM_RESIDENTIAL_MIN_SCORE = 90
# 家宽星级：3 星开始进入家宽专区；5 星为“高质量家宽池”并持久保存到仓库。
# 评分是证据置信度，不代表真实住宅身份的绝对证明。
RESIDENTIAL_3STAR_SCORE = 60
RESIDENTIAL_4STAR_SCORE = 75
RESIDENTIAL_5STAR_SCORE = 90
RESIDENTIAL_POOL_FILE = os.path.join(OUTPUT_DIR, "residential-pool.json")
RESIDENTIAL_POOL_MAX_FAILURES = 6
RESIDENTIAL_POOL_MAX_ENTRIES = 1000
RESIDENTIAL_POOL_URIS = set()

LEAK_HEADERS = (
    "x-forwarded-for", "forwarded", "via", "x-real-ip", "client-ip",
    "true-client-ip", "x-client-ip", "cf-connecting-ip", "x-forwarded",
    "forwarded-for", "x-original-forwarded-for",
)
IDC_KEYWORDS_STRONG = (
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle cloud",
    "digitalocean", "vultr", "hetzner", "ovh", "contabo", "leaseweb",
    "linode", "akamai", "fastly", "cloudflare", "bunny", "zenlayer",
    "m247", "gcore", "choopa", "serverius", "clouvider", "datacamp",
    "hostinger", "hostwinds", "hivelocity", "equinix", "rackspace",
    "colocation", "colo", "hosting", "datacenter", "data center", "vps",
    "dedicated server", "server hosting",
)
RESIDENTIAL_KEYWORDS = (
    "broadband", "cable", "fiber", "fibre", "dsl", "adsl", "ftth", "fttx",
    "telecom", "communications", "internet service", "isp", "wireless",
    "mobile", "cellular", "4g", "5g", "lte",
)


# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    54866,  # Parsebian/HydraTransit 类
    45899,  # VNPT 云? 标记为 IDC
    # ★ 实测漏网: 收购家宽段/伪装 DSL rDNS 的云边网络 (ip-api proxy=true 案例补充)
    62610,  # Zenlayer (AS62610, rDNS 带 dsl.speakeasy.net 但 proxy=true)
    60205,  # 62610 关联段
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
}

# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directory(path: str):
    """Ensure path is a directory. Remove a legacy output file with the same name."""
    if os.path.exists(path) and not os.path.isdir(path):
        try:
            os.remove(path)
        except OSError as exc:
            raise RuntimeError(f"Output path exists but is not a directory: {path}: {exc}") from exc
    os.makedirs(path, exist_ok=True)


def ensure_directories():
    # Some older versions of this project created output/by-country and
    # output/residential-by-country as files. Convert those legacy paths
    # to directories automatically so GitHub Actions can upgrade cleanly.
    ensure_directory(OUTPUT_DIR)
    ensure_directory(COUNTRY_DIR)
    ensure_directory(RESIDENTIAL_COUNTRY_DIR)
    ensure_directory(RUNTIME_DIR)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    # 部分订阅生成器会把 UUID:password 中的冒号编码成 %3A；
    # 必须先 URL-decode 再拆分，否则这类合法 TUIC 节点会被误判为无密码。
    userinfo = urllib.parse.unquote(userinfo)
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


def parse_http_proxy(uri: str):
    """解析 HTTP/HTTPS 正向代理；https:// 表示 TLS 包裹的 HTTP CONNECT。"""
    try:
        u = urllib.parse.urlsplit(uri)
        scheme = u.scheme.lower()
        if scheme not in ("http", "https"): return None
        host, port = u.hostname, u.port
        if not host or not port: return None
        out = {"type":"http", "server":host, "server_port":int(port), "proxy_scheme": scheme}
        if u.username is not None: out["username"] = urllib.parse.unquote(u.username)
        if u.password is not None: out["password"] = urllib.parse.unquote(u.password)
        if scheme == "https": out["tls"] = {"enabled":True, "server_name":host}
        return out
    except Exception:
        return None


def parse_socks(uri: str):
    """解析公开 SOCKS4/SOCKS5 URI。公开代理通常没有用户名密码。"""
    try:
        u = urllib.parse.urlsplit(uri)
        scheme = u.scheme.lower()
        if scheme not in ("socks", "socks4", "socks5", "socks5h"):
            return None
        host = u.hostname
        port = u.port
        if not host or not port:
            return None
        out = {
            "type": "socks",
            "server": host,
            "server_port": int(port),
            "version": "4" if scheme == "socks4" else "5",
        }
        if u.username is not None:
            out["username"] = urllib.parse.unquote(u.username)
        if u.password is not None:
            out["password"] = urllib.parse.unquote(u.password)
        return out
    except Exception:
        return None


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
    "http://": parse_http_proxy,
    "https://": parse_http_proxy,
    "socks://": parse_socks,
    "socks4://": parse_socks,
    "socks5://": parse_socks,
    "socks5h://": parse_socks,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)


def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def clash_proxy_to_uri(proxy: dict) -> str | None:
    """把常见 Clash/Mihomo proxy 项转换成项目内部统一的 URI。"""
    if not isinstance(proxy, dict):
        return None
    typ = str(proxy.get("type", "")).lower().strip()
    name = str(proxy.get("name", "node")).strip() or "node"
    server = str(proxy.get("server", "")).strip()
    port = proxy.get("port")
    if not server or not port:
        return None
    try:
        port = int(port)
    except Exception:
        return None

    def q(params):
        return urllib.parse.urlencode({k: v for k, v in params.items() if v not in (None, "", False)})

    if typ == "vless":
        uuid = proxy.get("uuid") or proxy.get("password")
        if not uuid:
            return None
        params = {"type": proxy.get("network", "tcp"),
                  "security": "tls" if proxy.get("tls") else "none",
                  "sni": proxy.get("servername") or proxy.get("sni"),
                  "fp": proxy.get("client-fingerprint")}
        if proxy.get("tls") and proxy.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if proxy.get("network") == "ws":
            ws = proxy.get("ws-opts") or {}
            params["path"] = ws.get("path", "/")
            headers = ws.get("headers") or {}
            if headers.get("Host"):
                params["host"] = headers["Host"]
        elif proxy.get("network") == "grpc":
            go = proxy.get("grpc-opts") or {}
            params["serviceName"] = go.get("grpc-service-name")
        ro = proxy.get("reality-opts") or {}
        if ro:
            params["security"] = "reality"
            params["pbk"] = ro.get("public-key")
            params["sid"] = ro.get("short-id")
        return "vless://%s@%s:%d?%s#%s" % (urllib.parse.quote(str(uuid), safe=""), server, port, q(params), urllib.parse.quote(name, safe=""))

    if typ == "vmess":
        obj = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": proxy.get("uuid", ""), "aid": str(proxy.get("alterId", proxy.get("alter-id", 0))),
            "scy": proxy.get("cipher", "auto"), "net": proxy.get("network", "tcp"),
            "type": proxy.get("type", "none"), "host": "", "path": "", "tls": ""
        }
        if proxy.get("tls"):
            obj["tls"] = "tls"
            obj["sni"] = proxy.get("servername") or proxy.get("sni", "")
        if proxy.get("network") == "ws":
            ws = proxy.get("ws-opts") or {}
            obj["path"] = ws.get("path", "/")
            obj["host"] = (ws.get("headers") or {}).get("Host", "")
        raw = base64.b64encode(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        return "vmess://" + raw

    if typ == "trojan":
        password = proxy.get("password")
        if not password:
            return None
        params = {"security": "tls", "sni": proxy.get("servername") or proxy.get("sni"),
                  "type": proxy.get("network", "tcp"), "fp": proxy.get("client-fingerprint")}
        if proxy.get("skip-cert-verify"):
            params["allowInsecure"] = "1"
        if proxy.get("network") == "ws":
            ws = proxy.get("ws-opts") or {}
            params["path"] = ws.get("path", "/")
            params["host"] = (ws.get("headers") or {}).get("Host")
        return "trojan://%s@%s:%d?%s#%s" % (urllib.parse.quote(str(password), safe=""), server, port, q(params), urllib.parse.quote(name, safe=""))

    if typ in ("ss", "shadowsocks"):
        method = proxy.get("cipher") or proxy.get("method")
        password = proxy.get("password")
        if not method or password is None:
            return None
        user = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
        return "ss://%s@%s:%d#%s" % (user, server, port, urllib.parse.quote(name, safe=""))

    if typ in ("hysteria2", "hy2"):
        password = proxy.get("password") or proxy.get("auth")
        if not password:
            return None
        params = {"sni": proxy.get("sni") or proxy.get("servername"), "insecure": "1" if proxy.get("skip-cert-verify") else None}
        return "hysteria2://%s@%s:%d?%s#%s" % (urllib.parse.quote(str(password), safe=""), server, port, q(params), urllib.parse.quote(name, safe=""))

    if typ == "tuic":
        uuid, password = proxy.get("uuid"), proxy.get("password")
        if not uuid or password is None:
            return None
        params = {"sni": proxy.get("sni") or proxy.get("servername"), "insecure": "1" if proxy.get("skip-cert-verify") else None}
        return "tuic://%s:%s@%s:%d?%s#%s" % (urllib.parse.quote(str(uuid), safe=""), urllib.parse.quote(str(password), safe=""), server, port, q(params), urllib.parse.quote(name, safe=""))

    if typ == "anytls":
        password = proxy.get("password")
        if not password:
            return None
        params = {"sni": proxy.get("sni") or proxy.get("servername"), "insecure": "1" if proxy.get("skip-cert-verify") else None}
        return "anytls://%s@%s:%d?%s#%s" % (urllib.parse.quote(str(password), safe=""), server, port, q(params), urllib.parse.quote(name, safe=""))

    if typ in ("socks5", "socks4", "socks"):
        version = "4" if typ == "socks4" else "5"
        auth = ""
        if proxy.get("username") is not None:
            auth = urllib.parse.quote(str(proxy.get("username")), safe="")
            if proxy.get("password") is not None:
                auth += ":" + urllib.parse.quote(str(proxy.get("password")), safe="")
            auth += "@"
        return f"socks{version}://{auth}{server}:{port}#{urllib.parse.quote(name, safe='')}"

    return None


def extract_nodes_from_clash_yaml(text: str) -> set:
    """从 Clash/Mihomo YAML 的 proxies 列表提取 URI。"""
    results = set()
    try:
        data = yaml.safe_load(text)
    except Exception:
        return results
    if not isinstance(data, dict):
        return results
    for proxy in data.get("proxies") or []:
        uri = clash_proxy_to_uri(proxy)
        if uri and parse_node_uri(uri):
            results.add(uri)
    return results


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    # 优先识别 Clash/Mihomo YAML；普通 URI/Base64 继续走原有逻辑
    if "proxies:" in text[:20000] and ("proxy-groups:" in text or "allow-lan:" in text):
        results.update(extract_nodes_from_clash_yaml(text))
        if results:
            return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh|http|https|socks|socks4|socks5|socks5h)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def extract_bare_proxy_nodes(text: str, default_scheme: str = "socks5") -> set:
    """提取公开代理源中的裸 IP:PORT，并按源协议转换；也兼容已有 protocol:// 前缀。"""
    results=set(); default_scheme=(default_scheme or "socks5").lower()
    if default_scheme not in ("http","https","socks4","socks5"): default_scheme="socks5"
    for line in (text or "").splitlines():
        line=line.strip().strip('"\' ,;')
        if not line or line.startswith('#'): continue
        if line.lower().startswith(("http://","https://","socks://","socks4://","socks5://","socks5h://")):
            uri=line.split('#',1)[0]
        else:
            m=re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})",line)
            if not m: continue
            try:
                ip=ipaddress.ip_address(m.group(1)); port=int(m.group(2))
                if ip.version!=4 or not 1<=port<=65535: continue
            except Exception: continue
            uri=f"{default_scheme}://{m.group(1)}:{port}"
        if parse_node_uri(uri): results.add(uri)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部公开代理源（旧版节点订阅源已禁用） ...")

    all_urls = [(u, True) for u in PROXY_SOURCE_URLS]

    def _fetch(item):
        url, is_public_proxy = item
        last_err = None
        # 重试 2 次 (网络抖动/GFW 间歇性重置; 退避 3s)
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_bare_proxy_nodes(r.text, PROXY_SOURCE_URLS.get(url, "socks5"))
                    # 稳定 hash 采样：每个来源只把有限数量送入后续 TCP/sing-box 测活。
                    # 不按文件头部截断，避免某些来源长期偏向固定国家/IP 段。
                    if len(got) > MAX_PROXY_CANDIDATES_PER_SOURCE:
                        import hashlib
                        got = set(sorted(got, key=lambda x: hashlib.sha256(
                            (url + "\0" + x).encode("utf-8", "ignore")).hexdigest())[:MAX_PROXY_CANDIDATES_PER_SOURCE])
                    return url, got, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, item) for item in all_urls]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                kind = f"公开 {PROXY_SOURCE_URLS.get(url, '代理').upper()}" if url in PROXY_SOURCE_URLS else "订阅"
                print(f"[+] {kind}: {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}
# 本轮端口预检结果：按节点身份记录，供最终统计“预检未过但最终入选”的比例。
PRECHECK_PASSED_KEYS = set()
PRECHECK_DEFERRED_KEYS = set()

def resolve_host(host: str) -> str:
    """DoH 解析 (带本地缓存); 失败退回系统 DNS"""
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    # 1) DoH (Cloudflare 1.1.1.1, 走 DIRECT_SESSION 可过墙)
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer") or []
            for a in answers:
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    # 2) 系统 DNS 兜底
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """TCP 直连预检 (DoH 解析防本地 DNS 污染); QUIC 类直接放行阶段B
    注: 预检失败不淘汰 (本地大陆视角的假死 ≠ 节点死亡), 只影响排序;
        生死由阶段B sing-box 全流程测活裁决 (Actions 海外视角)"""
    if protocol_type in ("hysteria2", "tuic"):
        # QUIC 无法轻量预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 放行交阶段B
        return True
    try:
        ip = resolve_host(server)
        if not ip:
            return False
        with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
            return True
    except Exception:
        return False


def prefilter_candidates(candidates: list) -> list:
    """端口预检: 通过者优先, 未通过者降级保留 (防止本地网络/GFW 视角误杀;
    真正生死由阶段B sing-box 全流程测活裁决 — Actions 海外视角)"""
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s): {len(candidates)} 候选 ...")
    passed, deferred = [], []

    def _knock(item):
        raw, outbound, server, port, proto = item
        return knock_port(server, port, proto)

    global PRECHECK_PASSED_KEYS, PRECHECK_DEFERRED_KEYS
    PRECHECK_PASSED_KEYS = set()
    PRECHECK_DEFERRED_KEYS = set()
    with ThreadPoolExecutor(max_workers=64) as ex:
        # ex.map 保序返回; 通过者优先, 未通过降级保留 (不淘汰, 防本地视角误杀)
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            key = node_identity_key(item[0], item[2], item[3], item[4])
            if ok:
                passed.append(item)
                PRECHECK_PASSED_KEYS.add(key)
            else:
                deferred.append(item)
                PRECHECK_DEFERRED_KEYS.add(key)
    print(f"[+] 预检通过: {len(passed)} | 预检未过(保留低优先级待全测): {len(deferred)}")
    # 预检未过的仍进入全流程 (只是排在后面) — 交给 sing-box 真实裁决
    return passed + deferred


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def normalize_test_relay_uri(value: str) -> str:
    """允许直接粘贴普通 URI 或 Base64 编码的单条节点。"""
    value = (value or "").strip()
    if not value:
        return ""
    if any(value.startswith(prefix) for prefix in PARSERS):
        return value
    decoded = b64_decode(value)
    decoded = decoded.strip()
    if any(decoded.startswith(prefix) for prefix in PARSERS):
        return decoded
    return value


def get_test_relay_uri() -> str:
    """Secret 优先选择测试中转节点；支持 3 个候选，代码配置作为最后备用。"""
    global _TEST_RELAY_SELECTED_URI
    if _TEST_RELAY_SELECTED_URI is not None:
        return _TEST_RELAY_SELECTED_URI

    for secret_name in TEST_RELAY_NODE_SECRET_NAMES:
        value = os.environ.get(secret_name, "").strip()
        if not value:
            continue
        uri = normalize_test_relay_uri(value)
        if uri and parse_node_uri(uri):
            _TEST_RELAY_SELECTED_URI = uri
            print(f"[+] 已从 GitHub Secret {secret_name} 读取测试中转节点。")
            return uri
        print(f"[!] GitHub Secret {secret_name} 已设置，但节点无法解析，继续尝试下一个备用节点。")

    uri = normalize_test_relay_uri(TEST_RELAY_NODE_URI)
    if uri and parse_node_uri(uri):
        _TEST_RELAY_SELECTED_URI = uri
        print("[+] 已使用代码中的 TEST_RELAY_NODE_URI 作为测试中转备用节点。")
        return uri

    _TEST_RELAY_SELECTED_URI = ""
    return ""


def get_test_relay_outbound() -> dict | None:
    """读取并解析测试中转节点；Secret 优先，失败后使用下一个 Secret/代码备用。"""
    uri = get_test_relay_uri()
    if not uri:
        return None
    parsed = parse_node_uri(uri)
    if not parsed:
        return None
    outbound, server, port, proto = parsed
    relay = dict(outbound)
    relay.pop("detour", None)
    relay["tag"] = "test-relay"
    print_once("_TEST_RELAY_ENABLED",
               f"[*] 测活中转已启用: {proto}://{server}:{port} → GitHub → 中转 → 候选节点 → 目标")
    return relay


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 用户指定测试中转节点 ═════════════════════════════════════════
    # 优先级：chain_relay（内部家宽双跳复测） > TEST_RELAY_NODE_URI。
    # TEST_RELAY_NODE_URI 支持 VLESS/VMess/Trojan/SS/HY2/TUIC/AnyTLS。
    if not chain_relay:
        test_relay = get_test_relay_outbound()
        if test_relay:
            outbounds.append(test_relay)
            node["detour"] = "test-relay"

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    front = os.environ.get("FRONT_PROXY", "").strip()
    if front and not chain_relay and not get_test_relay_outbound():
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def node_identity_key(raw_or_outbound, server=None, port=None, proto=None):
    """生成稳定节点身份指纹：目标 + 协议 + 核心凭据。
    同一节点换名字/来源不会被误认为新节点；不同凭据不会错误合并。
    """
    try:
        if isinstance(raw_or_outbound, str):
            parsed = parse_node_uri(raw_or_outbound)
            if not parsed:
                return hashlib.sha1(raw_or_outbound.encode()).hexdigest()
            outbound, server, port, proto = parsed
        else:
            outbound = raw_or_outbound
        if proto == "vless":
            cred = outbound.get("uuid", "")
        elif proto == "vmess":
            cred = outbound.get("uuid", "") or outbound.get("user_id", "")
        elif proto == "trojan":
            cred = outbound.get("password", "")
        elif proto == "shadowsocks":
            cred = f"{outbound.get('method','')}|{outbound.get('password','')}"
        elif proto == "hysteria2":
            cred = f"{outbound.get('password','')}|{outbound.get('server_ports','')}"
        elif proto == "tuic":
            cred = f"{outbound.get('uuid','')}|{outbound.get('password','')}"
        elif proto == "anytls":
            cred = outbound.get("password", "")
        elif proto == "socks":
            cred = f"{outbound.get('version','5')}|{outbound.get('username','')}|{outbound.get('password','')}"
        else:
            cred = json.dumps({k: outbound.get(k) for k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        raw = f"{(server or '').lower()}|{port or ''}|{proto or ''}|{cred}"
        return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()
    except Exception:
        raw = str(raw_or_outbound)
        return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


def load_node_history():
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"nodes": {}, "active": [], "last_run": ""}
        data.setdefault("nodes", {})
        data.setdefault("active", [])
        data.setdefault("last_run", "")
        return data
    except Exception:
        return {"nodes": {}, "active": [], "last_run": ""}


def save_node_history(history):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    nodes = history.get("nodes", {})
    if len(nodes) > HISTORY_MAX_ENTRIES:
        items = sorted(nodes.items(), key=lambda kv: kv[1].get("last_seen", ""), reverse=True)[:HISTORY_MAX_ENTRIES]
        history["nodes"] = dict(items)
    tmp = HISTORY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(history, f, ensure_ascii=False, indent=2)
    os.replace(tmp, HISTORY_FILE)


def load_residential_pool():
    """读取历史 5 星家宽池。池内节点即使本轮公开源暂时消失，也会继续参与测活。"""
    global RESIDENTIAL_POOL_URIS
    RESIDENTIAL_POOL_URIS = set()
    try:
        with open(RESIDENTIAL_POOL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        items = data.get("nodes", []) if isinstance(data, dict) else []
        valid = []
        for item in items:
            raw = str(item.get("raw") or "").strip()
            if not raw or not parse_node_uri(raw):
                continue
            valid.append(item)
            RESIDENTIAL_POOL_URIS.add(raw)
        print(f"[*] 读取历史五星家宽池: {len(valid)} 个，将强制重新测活")
        return valid
    except FileNotFoundError:
        return []
    except Exception as e:
        print(f"[!] 读取历史家宽池失败: {e}")
        return []


def merge_residential_pool(raw_nodes, pool_nodes):
    """将历史五星家宽 URI 注入本轮候选；公开源与历史池重复时自动去重。"""
    if not pool_nodes:
        return raw_nodes
    existing = set(raw_nodes)
    added = 0
    for item in pool_nodes:
        raw = str(item.get("raw") or "").strip()
        if raw and raw not in existing:
            raw_nodes.append(raw)
            existing.add(raw)
            added += 1
    if added:
        print(f"[+] 历史五星家宽补充候选: +{added}")
    return raw_nodes


def residential_stars(score):
    """将家宽置信度映射为 0~5 星；3 星及以上进入家宽订阅。"""
    try:
        score = int(score or 0)
    except Exception:
        score = 0
    if score >= RESIDENTIAL_5STAR_SCORE:
        return 5
    if score >= RESIDENTIAL_4STAR_SCORE:
        return 4
    if score >= RESIDENTIAL_3STAR_SCORE:
        return 3
    if score >= 45:
        return 2
    if score >= 30:
        return 1
    return 0


def update_residential_pool(current_nodes, test_results):
    """动态维护 5 星家宽池。成功且仍为 5 星就更新；连续失败达到阈值才移除。"""
    old = {}
    try:
        with open(RESIDENTIAL_POOL_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for item in (data.get("nodes", []) if isinstance(data, dict) else []):
            raw = str(item.get("raw") or "").strip()
            if raw:
                old[node_identity_key(raw)] = dict(item)
    except Exception:
        pass

    current_5 = {}
    for n in current_nodes:
        if int(n.get("residential_stars", 0)) >= 5:
            rec = {
                "raw": n.get("raw", ""),
                "server": n.get("server"), "port": n.get("port"), "proto": n.get("proto"),
                "exit_ip": n.get("exit_ip"), "country": n.get("country"),
                "net_type": n.get("net_type"), "residential_score": n.get("residential_score"),
                "residential_stars": n.get("residential_stars"),
                "anonymity": n.get("anonymity"), "anonymity_score": n.get("anonymity_score"),
                "risk_score": n.get("risk_score"), "fraud_score": n.get("fraud_score", -1),
                "stability_rate": n.get("stability_rate"), "survival_streak": n.get("survival_streak", 0),
                "latency_ms": n.get("latency_ms"), "speed_bps": n.get("speed_bps"),
                "overall_score": n.get("overall_score"),
                "source": n.get("source", ""),
                "last_verified": datetime.now(timezone.utc).isoformat(),
                "consecutive_failures": 0,
            }
            current_5[node_identity_key(rec["raw"])] = rec

    result_by_key = {node_identity_key(r.get("raw", "")): r for r in test_results}
    merged = dict(current_5)
    removed = 0
    for key, rec in old.items():
        if key in current_5:
            continue
        r = result_by_key.get(key)
        if r is not None:
            # 本轮明确测过但没有重新达到 5 星：连续失败/降级计数。
            fails = int(rec.get("consecutive_failures", 0) or 0) + (0 if r.get("alive") else 1)
            if r.get("alive") and not r.get("is_stalled"):
                # 活着但星级下降，保留一次观察；连续两次仍非 5 星再清掉。
                fails = max(1, fails)
            rec["consecutive_failures"] = fails
            rec["last_checked"] = datetime.now(timezone.utc).isoformat()
            if fails >= RESIDENTIAL_POOL_MAX_FAILURES:
                removed += 1
                continue
            merged[key] = rec
        else:
            # 本轮没测到（例如历史黑名单/临时源异常），暂时保留。
            merged[key] = rec

    items = sorted(merged.values(), key=lambda x: (-int(x.get("residential_stars", 0)), -int(x.get("overall_score", 0)), x.get("latency_ms", 99999)))
    items = items[:RESIDENTIAL_POOL_MAX_ENTRIES]
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    tmp = RESIDENTIAL_POOL_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "description": "动态五星家宽候选池；下次运行会优先读取并重新测活。连续失败达到阈值自动移除。",
            "max_failures": RESIDENTIAL_POOL_MAX_FAILURES,
            "nodes": items,
        }, f, ensure_ascii=False, indent=2)
    os.replace(tmp, RESIDENTIAL_POOL_FILE)
    global RESIDENTIAL_POOL_URIS
    RESIDENTIAL_POOL_URIS = {str(x.get("raw")) for x in items if x.get("raw")}
    print(f"[*] 五星家宽池更新: {len(items)} 个 | 新增/刷新 {len(current_5)} | 移除 {removed}")
    return items


def filter_blacklisted_candidates(candidates, history):
    """跳过短期内连续失败节点，减少每 4 小时重复消耗 CI 时间。"""
    now = time.time()
    kept, skipped = [], 0
    for item in candidates:
        key = node_identity_key(item[1], item[2], item[3], item[4])
        rec = history.get("nodes", {}).get(key, {})
        fail_count = int(rec.get("fail_count", 0) or 0)
        last_fail = float(rec.get("last_fail_ts", 0) or 0)
        if item[0] in RESIDENTIAL_POOL_URIS:
            # 历史五星家宽是重点资产：每轮都重新测活，不受普通失败冷却影响。
            kept.append(item)
            continue
        if fail_count >= BLACKLIST_FAIL_COUNT and last_fail and now - last_fail < BLACKLIST_COOLDOWN_HOURS * 3600:
            skipped += 1
            continue
        kept.append(item)
    if skipped:
        print(f"[*] 历史失败黑名单: 跳过 {skipped} 个节点（连续失败≥{BLACKLIST_FAIL_COUNT}，冷却 {BLACKLIST_COOLDOWN_HOURS}h）")
    return kept


def update_node_history(history, tested_candidates, test_results):
    """更新连续失败、成功次数、最后延迟/质量，并返回本轮身份统计。"""
    now = time.time()
    stamp = datetime.now(timezone.utc).isoformat()
    nodes = history.setdefault("nodes", {})
    success_keys = set()
    result_by_key = {}
    for r in test_results:
        key = node_identity_key(r.get("raw", ""))
        result_by_key[key] = r
        if r.get("alive") and not r.get("is_stalled") and not r.get("mitm_risk") and r.get("exit_ip"):
            success_keys.add(key)
    tested_keys = set()
    for item in tested_candidates:
        key = node_identity_key(item[1], item[2], item[3], item[4])
        tested_keys.add(key)
        rec = nodes.setdefault(key, {})
        rec["last_seen"] = stamp
        rec["last_test_ts"] = now
        if key in success_keys:
            rec["fail_count"] = 0
            rec["success_count"] = int(rec.get("success_count", 0) or 0) + 1
            # 连续存活轮次：每 4 小时成功一次。用于稳定节点精选，不代表绝对可靠。
            rec["survival_streak"] = int(rec.get("survival_streak", 0) or 0) + 1
            r = result_by_key.get(key, {})
            rec["last_success"] = stamp
            rec["last_latency_ms"] = r.get("latency_ms", 99999)
        else:
            rec["fail_count"] = int(rec.get("fail_count", 0) or 0) + 1
            rec["survival_streak"] = 0
            rec["last_fail_ts"] = now
            rec["last_failure"] = stamp
    return tested_keys, success_keys


def build_run_report(previous_active, current_nodes, test_results, candidates_count, raw_count, parsed_count, residential_count, nonresidential_count):
    prev = set(previous_active or [])
    final_res_deferred = 0
    final_nonres_deferred = 0
    for n in current_nodes:
        key = node_identity_key(n.get("raw", ""))
        if key in PRECHECK_DEFERRED_KEYS:
            if n in []:
                pass
            elif n.get("net_type") in ("residential", "mobile"):
                final_res_deferred += 1
            else:
                final_nonres_deferred += 1
    deferred_total = len(PRECHECK_DEFERRED_KEYS)
    precheck_stats = {
        "passed": len(PRECHECK_PASSED_KEYS),
        "deferred": deferred_total,
        "deferred_to_residential": final_res_deferred,
        "deferred_to_nonresidential": final_nonres_deferred,
        "deferred_residential_selection_rate": round(final_res_deferred / deferred_total * 100, 2) if deferred_total else 0,
        "deferred_nonresidential_selection_rate": round(final_nonres_deferred / deferred_total * 100, 2) if deferred_total else 0,
        "deferred_to_final_selection": final_res_deferred + final_nonres_deferred,
        "deferred_final_selection_rate": round((final_res_deferred + final_nonres_deferred) / deferred_total * 100, 2) if deferred_total else 0,
        "residential_share_of_final": round(final_res_deferred / residential_count * 100, 2) if residential_count else 0,
        "nonresidential_share_of_final": round(final_nonres_deferred / nonresidential_count * 100, 2) if nonresidential_count else 0,
    }
    current = {node_identity_key(n.get("raw", "")) for n in current_nodes}
    new_nodes = current - prev
    disappeared = prev - current
    proto = {}
    seen_results = set()
    for r in test_results:
        # 回填重复节点后，同一身份可能出现多次；统计时只计算代表节点，避免成功率被重复来源扭曲。
        rid = node_identity_key(r.get("raw", ""))
        if rid in seen_results:
            continue
        seen_results.add(rid)
        p = r.get("proto", "unknown")
        st = proto.setdefault(p, {"tested": 0, "success": 0})
        st["tested"] += 1
        if r.get("alive") and not r.get("is_stalled") and not r.get("mitm_risk"):
            st["success"] += 1
    for st in proto.values():
        st["success_rate"] = round(st["success"] / st["tested"] * 100, 1) if st["tested"] else 0
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "raw_sources_nodes": raw_count,
        "parsed_candidates": parsed_count,
        "tested_candidates": candidates_count,
        "test_results": len(test_results),
        "final_nodes": len(current_nodes),
        "residential_nodes": residential_count,
        "non_residential_nodes": nonresidential_count,
        "precheck_stats": precheck_stats,
        "new_nodes": len(new_nodes),
        "disappeared_nodes": len(disappeared),
        "protocol_stats": proto,
        "new_node_ids": sorted(new_nodes),
        "disappeared_node_ids": sorted(disappeared),
    }


def write_run_report(report):
    path = os.path.join(OUTPUT_DIR, "run_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)


def print_run_report(report):
    print("\n===== 本轮智能质量报告 =====")
    print(f"新增节点: {report['new_nodes']} | 消失节点: {report['disappeared_nodes']}")
    print(f"最终节点: {report['final_nodes']} | 家宽/移动: {report['residential_nodes']} | 非家宽: {report.get('non_residential_nodes', 0)}")
    ps = report.get("precheck_stats", {})
    if ps:
        print(f"预检未过: {ps.get('deferred', 0)} | 最终入选: {ps.get('deferred_to_final_selection', 0)} "
              f"({ps.get('deferred_final_selection_rate', 0):.2f}%) | 家宽 {ps.get('deferred_to_residential', 0)} "
              f"({ps.get('deferred_residential_selection_rate', 0):.2f}%) | 非家宽 {ps.get('deferred_to_nonresidential', 0)} "
              f"({ps.get('deferred_nonresidential_selection_rate', 0):.2f}%)")
    print("协议成功率:")
    for proto, st in sorted(report["protocol_stats"].items()):
        print(f"  {proto:<14} {st['success']:>4}/{st['tested']:<4} = {st['success_rate']:>5.1f}%")


def test_single_node(item, keep_alive_check=True):
    """返回 dict 或 None; 含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM"""
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

    # ★ 链式前置 (chain relay): 注入已验证存活节点作前置 (chain_retest 用, 模拟 v2rayN 链式)
    chain_out = None
    chain_json = os.environ.get("CHAIN_RELAY_OUT", "").strip()
    if chain_json:
        try:
            chain_out = json.loads(chain_json)
        except Exception:
            chain_out = None
    config = build_test_config(outbound, socks_port, chain_relay=chain_out)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    # --- 0) sing-box check 预校验: 快速淘汰 schema 错误 (实测可发现 2022 密钥长度/端口区间等错误) ---
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return None  # 配置级错误 → 该节点无法被 sing-box 使用, 必淘汰
    except Exception:
        pass  # check 本身失败不阻止后续 run 尝试

    proc = None
    result = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        # 等 SOCKS 端口就绪 (主动探测而非盲 sleep — 修复旧版误杀)
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # 进程崩溃 (配置错误/端口冲突)
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测: 分层超时重试 (首击宽 12s 容慢节点保准确率; 重试窄 4s 快速放弃死节点) ---
        alive_hits, latency_ms = 0, 99999
        t0 = time.time()
        for i, url in enumerate(LIVENESS_URLS):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in (204, 200):
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t0) * 1000)
                    break  # 任一成功即可
            except Exception:
                continue
        if alive_hits == 0:
            return None

        # --- 1.5) 轻量稳定性复测：同一 sing-box 进程连续复测，避免“一次碰巧成功” ---
        stability_hits = 1
        for _ in range(STABILITY_RECHECKS):
            try:
                rr = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                       timeout=STABILITY_TIMEOUT, allow_redirects=False)
                if rr.status_code in (204, 200):
                    stability_hits += 1
            except Exception:
                pass
        stability_rate = stability_hits / float(STABILITY_RECHECKS + 1)

        # --- 2) 真实出口 IP (多路冗余) ---
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        # --- 3) MITM 劫持检测 (轻量: 复用活性首击的 gstatic 请求已验证证书链) ---
        # 3a) 独立复检一次带 verify=True 的请求: SSLError = TLS 拦截
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code in (204, 200):
                mitm_risk = False
            else:
                mitm_risk = r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
        except requests.exceptions.SSLError:
            # 证书链验证失败 = TLS 拦截 (MITM) 或劣质自签劫持
            mitm_risk = True
        except Exception:
            pass  # 网络层失败不算 MITM (活性探测已通过)

        # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 降权标记) — 4s 窄超时
        is_warp = False
        try:
            r = PROBE_SESSION.get(TRACE_URL, proxies=proxies, timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code == 200:
                if re.search(r"^warp=on", r.text, re.M):
                    is_warp = True
        except Exception:
            pass

        # --- 4) 断流检测: 限时下载测速 (chunked 读 + 空闲计时; 多端点兜底防测速站被屏蔽) ---
        # 断流签名: 连接建立且首包正常, 但中途停止送数据 → 空闲超时强断
        speed_bps = 0
        for speed_url in SPEED_TEST_URLS:
            downloaded = 0
            t_speed = time.time()
            last_chunk_time = time.time()
            try:
                with PROBE_SESSION.get(speed_url, proxies=proxies,
                                       timeout=(5, SPEED_TEST_BUDGET), stream=True) as r:
                    if r.status_code == 200:
                        for chunk in r.iter_content(chunk_size=65536):
                            now = time.time()
                            if chunk:
                                downloaded += len(chunk)
                                last_chunk_time = now
                            # 总预算超限 → 正常截断 (拿已有数据算吞吐)
                            if now - t_speed > SPEED_TEST_BUDGET:
                                break
                            # 空闲 > 3s 无任何数据 → 断流签名, 立即中止
                            if now - last_chunk_time > 3.0:
                                break
                elapsed = max(time.time() - t_speed, 0.001)
                if downloaded > 0:
                    speed_bps = int(downloaded / elapsed)
                    break  # 首个成功端点的结果即有效
            except Exception:
                continue
        # 全部端点都失败 (下载0字节) → 视为断流 (活性已过但无法承载数据流)

        # 断流判定: 连 70KB/s 都达不到 → 断流/极慢, 真实不可用
        is_stalled = speed_bps < SPEED_MIN_BYTES_PER_S

        result = {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            "alive": True,
            "latency_ms": int(latency_ms),
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "is_warp": is_warp,
            "speed_bps": speed_bps,
            "is_stalled": is_stalled,
            "stability_hits": stability_hits,
            "stability_total": STABILITY_RECHECKS + 1,
            "stability_rate": stability_rate,
            "https_ok": True,
            "anonymity": "unknown",
            "header_leaks": [],
            "anonymity_probe_count": 0,
        }
        return result
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]

    def _work(item):
        return test_single_node(item)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {len(results)}")

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} | MITM 风险 {mitm}")
    return results  # 保留全部信息, 分类阶段再决定去留


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips, intel_cache)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile") and c >= 60:
            res_candidates[(r["server"].lower(), r["port"], r["proto"])] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"]) not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        for key, r in res_candidates.items():
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                chain_dead.append(r)
                continue
            recheck = test_single_node(item)
            if recheck and recheck.get("alive") and not recheck.get("is_stalled"):
                chain_alive.append(r)
            else:
                chain_dead.append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    for r in chain_dead:
        r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def _load_ip_intel_cache() -> dict:
    try:
        if not os.path.exists(IP_INTEL_CACHE_FILE):
            return {}
        with open(IP_INTEL_CACHE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_ip_intel_cache(cache: dict):
    try:
        # 防止长期运行导致缓存无限增长；保留最近 10,000 个 IP。
        if len(cache) > 10000:
            ranked = sorted(cache.items(), key=lambda kv: max(
                float((v or {}).get("ts", 0) or 0)
                for v in (kv[1].values() if isinstance(kv[1], dict) else [])
            ), reverse=True)
            cache.clear()
            cache.update(dict(ranked[:10000]))
        tmp = IP_INTEL_CACHE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, IP_INTEL_CACHE_FILE)
    except Exception as e:
        print(f"[!] IP 情报缓存保存失败: {e}")


def _cache_get(cache: dict, ip: str, field: str, ttl: int):
    rec = cache.get(ip) or {}
    item = rec.get(field)
    if not isinstance(item, dict):
        return None
    ts = float(item.get("ts", 0) or 0)
    if ts and time.time() - ts <= ttl:
        return item.get("value")
    return None


def _cache_put(cache: dict, ip: str, field: str, value):
    rec = cache.setdefault(ip, {})
    rec[field] = {"ts": time.time(), "value": value}


def ip_api_batch_lookup(ip_list: list, cache: dict | None = None) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min)。优先读取 24h 本地缓存。"""
    cache = cache if cache is not None else {}
    info = {}
    pending = []
    for ip in ip_list:
        cached = _cache_get(cache, ip, "ip_api", IP_INTEL_CACHE_TTL)
        if cached is not None:
            info[ip] = cached
        else:
            pending.append(ip)
    if not pending:
        print(f"[*] ip-api 缓存命中: {len(info)}/{len(ip_list)}，无需联网查询")
        return info
    print(f"[*] ip-api 缓存命中 {len(info)}/{len(ip_list)}，本轮实际查询 {len(pending)} 个 IP")
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                            _cache_put(cache, q, "ip_api", rec)
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def cached_scamalytics_fraud_score(ip: str, cache: dict) -> int:
    cached = _cache_get(cache, ip, "scamalytics", SCAMALYTICS_CACHE_TTL)
    if cached is not None:
        return int(cached)
    score = scamalytics_fraud_score(ip)
    if score >= 0:
        _cache_put(cache, ip, "scamalytics", int(score))
    return score


def cached_ipapi_is_verify(ip: str, cache: dict) -> dict:
    cached = _cache_get(cache, ip, "ipapi_is", IPAPI_IS_CACHE_TTL)
    if cached is not None:
        return cached if isinstance(cached, dict) else {}
    info = ipapi_is_verify(ip)
    if info:
        _cache_put(cache, ip, "ipapi_is", info)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def is_broadcast_ip(ip: str, org: str = "", ip_api_rec: dict = None) -> bool:
    """判断出口 IP 是否属于明确的广播/Anycast/任播网络。

    只使用高置信度信号，避免把普通 IDC 错杀：
      1) Cloudflare 官方 Anycast 网段；
      2) 在线 ISP/ORG/ASN/反向 DNS 明确出现 anycast/broadcast/cdn/edge 等任播特征。
    普通数据中心 IP 不会仅因为是 IDC 就被视为广播 IP。
    """
    if not ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(str(ip))
    except ValueError:
        return False

    # Cloudflare 官方 IPv4 Anycast 网段：明确属于任播网络。
    if any(ip_obj in net for net in CLOUDFLARE_IP_NETWORKS):
        return True

    rec = ip_api_rec or {}
    parts = [
        str(org or ""),
        str(rec.get("asname") or ""),
        str(rec.get("org") or ""),
        str(rec.get("isp") or ""),
        str(rec.get("reverse") or ""),
    ]
    text = " ".join(parts).lower()
    strong_anycast = (
        "anycast" in text
        or "broadcast" in text
        or "anycast network" in text
        or "anycast ip" in text
        or "anycast address" in text
    )
    return strong_anycast


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, broadcast, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) 广播/Anycast 与 CDN 网段 (硬判据)
    # Cloudflare 官方网段属于明确 Anycast，单独标记为 broadcast。
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "broadcast", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if is_broadcast_ip(ip_str, org_lower, ip_api_rec):
        return "broadcast", 98

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict"""
    t = node.get("type")
    server, port = node["server"], node["server_port"]
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    elif t == "socks":
        proxy["type"] = "socks5" if str(node.get("version", "5")) != "4" else "socks4"
        if node.get("username") is not None:
            proxy["username"] = node.get("username")
        if node.get("password") is not None:
            proxy["password"] = node.get("password")
    elif t == "http":
        # HTTP/HTTPS 正向代理；HTTPS 代理通过 TLS 包裹 CONNECT。
        proxy["type"] = "http"
        if node.get("username") is not None:
            proxy["username"] = node.get("username")
        if node.get("password") is not None:
            proxy["password"] = node.get("password")
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        return "vmess://" + base64.b64encode(json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "http":
        # v2rayN/通用客户端最兼容的形式是 http://host:port；
        # HTTPS 正向代理仍保留 https:// scheme，供支持 TLS HTTP proxy 的客户端使用。
        scheme = "https" if tls.get("enabled") else "http"
        auth = ""
        if node.get("username") is not None:
            auth = urllib.parse.quote(str(node.get("username")), safe="")
            if node.get("password") is not None:
                auth += ":" + urllib.parse.quote(str(node.get("password")), safe="")
            auth += "@"
        return f"{scheme}://{auth}{server}:{port}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "socks":
        version = "4" if str(node.get("version", "5")) == "4" else "5"
        auth = ""
        if node.get("username") is not None:
            auth = urllib.parse.quote(str(node.get("username")), safe="")
            if node.get("password") is not None:
                auth += ":" + urllib.parse.quote(str(node.get("password")), safe="")
            auth += "@"
        return f"socks{version}://{auth}{server}:{port}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


def _normalize_header_map(obj):
    """Normalize echo JSON headers to lowercase string->list values."""
    if not isinstance(obj, dict):
        return {}
    out = {}
    for k, v in obj.items():
        key = str(k).strip().lower()
        if isinstance(v, list):
            vals = [str(x).strip() for x in v if str(x).strip()]
        else:
            vals = [str(v).strip()] if str(v).strip() else []
        if key:
            out[key] = vals
    return out


def probe_anonymity_through_singbox(node: dict) -> tuple[str, list[str], int]:
    """通过与主测活完全相同的 sing-box 链路做匿名性检测。

    这样 VLESS/VMess/Trojan/TUIC 等协议也不会再被错误地当成普通 HTTP/SOCKS
    直连代理。若配置 TEST_RELAY_NODE_URI，则链路为：GitHub → 测试中转 → 候选节点 → echo。
    """
    outbound = node.get("outbound") or {}
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_anon_{task_id}.json")
    relay = get_test_relay_outbound()
    config = build_test_config(outbound, socks_port, chain_relay=relay)
    # build_test_config 在 chain_relay=None 时会自行读取 TEST_RELAY_NODE_URI；
    # 显式传入 relay 后可避免重复解析，并保持匿名性测试链路与测活一致。
    if relay:
        config = build_test_config(outbound, socks_port, chain_relay=relay)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    proc = None
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path], capture_output=True,
                             text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return "unknown", [], 0
        proc = subprocess.Popen([exe, "run", "-c", cfg_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        deadline = time.time() + 6
        while time.time() < deadline:
            if proc.poll() is not None:
                return "unknown", [], 0
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    break
            except Exception:
                time.sleep(0.15)
        else:
            return "unknown", [], 0

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}
        seen = []
        for url in ANONOMY_PROBE_URLS:
            try:
                rr = PROBE_SESSION.get(url, proxies=proxies, timeout=ANONOMY_PROBE_TIMEOUT,
                                       headers={"User-Agent": USER_AGENT}, verify=True)
                if rr.status_code != 200:
                    continue
                body = rr.json()
                headers = body.get("headers", body if isinstance(body, dict) else {})
                cat, _, leaks = classify_header_anonymity(headers, node.get("exit_ip"))
                seen.append((cat, leaks))
            except Exception:
                continue
        if not seen:
            return "unknown", [], 0
        cats = [x[0] for x in seen]
        if "transparent" in cats:
            cat = "transparent"
        elif "anonymous" in cats:
            cat = "anonymous"
        elif all(c == "elite" for c in cats):
            cat = "elite"
        else:
            cat = "unknown"
        leaks = sorted({h for _, ls in seen for h in ls})
        return cat, leaks, len(seen)
    except Exception:
        return "unknown", [], 0
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def classify_header_anonymity(headers: dict, real_ip: str | None = None) -> tuple[str, int, list[str]]:
    """Classify proxy anonymity from echo headers without trusting one header blindly.

    ELITE: no known forwarding/proxy headers.
    ANONYMOUS: proxy headers exist, but no obvious client IP disclosure.
    TRANSPARENT: a header appears to disclose the direct/client IP.
    UNKNOWN: probe unavailable or malformed.
    """
    h = _normalize_header_map(headers)
    if not h:
        return "unknown", 0, []
    leaked = []
    proxy_headers = []
    for name in LEAK_HEADERS:
        vals = h.get(name, [])
        if vals:
            proxy_headers.append(name)
            leaked.extend(vals)
    if real_ip:
        try:
            rip = ipaddress.ip_address(real_ip).compressed
        except ValueError:
            rip = real_ip.strip()
        for value in leaked:
            if rip and rip in value:
                return "transparent", 10, proxy_headers
    if proxy_headers:
        return "anonymous", 68, proxy_headers
    return "elite", 96, []


def calculate_anonymity_score(n: dict) -> int:
    """Combine protocol-aware header evidence and transport behavior."""
    category = str(n.get("anonymity") or "unknown").lower()
    base = {"elite": 96, "anonymous": 68, "transparent": 10, "ip_leak": 0, "unknown": 45}.get(category, 45)
    if n.get("mitm_risk"):
        base -= 35
    # HTTPS CONNECT success gives stronger evidence than HTTP-only success.
    if n.get("https_ok"):
        base += 3
    if n.get("anonymity_probe_count", 0) >= 2:
        base += 2
    if n.get("header_leak_count", 0):
        base -= min(20, n["header_leak_count"] * 4)
    return max(0, min(100, int(round(base))))


def calculate_risk_score(n: dict) -> int:
    """0-100, higher = more risky. Conservative: unknown data is not treated as safe."""
    risk = 10
    rec = n.get("ip_api_rec") or {}
    fraud = n.get("fraud_score", -1)
    net = n.get("net_type", "unknown")
    org = " ".join(str(n.get(k) or "") for k in ("org", "isp", "asn_org")).lower()
    if net in ("datacenter", "cdn", "broadcast", "anycast"):
        risk += 30
    elif net == "unknown":
        risk += 12
    if rec.get("hosting"):
        risk += 35
    if rec.get("proxy"):
        risk += 30
    if rec.get("mobile") and net == "mobile":
        risk += 0
    if any(k in org for k in IDC_KEYWORDS_STRONG):
        risk += 22
    if fraud >= 90:
        risk += 55
    elif fraud >= 75:
        risk += 35
    elif fraud >= 60:
        risk += 20
    elif fraud >= 40:
        risk += 8
    if n.get("anonymity") == "transparent":
        risk += 30
    elif n.get("anonymity") == "anonymous":
        risk += 5
    if n.get("mitm_risk"):
        risk += 45
    if n.get("is_warp"):
        risk += 8
    if n.get("stability_rate", 1) < 0.8:
        risk += 8
    return max(0, min(100, int(risk)))


def calculate_residential_score(n: dict) -> int:
    """更宽松但仍有硬否决的家宽置信度。3 星(>=60)即进入家宽专区。"""
    net = n.get("net_type", "unknown")
    rec = n.get("ip_api_rec") or {}
    org = " ".join(str(n.get(k) or "") for k in ("org", "isp", "asn_org")).lower()

    # 硬否决：明确机房/托管/代理/VPN/广播/Anycast/CDN 不得冒充家宽。
    if rec.get("hosting") or rec.get("proxy"):
        return 0
    if net in ("broadcast", "anycast", "cdn", "datacenter"):
        return 0
    if n.get("fraud_score", -1) >= VERY_HIGH_RISK_FRAUD_SCORE:
        return 0
    if n.get("mitm_risk"):
        return 0

    score = 0
    if net == "residential":
        score += 58
    elif net == "mobile":
        score += 55
    elif net == "unknown":
        score += 20
    else:
        return 0

    # 分类置信度：ASN/ISP/rDNS 等多信号一致时提高分数。
    score += min(10, max(0, int(n.get("confidence", 0)) // 10))
    if rec.get("mobile"):
        score += 10
    if any(k in org for k in IDC_KEYWORDS_STRONG):
        score -= 25
    if any(k in org for k in RESIDENTIAL_KEYWORDS):
        score += 12

    fraud = n.get("fraud_score", -1)
    if 0 <= fraud < 25:
        score += 8
    elif 25 <= fraud < 50:
        score += 4
    elif 50 <= fraud < 75:
        score -= 5
    elif 75 <= fraud < 90:
        score -= 15

    # 稳定性/匿名性是质量加分，而不是“创造家宽身份”的依据。
    score += min(8, round(8 * float(n.get("stability_rate", 0))))
    score += min(5, round(5 * float(n.get("anonymity_score", 0)) / 100))
    return max(0, min(100, int(score)))


def calculate_overall_score(n: dict) -> int:
    """Weighted score for sorting only; hard safety gates happen elsewhere."""
    latency = float(n.get("latency_ms") or 99999)
    speed = float(n.get("speed_bps") or 0)
    latency_score = 100 if latency <= 200 else 80 if latency <= 500 else 60 if latency <= 1000 else 35 if latency <= 2000 else 10
    speed_score = min(100, int(speed / 10000)) if speed else 0
    stability = int(round(100 * float(n.get("stability_rate", 0))))
    anon = int(n.get("anonymity_score", 0))
    risk = int(n.get("risk_score", 100))
    residential = int(n.get("residential_score", 0))
    score = (0.22 * latency_score + 0.15 * speed_score + 0.20 * stability +
             0.18 * anon + 0.15 * (100 - risk) + 0.10 * residential)
    return max(0, min(100, int(round(score))))


def calculate_ip_quality_score(n: dict) -> int:
    """根据已有出口 IP 情报计算 0-100 质量分。
    不额外调用 API，避免增加运行时间；主要用于压缩普通节点数量。
    """
    ip = n.get("exit_ip")
    if not ip:
        return 0

    score = 50
    net_type = n.get("net_type")
    fraud = n.get("fraud_score", -1)
    org = (n.get("org") or n.get("isp") or "").lower()
    asn = n.get("asn")

    # 网络类型
    if net_type == "residential":
        score += 35
    elif net_type == "mobile":
        score += 28
    elif net_type == "datacenter":
        score -= 8
    elif net_type == "cdn":
        score -= 35
    else:
        score -= 5

    # ip-api 已明确识别的高风险类型
    rec = n.get("ip_api_rec") or {}
    if rec.get("hosting"):
        score -= 40
    if rec.get("proxy"):
        score -= 45
    if rec.get("mobile"):
        score += 5

    # 已知机房关键词再扣分（兼容 ip-api / MaxMind 信息不完整的情况）
    idc_words = (
        "cloud", "hosting", "datacenter", "data center", "server",
        "vps", "dedicated", "colo", "colocation", "compute",
        "digitalocean", "vultr", "hetzner", "ovh", "contabo",
        "leaseweb", "linode", "amazon", "aws", "google cloud",
        "microsoft", "azure", "oracle cloud", "alibaba cloud",
        "tencent cloud", "huawei cloud", "zenlayer", "m247",
        "choopa", "gcore", "akamai", "fastly", "bunny",
    )
    if any(w in org for w in idc_words):
        score -= 25

    # 风控分：越高越危险
    if fraud >= 90:
        return 0
    if fraud >= 75:
        score -= 35
    elif fraud >= 60:
        score -= 20
    elif fraud >= 40:
        score -= 8
    elif 0 <= fraud < 20:
        score += 5

    # 有 ASN / 组织信息通常比完全未知 IP 更可靠
    if asn:
        score += 3
    if org:
        score += 2

    return max(0, min(100, score))


def filter_ip_quality(unique_nodes: list, residential: list):
    """第二道 IP 质量过滤：减少普通节点数量，并限制同出口 IP 刷屏。
    家宽列表沿用前面的严格家宽筛选，不因质量阈值再次大量误删。
    """
    if not unique_nodes:
        return unique_nodes, residential

    # 给每个节点记录质量分，方便日志/后续调参
    for n in unique_nodes:
        n["ip_quality_score"] = calculate_ip_quality_score(n)

    before = len(unique_nodes)
    filtered = []
    for n in unique_nodes:
        if not n.get("exit_ip") and DROP_UNKNOWN_IP_QUALITY:
            continue
        # 家宽/移动已经经过严格分类、交叉核验和 fraud 检查，保留
        if n in residential:
            filtered.append(n)
            continue
        # 普通/非家宽节点不因 IP 质量分被淘汰。
        # 质量分仅用于排序和日志；真正的硬淘汰仍由测活、MITM、断流、fraud>=90 等规则负责。
        if MIN_IP_QUALITY_SCORE > 0 and n["ip_quality_score"] < MIN_IP_QUALITY_SCORE:
            continue
        filtered.append(n)

    quality_dropped = before - len(filtered)
    print(f"[*] IP 质量过滤: {before} → {len(filtered)} (质量分 < {MIN_IP_QUALITY_SCORE} / 无出口IP 淘汰 {quality_dropped})")

    # 同一个出口 IP 可能对应大量不同入口节点/端口，只保留质量高且延迟低的前 N 个。
    by_ip = {}
    for n in filtered:
        ip = n.get("exit_ip")
        if not ip:
            continue
        by_ip.setdefault(ip, []).append(n)

    limited = []
    ip_dup_dropped = 0
    for ip, items in by_ip.items():
        # 家宽前面已经每 IP 只保留一个；普通节点默认不限数量。
        items.sort(key=lambda x: (-x.get("ip_quality_score", 0), x.get("latency_ms", 99999)))
        kept = items if MAX_NODES_PER_EXIT_IP <= 0 else items[:MAX_NODES_PER_EXIT_IP]
        limited.extend(kept)
        ip_dup_dropped += max(0, len(items) - len(kept))

    limit_text = "不限" if MAX_NODES_PER_EXIT_IP <= 0 else str(MAX_NODES_PER_EXIT_IP)
    print(f"[*] 出口 IP 限制: {len(filtered)} → {len(limited)} (同 IP 最多 {limit_text} 个，剔除 {ip_dup_dropped})")

    # 重新生成家宽列表：这里不会改变原家宽集合，只过滤掉极高危节点
    keep_set = {id(n) for n in limited}
    residential = [n for n in residential if id(n) in keep_set]
    return limited, residential


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    no_exit_ip = []
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = {}
    scam_scores = {}
    intel_cache = _load_ip_intel_cache()
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})

        # 多源国家交叉验证：ip.sb/ipinfo → ip-api → MaxMind，采用多数票；平票优先在线出口信息。
        country_votes = []
        for cc in (online_country, rec.get("countryCode"), country):
            if cc and str(cc).upper() not in ("OTHER", "ZZ"):
                country_votes.append(str(cc).upper())
        if country_votes:
            counts = {}
            for cc in country_votes:
                counts[cc] = counts.get(cc, 0) + 1
            max_votes = max(counts.values())
            winners = {cc for cc, cnt in counts.items() if cnt == max_votes}
            if len(winners) == 1:
                country = next(iter(winners))
            elif online_country and str(online_country).upper() in winners:
                country = str(online_country).upper()

        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "ip_api_rec": rec,
            "latency_ms": r["latency_ms"],
            "stability_rate": r.get("stability_rate", 1.0),
            "speed_bps": r["speed_bps"],
            "mitm_risk": r["mitm_risk"],
            "is_stalled": r["is_stalled"],
            "is_warp": r.get("is_warp", False),
            "https_ok": r.get("https_ok", False),
            "anonymity": r.get("anonymity", "unknown"),
            "header_leaks": r.get("header_leaks", []),
            "header_leak_count": len(r.get("header_leaks", [])),
            "anonymity_probe_count": r.get("anonymity_probe_count", 0),
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 ──
    # MITM 劫持节点: 高危, 直接丢弃 (204 能通但证书被劫持 = 中间人)
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)

    # 广播/Anycast/CDN 出口不进入任何订阅；普通 IDC 仍然保留。
    broadcast_dropped = 0
    if EXCLUDE_BROADCAST_IP:
        before_broadcast = len(safe_nodes)
        safe_nodes = [n for n in safe_nodes if n.get("net_type") not in ("broadcast", "cdn")]
        broadcast_dropped = before_broadcast - len(safe_nodes)

    # 断流节点已无 (在 liveness 阶段淘汰), 但 double-check
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    stability_dropped = 0
    before_stability = len(safe_nodes)
    safe_nodes = [n for n in safe_nodes if n.get("stability_rate", 1.0) >= MIN_STABILITY_RATE]
    stability_dropped = before_stability - len(safe_nodes)
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped} | 广播/Anycast/CDN 剔除: {broadcast_dropped} | 稳定性不足剔除: {stability_dropped}")

    # ── Scamalytics 风控评分 (免费 HTML, 逐个) ──
    # 家宽候选 + 非家宽候选全部查询。非家宽现在要求 fraud 分可验证且不高于
    # NONRESIDENTIAL_MAX_FRAUD_SCORE，因此不能再只抽样普通节点。
    scam_candidates = set()
    for n in safe_nodes:
        if n.get("exit_ip") and n.get("net_type") in ("residential", "mobile", "datacenter", "unknown"):
            scam_candidates.add(n["exit_ip"])
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽/非家宽候选出口 IP ...")
        def _scam(ip):
            return ip, cached_scamalytics_fraud_score(ip, intel_cache)
        with ThreadPoolExecutor(max_workers=6) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, cached_ipapi_is_verify(ip, intel_cache)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if n["net_type"] not in ("residential", "mobile"):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # 持久化 IP 情报缓存：跨 Actions 运行复用，24h 后自动刷新。
    _save_ip_intel_cache(intel_cache)

    # ── 多端点匿名性 echo 检测 ──
    # 参考 Thordata/Proxmint：检查代理追加的 forwarding headers；不把“出口IP不同”误当作 elite。
    # 为避免成本爆炸，只对当前 safe_nodes 做并发轻量探测；失败则保留 UNKNOWN，不直接误杀。
    def _probe_anonymity(node):
        try:
            cat, leaks, count = probe_anonymity_through_singbox(node)
            return node, cat, leaks, count
        except Exception:
            return node, "unknown", [], 0

    if safe_nodes:
        # 家宽/移动候选全部深测；普通节点只抽样延迟/稳定性较好的前 N 个。
        res_candidates = [n for n in safe_nodes if n.get("net_type") in ("residential", "mobile")]
        ordinary = [n for n in safe_nodes if n.get("net_type") not in ("residential", "mobile")]
        ordinary.sort(key=lambda x: (x.get("latency_ms", 99999), -x.get("stability_rate", 0)))
        anon_targets = res_candidates + ordinary[:ANONOMY_ORDINARY_SAMPLE]
        target_ids = {id(n) for n in anon_targets}
        print(f"[*] 多端点匿名性检测: {len(anon_targets)} 个节点（家宽候选 {len(res_candidates)} + 普通抽样 {min(len(ordinary), ANONOMY_ORDINARY_SAMPLE)}）")
        with ThreadPoolExecutor(max_workers=ANONOMY_PROBE_CONCURRENCY) as ex:
            for node, cat, leaks, count in ex.map(_probe_anonymity, anon_targets):
                node["anonymity"] = cat
                node["header_leaks"] = leaks
                node["header_leak_count"] = len(leaks)
                node["anonymity_probe_count"] = count
        # 未深测的普通节点保持 UNKNOWN，由评分系统保守处理，不影响基础测活订阅。
        for node in safe_nodes:
            if id(node) not in target_ids:
                node.setdefault("anonymity", "unknown")
                node.setdefault("header_leaks", [])
                node.setdefault("header_leak_count", 0)
                node.setdefault("anonymity_probe_count", 0)

    # 重新计算多维评分。评分只用于排序/专区；硬风险条件仍然优先执行。
    for n in safe_nodes:
        n["anonymity_score"] = calculate_anonymity_score(n)
        n["residential_score"] = 0
        n["risk_score"] = 0

    # 风险分 >= 75 的家宽候选降级为普通 (fraud 池/被滥用 IP 绝不入家宽区)
    downgraded = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        if n["net_type"] in ("residential", "mobile") and sc >= 75:
            n["net_type"] = "datacenter"  # 高 fraud 分: 大概率代理池滥用 IP
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥75) 家宽候选降级: {downgraded} 个")

    # ── 多维信誉评分 ──
    for n in safe_nodes:
        n["anonymity_score"] = calculate_anonymity_score(n)
        n["residential_score"] = calculate_residential_score(n)
        n["risk_score"] = calculate_risk_score(n)
        n["overall_score"] = calculate_overall_score(n)

    # ── 去重 (同出口IP+端口 只留最快) ──
    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or n["latency_ms"] < cur["latency_ms"]:
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped})")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n.get("residential_score", 0) >= RESIDENTIAL_3STAR_SCORE:
            # 双跳失败不再取消家宽资格，只标记链式兼容性；用户可以直观看到。
            n["chain_compatible"] = n.get("raw") not in chain_failed_raws
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    # ★ 第二道 IP 质量过滤：压缩普通节点数量，并限制同出口 IP 刷屏
    unique_nodes, residential = filter_ip_quality(unique_nodes, residential)

    non_residential = [n for n in unique_nodes if n not in residential]

    # ── 非家宽二次硬过滤：只保留原生 IP + 低 fraud ──
    # “原生 IP”不是“家宽”的同义词：这里允许优质数据中心原生出口，
    # 但拒绝代理/VPN/托管/Cloud/CDN/Anycast 等明显非原生出口。
    # fraud 未查询到（-1）也不进入最终非家宽订阅，避免“未知”绕过门槛。
    before_nonres = len(non_residential)
    native_nonres = []
    nonres_drop_reasons = {"no_exit_ip": 0, "proxy_or_hosting": 0, "cdn_or_anycast": 0, "fraud_unknown": 0, "fraud_high": 0}
    for n in non_residential:
        if not n.get("exit_ip"):
            nonres_drop_reasons["no_exit_ip"] += 1
            continue
        rec = n.get("ip_api_rec") or {}
        if NONRESIDENTIAL_REQUIRE_NATIVE_IP:
            if rec.get("proxy") or rec.get("hosting"):
                nonres_drop_reasons["proxy_or_hosting"] += 1
                continue
            if n.get("net_type") in ("cdn", "broadcast"):
                nonres_drop_reasons["cdn_or_anycast"] += 1
                continue
        fraud = n.get("fraud_score", -1)
        if not isinstance(fraud, (int, float)) or fraud < 0:
            nonres_drop_reasons["fraud_unknown"] += 1
            continue
        if fraud > NONRESIDENTIAL_MAX_FRAUD_SCORE:
            nonres_drop_reasons["fraud_high"] += 1
            continue
        n["native_ip"] = True
        native_nonres.append(n)
    non_residential = native_nonres
    nonres_dropped = before_nonres - len(non_residential)
    if nonres_dropped:
        print(f"[*] 非家宽原生/低欺诈过滤: {before_nonres} → {len(non_residential)} | 剔除 {nonres_dropped} "
              f"(无出口IP {nonres_drop_reasons['no_exit_ip']}, proxy/hosting {nonres_drop_reasons['proxy_or_hosting']}, "
              f"CDN/Anycast {nonres_drop_reasons['cdn_or_anycast']}, fraud未知 {nonres_drop_reasons['fraud_unknown']}, "
              f"fraud>{NONRESIDENTIAL_MAX_FRAUD_SCORE} {nonres_drop_reasons['fraud_high']})")

    # 从总订阅中同步移除被非家宽硬过滤淘汰的节点；家宽集合保持不变。
    nonres_keep_ids = {id(n) for n in non_residential}
    residential_keep_ids = {id(n) for n in residential}
    unique_nodes = [n for n in unique_nodes if id(n) in nonres_keep_ids or id(n) in residential_keep_ids]

    print(f"[*] IP 质量过滤后: 家宽/移动 {len(residential)} | 非家宽原生低欺诈 {len(non_residential)} | 总计 {len(unique_nodes)}")

    # 排序: 家宽在前, 延迟升序
    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, x["latency_ms"]))
    residential.sort(key=lambda x: (-x.get("residential_stars", 0), -x.get("residential_score", 0), -x.get("overall_score", 0), x.get("latency_ms", 99999)))
    non_residential.sort(key=lambda x: x["latency_ms"])
    # ★ 链式复测双跳失败的家宽 → 降级普通区 (v2rayN 链式场景不可靠)
    #    保留在总订阅/国家订阅里 (直连场景仍可用), 只是退出家宽专区

    # 质量排序：延迟 + 稳定率 + IP 质量 + 家宽/移动优先。
    # 这里不把“家宽”当成唯一优先条件，避免高延迟家宽压过稳定低延迟节点。
    for n in unique_nodes:
        n["quality_score"] = round(
            min(100, max(0,
                45
                + min(25, max(0, (1000 - float(n.get("latency_ms", 1000))) / 40))
                + 20 * float(n.get("stability_rate", 0.0))
                + 0.15 * float(n.get("ip_quality_score", 0))
                + (8 if n.get("net_type") == "residential" else 5 if n.get("net_type") == "mobile" else 0)
            )), 1
        )

    for n in unique_nodes:
        n["overall_score"] = calculate_overall_score(n)
        n["residential_stars"] = residential_stars(n.get("residential_score", 0)) if n.get("net_type") in ("residential", "mobile") else 0
        n["residential_grade"] = ("★★★★★" if n["residential_stars"] == 5 else "★★★★☆" if n["residential_stars"] == 4 else "★★★☆☆" if n["residential_stars"] == 3 else "★★☆☆☆" if n["residential_stars"] == 2 else "★☆☆☆☆" if n["residential_stars"] == 1 else "☆☆☆☆☆")

    # 重建 outbound (测活阶段的 outbound 已验证可用); 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        parsed = parse_node_uri(n["raw"])
        if parsed:
            ob = parsed[0]
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    is_res = item["net_type"] in ("residential", "mobile") and (item["confidence"] >= 60 or force_residential)
    tag = ""
    if is_res:
        stars = item.get("residential_grade", "☆☆☆☆☆")
        tag = (" " + stars + " 家宽") if item["net_type"] == "residential" else (" " + stars + " 移动家宽")
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    return f"{flag} {cname} {idx:02d}{tag}{risk_tag} - xiaohe"


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    # 重新整理：协议独立、稳定精选、质量精选、国家独立订阅全部自动生成。
    PROTOCOLS = {
        "http": "http",
        "https": "https",
        "socks4": "socks4",
        "socks5": "socks5",
        "socks": "socks5",
    }

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            ob = item.get("outbound")
            if not ob:
                continue
            links.append(outbound_to_v2ray_link(ob, name))
            cp = outbound_to_clash(ob, name)
            if cp:
                proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    def write_group(nodes_list, stem, force_res=False):
        links, proxies, sb_nodes = build_group(nodes_list, force_res)
        with open(os.path.join(OUTPUT_DIR, f"{stem}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(links).encode()).decode())
        export_clash_yaml(proxies, os.path.join(OUTPUT_DIR, f"{stem}-clash.yaml"))
        export_singbox_json(sb_nodes, os.path.join(OUTPUT_DIR, f"{stem}-singbox.json"))
        return len(links)

    # 1) 总订阅 / 家宽 / 非家宽
    total = write_group(unique_nodes, "v2ray")
    # 兼容旧文件名：v2ray.txt 仍为总订阅。
    # residential.txt / residential-clash.yaml / residential-singbox.json
    # 是“全部家宽节点”的统一总订阅入口，不再要求用户逐国添加。
    res = write_group(residential, "residential", True)
    # 额外提供语义更直观的 residential-all 别名，避免与五星池混淆。
    write_group(residential, "residential-all", True)
    nonres = write_group(non_residential, "non-residential")

    # 2) 协议独立订阅：HTTP / HTTPS / SOCKS4 / SOCKS5
    protocol_dir = os.path.join(OUTPUT_DIR, "protocols")
    shutil.rmtree(protocol_dir, ignore_errors=True)
    os.makedirs(protocol_dir, exist_ok=True)
    for pkey, label in (("http", "http"), ("https", "https"), ("socks4", "socks4"), ("socks5", "socks5")):
        if pkey in ("socks4", "socks5"):
            ver = "4" if pkey == "socks4" else "5"
            lst = [n for n in unique_nodes if n.get("proto") == "socks" and str((n.get("outbound") or {}).get("version", "5")) == ver]
        else:
            # sing-box 内部统一 type=http；通过 proxy_scheme 区分 HTTP 与 HTTPS CONNECT。
            lst = [n for n in unique_nodes if n.get("proto") == "http" and str((n.get("outbound") or {}).get("proxy_scheme", "http")) == pkey]
        if not lst:
            continue
        links, proxies, sb = build_group(lst)
        stem = label
        with open(os.path.join(protocol_dir, f"{stem}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(links).encode()).decode())
        export_clash_yaml(proxies, os.path.join(protocol_dir, f"{stem}-clash.yaml"))
        export_singbox_json(sb, os.path.join(protocol_dir, f"{stem}-singbox.json"))

    # 3) 精选：高质量 + 低延迟 + 稳定。不是“保证可用”，只是比全量更严格。
    top_trusted = [n for n in unique_nodes if n.get("quality_score", 0) >= 78 and n.get("latency_ms", 99999) <= 1000 and n.get("stability_rate", 0) >= 0.66]
    stable = [n for n in unique_nodes if n.get("survival_streak", 0) >= 2]
    top_trusted.sort(key=lambda x: (-x.get("quality_score", 0), x.get("latency_ms", 99999)))
    stable.sort(key=lambda x: (-x.get("survival_streak", 0), -x.get("quality_score", 0), x.get("latency_ms", 99999)))
    write_group(top_trusted, "top-trusted")
    write_group(stable, "stable")

    # 4) 家宽精选 / 非家宽精选
    res_top = [n for n in residential if n.get("quality_score", 0) >= 75]
    nonres_top = [n for n in non_residential if n.get("quality_score", 0) >= 75]
    write_group(res_top, "residential-top", True)
    write_group(nonres_top, "non-residential-top")

    # 5) 国家目录：普通、家宽，以及国家+协议的精选订阅
    for root in (COUNTRY_DIR, RESIDENTIAL_COUNTRY_DIR):
        shutil.rmtree(root, ignore_errors=True)
        os.makedirs(root, exist_ok=True)

    def export_country_tree(nodes, root, force_res=False):
        by_cc = {}
        for n in nodes:
            by_cc.setdefault(n.get("country", "OTHER"), []).append(n)
        for cc, lst in by_cc.items():
            safe_cc = re.sub(r"[^A-Z0-9_-]", "", cc.upper()) or "OTHER"
            l, p, sb = build_group(lst, force_res)
            with open(os.path.join(root, f"{safe_cc}.txt"), "w", encoding="utf-8") as f:
                f.write(base64.b64encode("\n".join(l).encode()).decode())
            export_clash_yaml(p, os.path.join(root, f"clash-{safe_cc}.yaml"))
            export_singbox_json(sb, os.path.join(root, f"singbox-{safe_cc}.json"))
            for pkey in ("http", "https", "socks4", "socks5"):
                sub = [n for n in lst if (n.get("proto") == "http" and str((n.get("outbound") or {}).get("proxy_scheme", "http")) == pkey) or n.get("proto") == pkey]
                if not sub:
                    continue
                sl, sp, ss = build_group(sub, force_res)
                with open(os.path.join(root, f"{safe_cc}-{pkey}.txt"), "w", encoding="utf-8") as f:
                    f.write(base64.b64encode("\n".join(sl).encode()).decode())
                export_clash_yaml(sp, os.path.join(root, f"clash-{safe_cc}-{pkey}.yaml"))
                export_singbox_json(ss, os.path.join(root, f"singbox-{safe_cc}-{pkey}.json"))

    export_country_tree(non_residential, COUNTRY_DIR, False)
    export_country_tree(residential, RESIDENTIAL_COUNTRY_DIR, True)

    # 6) 机器可读质量报告，方便后续网页/Cloudflare Worker 直接读取。
    # 同时保存完整节点元数据，便于以后做历史信誉分析，而不必重新测所有节点。
    metadata = []
    for n in unique_nodes:
        metadata.append({
            "server": n.get("server"), "port": n.get("port"), "proto": n.get("proto"),
            "exit_ip": n.get("exit_ip"), "country": n.get("country"),
            "asn": n.get("asn"), "org": n.get("org"), "isp": n.get("isp"),
            "net_type": n.get("net_type"), "confidence": n.get("confidence"),
            "anonymity": n.get("anonymity"), "anonymity_score": n.get("anonymity_score"),
            "header_leaks": n.get("header_leaks", []),
            "residential_score": n.get("residential_score"),
            "residential_stars": n.get("residential_stars", 0), "residential_grade": n.get("residential_grade", "☆☆☆☆☆"),
            "chain_compatible": n.get("chain_compatible"),
            "fraud_score": n.get("fraud_score", -1), "risk_score": n.get("risk_score"),
            "native_ip": bool(n.get("native_ip", False)),
            "stability_rate": n.get("stability_rate"), "survival_streak": n.get("survival_streak", 0),
            "latency_ms": n.get("latency_ms"), "speed_bps": n.get("speed_bps"),
            "ip_quality_score": n.get("ip_quality_score"), "overall_score": n.get("overall_score"),
            "source": n.get("source", ""),
        })
    with open(os.path.join(OUTPUT_DIR, "nodes.json"), "w", encoding="utf-8") as f:
        json.dump(metadata, f, ensure_ascii=False, indent=2)

    premium_res = [n for n in residential if n.get("residential_stars", 0) >= 5 and
                   n.get("anonymity_score", 0) >= 85 and n.get("risk_score", 100) <= 35 and
                   n.get("stability_rate", 0) >= 0.80]
    premium_res.sort(key=lambda x: (-x.get("overall_score", 0), x.get("latency_ms", 99999)))
    write_group(premium_res, "residential-premium", True)
    # 持久五星池的当前快照订阅（JSON 是跨运行资产，以下是方便客户端直接使用的快照）
    five_star = [n for n in residential if n.get("residential_stars", 0) >= 5]
    write_group(five_star, "residential-pool", True)
    # 6.5)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total": len(unique_nodes),
        "residential": len(residential),
        "non_residential": len(non_residential),
        "top_trusted": len(top_trusted),
        "stable": len(stable),
        "residential_premium": len(premium_res),
        "residential_stars": {"3": 0, "4": 0, "5": 0},
        "protocols": {},
        "anonymity": {},
        "net_types": {},
        "risk_buckets": {"0-20": 0, "21-40": 0, "41-60": 0, "61-75": 0, "76-100": 0},
        "countries": {},
    }
    for n in unique_nodes:
        proto = n.get("proto", "unknown")
        if proto == "http":
            proto = str((n.get("outbound") or {}).get("proxy_scheme", "http"))
        elif proto == "socks":
            proto = "socks" + str((n.get("outbound") or {}).get("version", "5"))
        summary["protocols"][proto] = summary["protocols"].get(proto, 0) + 1
        cc = n.get("country", "OTHER")
        summary["countries"][cc] = summary["countries"].get(cc, 0) + 1
        an = n.get("anonymity", "unknown")
        summary["anonymity"][an] = summary["anonymity"].get(an, 0) + 1
        nt = n.get("net_type", "unknown")
        summary["net_types"][nt] = summary["net_types"].get(nt, 0) + 1
        stars = int(n.get("residential_stars", 0) or 0)
        if stars >= 3:
            summary["residential_stars"][str(min(stars, 5))] += 1
        rs = int(n.get("risk_score", 100))
        bucket = "0-20" if rs <= 20 else "21-40" if rs <= 40 else "41-60" if rs <= 60 else "61-75" if rs <= 75 else "76-100"
        summary["risk_buckets"][bucket] += 1
    with open(os.path.join(OUTPUT_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    print(f"[*] 导出完毕: 全量 {total} | 家宽(≥3星) {res} | 非家宽 {nonres} | 稳定 {len(stable)} | 精选 {len(top_trusted)}")
    return total, res, nonres

def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count, nonres_count, precheck_stats=None):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "hezhanleiok/freesub").strip()
    cache_bust = ""
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "hezhanleiok", "freesub"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/{cc}.txt) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/{cc}.txt)"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/clash-{cc}.yaml) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/clash-{cc}.yaml)"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/singbox-{cc}.json) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/singbox-{cc}.json)"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    ps = precheck_stats or {}
    deferred_total = int(ps.get("deferred", 0) or 0)
    deferred_res = int(ps.get("deferred_to_residential", 0) or 0)
    deferred_nonres = int(ps.get("deferred_to_nonresidential", 0) or 0)
    deferred_final = int(ps.get("deferred_to_final_selection", 0) or 0)
    deferred_res_rate = float(ps.get("deferred_residential_selection_rate", 0) or 0)
    deferred_nonres_rate = float(ps.get("deferred_nonresidential_selection_rate", 0) or 0)
    deferred_final_rate = float(ps.get("deferred_final_selection_rate", 0) or 0)
    deferred_res_final_share = float(ps.get("residential_share_of_final", 0) or 0)
    deferred_nonres_final_share = float(ps.get("nonresidential_share_of_final", 0) or 0)

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v{SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/singbox.json) |

### 🖥️ 非家宽 / 原生 IP + 低欺诈独立总订阅

> 仅保留非家宽中的原生出口 IP：`hosting=false`、`proxy=false`，排除 CDN/Anycast/广播出口，并要求 Scamalytics `fraud_score <= {NONRESIDENTIAL_MAX_FRAUD_SCORE}`。无法取得 fraud 分的节点也不会进入该专区。

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 | 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN** | `{nonres_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/non-residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/non-residential.txt) |
| 🚀 **Clash** | `{nonres_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/non-residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/non-residential-clash.yaml) |
| 📦 **sing-box** | `{nonres_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/non-residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/non-residential-singbox.json) |

---

## 🏠 家宽全部节点统一总订阅

> 以下 3 个链接始终对应本轮筛选出的**全部家宽节点**，与按国家拆分的家宽订阅互补；五星持久池 `residential-pool` 是另一套独立资产。

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 | 官方 Raw 直链 |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential.txt) |
| 🚀 **Clash** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential-clash.yaml) |
| 📦 **sing-box** | `{res_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential-singbox.json) |

---

## 📊 预检未过节点最终入选统计

> 本统计用于评估“端口预检”是否值得保留。预检未过节点当前仍会进入后续 sing-box 全流程，因此这里统计它们最终进入**家宽总订阅**和**非家宽总订阅**的数量与占比。

| 指标 | 数量 | 占预检未过 | 占最终该专区 |
| :--- | ---: | ---: | ---: |
| 预检未过 → 家宽总订阅 | `{deferred_res}` | `{deferred_res_rate}%` | `{deferred_res_final_share}%` |
| 预检未过 → 非家宽总订阅 | `{deferred_nonres}` | `{deferred_nonres_rate}%` | `{deferred_nonres_final_share}%` |
| 预检未过 → 最终任一总订阅 | `{deferred_final}` | `{deferred_final_rate}%` | - |

> 💡 如果连续多轮数据显示“预检未过 → 家宽总订阅”的入选率长期极低，可以考虑将预检未过节点直接跳过，从而显著减少后续 sing-box 测活时间。建议至少观察 **3–5 轮** 再决定是否关闭，以免偶发的本地 TCP 误判导致漏掉可用家宽。

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽采用多信号置信度评分，并以星级展示：★★★☆☆（≥60）及以上进入家宽专区，★★★★☆（≥75）为优质，★★★★★（≥90）为高质量家宽。明确 hosting/proxy/数据中心/CDN/广播/Anycast/fraud≥90 仍硬否决。★★★★★ 节点会动态保存到 `output/residential-pool.json`，下一轮优先重新测活，即使原公开源暂时消失也不会立即丢失。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

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
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
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

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **测活标准**：节点必须通过 ① 端口预检 ② sing-box 实际隧道 3 个 generate_204 探测 ③ 真实出口 IP 穿透获取 ④ Cloudflare 5MB 限时下载 (吞吐 ≥ 70KB/s) ⑤ TLS 证书校验非 MITM, 方可入库。
3. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}, 非家宽 {nonres_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()
    # 启动时先解析一次配置。Secret 优先，支持 TEST_RELAY_NODE / _2 / _3，代码配置为备用。
    relay_uri = get_test_relay_uri()
    if relay_uri:
        relay = get_test_relay_outbound()
        if relay:
            print("[+] 自定义测试出口模式：已启用（GitHub → 测试中转 → 候选节点）")
        else:
            print("[!] 自定义测试出口配置无效：将退回 GitHub 直连模式")
    else:
        print("[*] 自定义测试出口：未配置，使用 GitHub Runner 直连")
    history = load_node_history()
    previous_active = list(history.get("active", []))
    pool_nodes = load_residential_pool()

    # 1. 抓取 + 历史五星家宽补池
    raw_nodes = fetch_raw_nodes()
    raw_nodes = merge_residential_pool(raw_nodes, pool_nodes)

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前强去重 (凭据指纹去重: 同 凭据+目标+协议 只测一次, 结果回填全部重复节点)
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹: uuid/password 各协议的核心身份字段 (vless uuid / vmess id+alterId /
    #               trojan password / ss 2022密钥 / hy2 auth / tuic uuid+passwd / anytls password)
    #     完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次
    def cred_fingerprint(outbound: dict, proto: str) -> str:
        try:
            if proto == "vless":
                return f"{outbound.get('uuid','')}"
            if proto == "vmess":
                return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
            if proto == "trojan":
                return f"{outbound.get('password','')}"
            if proto == "shadowsocks":
                return f"{outbound.get('method','')}|{outbound.get('password','')}"
            if proto == "hysteria2":
                return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
            if proto == "tuic":
                return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
            if proto == "anytls":
                return f"{outbound.get('password','')}"
            return json.dumps({k: v for k, v in outbound.items()
                              if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        except Exception:
            return ""  # 指纹失败 → 不合并 (宁慢不错)

    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)  # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} (剔除重复 {dup_count} — 结果将回填)")
    DEDUP_MAP = seen_keys  # 供测活后回填 (全局)
    candidates = deduped

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    parsed_candidates_count = len(candidates)
    candidates = filter_blacklisted_candidates(candidates, history)
    if not candidates:
        print("[!] 无需本轮测活的节点（可能全部处于历史失败冷却） — 保留上次 output")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)
    tested_candidates = list(candidates)

    # 4. 真实测活 (只测去重后的代表节点)
    test_results = run_liveness_test(candidates)
    update_node_history(history, tested_candidates, test_results)
    save_node_history(history)

    # 4.5 ★ 重复节点结果回填: 同 凭据+目标 的重复 URI 继承测活结果 (凭据相同 → 服务端表现一致)
    if DEDUP_MAP:
        result_by_key = {}
        for r in test_results:
            result_by_key[node_identity_key(r.get("raw", ""))] = r
        expanded = list(test_results)
        backfilled = 0
        # 反向索引使用完整身份指纹，避免同 server:port 上不同凭据被错误回填。
        for key, uris in DEDUP_MAP.items():
            if len(uris) <= 1:
                continue
            representative_uri = uris[0]
            r = result_by_key.get(node_identity_key(representative_uri))
            if not r or not r.get("alive"):
                continue
            for extra_uri in uris[1:]:
                clone = dict(r)
                clone["raw"] = extra_uri
                expanded.append(clone)
                backfilled += 1
        if backfilled:
            print(f"[+] 重复节点回填: +{backfilled} (继承代表测活结果)")
        test_results = expanded

    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return
    total, res, nonres = export_all(unique_nodes, residential, non_residential)
    # ★ 动态更新五星家宽持久池；下次 Actions 运行会优先读取这些节点。
    update_residential_pool(unique_nodes, test_results)

    # 历史状态：只把“最终入库节点”作为上一轮 active，避免把仅测活通过但被质量过滤的节点算成活跃。
    current_active = [node_identity_key(n.get("raw", "")) for n in unique_nodes]
    history["active"] = current_active
    history["last_run"] = datetime.now(timezone.utc).isoformat()
    save_node_history(history)

    report = build_run_report(previous_active, unique_nodes, test_results, len(tested_candidates),
                              len(raw_nodes), parsed_candidates_count, len(residential), len(non_residential))
    write_run_report(report)
    print_run_report(report)
    update_readme(total, res, nonres, report.get("precheck_stats"))


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    nonres_count = len([n for n in unique_nodes if n not in residential])
    print(f"总耗时: {elapsed:.0f}s | 抓取 {len(raw_nodes)} → 解析成功 {len(candidates)} → 真活 {len(test_results)} → 去重后 {len(unique_nodes)} → 家宽 {len(residential)} → 非家宽 {nonres_count}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")


if __name__ == "__main__":
    main()
