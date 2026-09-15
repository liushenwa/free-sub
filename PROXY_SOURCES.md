# 公开代理来源

本项目已经彻底移除旧版 VLESS / VMess / Trojan 等免费订阅来源，只使用公开 HTTP/HTTPS/SOCKS4/SOCKS5 代理池。

## 当前来源

1. HProxy — HTTP / HTTPS / SOCKS4 / SOCKS5，提供实时 API 与匿名/国家/延迟等过滤。
2. Stormsia — HTTP / SOCKS4 / SOCKS5 公开池。
3. ProxyScrape — HTTP / HTTPS / SOCKS4 / SOCKS5，提供 TXT/JSON/CSV 与协议分片。
4. Proxmint — HTTP / HTTPS / SOCKS4 / SOCKS5。
5. IPLocate — HTTP / HTTPS / SOCKS4 / SOCKS5。
6. Thordata/awesome-free-proxy-list — HTTP / HTTPS / SOCKS4 / SOCKS5，并额外使用 `top-trusted`、`stable` 精选集合。
7. Databay — HTTP / HTTPS / SOCKS4 / SOCKS5。
8. Proxio — HTTP / HTTPS / SOCKS4 / SOCKS5。

## 重要原则

来源网站的 `residential`、`elite` 等标签都只是候选元数据，不直接决定最终分类。

所有代理必须经过本项目自己的：

- TCP 预检
- sing-box 实际代理测试
- 出口 IP 获取
- 国家/ASN/ISP 交叉判断
- Hosting / Datacenter / Mobile / Residential 判断
- Broadcast / Anycast / CDN 剔除
- MITM / TLS 风险检测
- 稳定性复测
- Scamalytics / ipapi.is 风险交叉验证
- 出口 IP 去重

因此 `residential` 输出表示“本项目最终判断为家宽/移动家宽”，不是简单复制来源网站标签。
