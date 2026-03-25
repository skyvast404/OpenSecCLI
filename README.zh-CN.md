# OpenSecCLI

**开源安全 CLI 中枢 — 查询、聚合、自动化。**

[English](README.md) | 中文

一个 YAML 文件就能把任何安全 API 变成 CLI 命令。灵感来自 [OpenCLI](https://github.com/jackwener/opencli)。

```bash
# 安装
npm install -g openseccli

# 查询 CVE（无需 API Key）
opensec nvd cve-get CVE-2024-3094

# 检查 IP 是否恶意（无需 API Key）
opensec abuse.ch threatfox-search --ioc 185.220.101.34

# 搜索证书透明度日志
opensec crtsh cert-search --domain example.com

# 多源 IP 情报聚合（杀手功能）
opensec enrichment ip-enrich 185.220.101.34

  Source        Verdict      Detail
  AbuseIPDB     Malicious    abuse_score: 100, reports: 847
  GreyNoise     Malicious    classification: malicious, tags: [tor, scanner]
  VirusTotal    Malicious    malicious_votes: 12
  ipinfo        —            country: DE, org: Hetzner
  ThreatFox     Known IOC    malware: Cobalt Strike

  Consensus: MALICIOUS (4/5 sources)

# 与 ProjectDiscovery 工具链组合
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec enrichment ip-enrich --json | jq '.verdict'
```

## 为什么用 OpenSecCLI？

| 以前 | 现在 |
|------|------|
| 登录 VirusTotal 网页 → 粘贴 hash → 等待 → 复制结果 | `opensec virustotal hash-lookup <sha256>` |
| 逐个查 5 个威胁情报平台 | `opensec enrichment ip-enrich <ip>`（并行查询，一条命令） |
| 每次自动化都要写 Python 脚本 | 写一个 YAML 文件，就有了 CLI 命令 |
| 每个工具输出格式不一样 | 统一的 `--format table|json|csv` |

## 已有适配器

### 无需 API Key（开箱即用）

| 提供商 | 命令 | 功能 |
|--------|------|------|
| abuse.ch | `opensec abuse.ch urlhaus-query --url <url>` | URLhaus 恶意 URL 检查 |
| abuse.ch | `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar 恶意样本查询 |
| abuse.ch | `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC 搜索 |
| abuse.ch | `opensec abuse.ch feodo-list` | Feodo Tracker 僵尸网络 C&C 列表 |
| abuse.ch | `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL 恶意 SSL 证书搜索 |
| NVD | `opensec nvd cve-get <cve-id>` | CVE 详情查询 |
| NVD | `opensec nvd cve-search --keyword <term>` | CVE 关键词搜索 |
| crt.sh | `opensec crtsh cert-search --domain <domain>` | 证书透明度日志搜索 |

### 需要免费 API Key（注册即可使用）

| 提供商 | 命令 | 免费额度 |
|--------|------|---------|
| AbuseIPDB | `opensec abuseipdb ip-check <ip>` | 1,000 次/天 |
| VirusTotal | `opensec virustotal hash-lookup <hash>` | 500 次/天 |
| GreyNoise | `opensec greynoise ip-check <ip>` | 50 次/天 |
| Shodan | `opensec shodan host-lookup <ip>` | 有限免费 |
| ipinfo | `opensec ipinfo ip-lookup <ip>` | 50K 次/月 |

### 多源聚合查询

| 命令 | 聚合的数据源 |
|------|-------------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VT + GreyNoise + ipinfo + ThreatFox |
| `opensec enrichment domain-enrich <domain>` | VT + crt.sh + Shodan + WHOIS |
| `opensec enrichment hash-enrich <hash>` | VT + MalwareBazaar + ThreatFox |

## 认证管理

```bash
# 添加 API Key（交互式输入，加密存储）
opensec auth add virustotal --api-key
opensec auth add abuseipdb --api-key

# 查看已配置的提供商
opensec auth list

# 测试连通性
opensec auth test virustotal
```

## 输出格式

```bash
opensec nvd cve-get CVE-2024-3094                    # table（默认）
opensec nvd cve-get CVE-2024-3094 --format json       # JSON
opensec nvd cve-get CVE-2024-3094 --format csv        # CSV
opensec nvd cve-get CVE-2024-3094 --json               # JSON 简写
opensec nvd cve-get CVE-2024-3094 -o result.json       # 保存到文件
```

所有命令的数据输出到 stdout，状态/错误输出到 stderr，pipe 始终可用：

```bash
opensec nvd cve-search --keyword log4j --json | jq '.[].cve_id'
opensec abuse.ch feodo-list --format csv > botnet_c2.csv
```

## 贡献 Adapter

添加新的安全 API 只需要**一个 YAML 文件**：

```yaml
# src/adapters/urlscan/scan.yaml
provider: urlscan
name: scan
description: Submit URL for scanning on urlscan.io
strategy: API_KEY
auth: urlscan

args:
  url:
    type: string
    required: true
    help: URL to scan

pipeline:
  - request:
      url: https://urlscan.io/api/v1/scan/
      method: POST
      headers:
        API-Key: "{{ auth.api_key }}"
        Content-Type: application/json
      body:
        url: "{{ args.url }}"

  - map:
      template:
        uuid: "{{ item.uuid }}"
        url: "{{ item.url }}"
        visibility: "{{ item.visibility }}"
        result_url: "{{ item.result }}"

columns: [uuid, url, visibility, result_url]
```

完整指南见 [CONTRIBUTING.md](CONTRIBUTING.md)。

## 与 ProjectDiscovery 生态兼容

OpenSecCLI 遵循 ProjectDiscovery 的约定（`--json`、`--silent`、stdin 支持）：

```bash
# 用 subfinder 发现子域名后聚合情报
subfinder -d target.com -silent | opensec enrichment domain-enrich --json

# 过滤高风险 IP 后送入 nuclei 扫描
cat ips.txt | opensec abuseipdb ip-check --json | \
  jq -r 'select(.abuse_score > 80) | .ip' | nuclei -t cves/

# 从文件批量检查 IOC
cat suspicious_hashes.txt | opensec abuse.ch malwarebazaar-query --json
```

## 架构

基于 [OpenCLI](https://github.com/jackwener/opencli) 相同的架构模式：

- **YAML + TypeScript 双轨适配器** — 简单 API 用 YAML，复杂逻辑用 TypeScript
- **Pipeline 执行引擎** — `request → select → map → filter → sort → limit`
- **单例命令注册表** — `globalThis` 模式保证模块安全
- **Manifest 编译** — 构建时 YAML 编译为 JSON，启动零解析开销
- **插件系统** — `opensec plugin install github:user/repo`
- **生命周期钩子** — `onStartup`、`onBeforeExecute`、`onAfterExecute`

完整架构文档见 [BLUEPRINT.md](BLUEPRINT.md)。

## 开源协议

Apache-2.0
