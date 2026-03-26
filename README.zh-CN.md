# OpenSecCLI

> 一个 YAML 文件，把任何安全 API 变成 CLI 命令。

[English](./README.md) | 中文文档

[![npm version](https://img.shields.io/npm/v/openseccli?style=flat-square)](https://www.npmjs.com/package/openseccli)
[![Node.js](https://img.shields.io/node/v/openseccli?style=flat-square)](https://nodejs.org)
[![License](https://img.shields.io/github/license/user/OpenSecCLI?style=flat-square)](./LICENSE)

```bash
npm install -g openseccli
```

```bash
$ opensec nvd cve-get CVE-2024-3094
┌───────────────┬────────────┬──────────┬──────────┬─────────────────────┬──────────────────────────────────────┐
│ cve_id        │ cvss_score │ severity │ status   │ published           │ description                          │
├───────────────┼────────────┼──────────┼──────────┼─────────────────────┼──────────────────────────────────────┤
│ CVE-2024-3094 │ 10         │ CRITICAL │ Modified │ 2024-03-29T17:15:21 │ Malicious code was discovered in ... │
└───────────────┴────────────┴──────────┴──────────┴─────────────────────┴──────────────────────────────────────┘
1 item · 1.0s · from nvd
```

## 亮点

- **62 条命令**，覆盖 19 个提供商 —— 侦查、漏洞扫描、密钥检测、供应链、云安全、取证、Agent 安全、SAST 等全覆盖
- **6 个纯 TypeScript 适配器**，零外部依赖（header-audit、cors-check、hash-id、http-request、race-test、ci-audit）
- **22 个 Claude Code Skills** —— AI 驱动的调查与渗透工作流（IOC 调查、代码审计、应急响应、Web/API/网络渗透、Agent 安全等）
- **多源聚合查询** —— 并行查 5 个威胁情报 API，输出共识判定
- **一个 YAML = 一条命令** —— 贡献者不需要写 TypeScript
- **原生管道** —— stdin/stdout、`--json`、`--silent`，兼容 ProjectDiscovery 生态
- **5 种输出格式** —— table、JSON、CSV、YAML、Markdown
- **架构源自 [OpenCLI](https://github.com/jackwener/opencli)** —— 相同架构，安全聚焦

## 快速开始

```bash
# 无需 API Key —— 装完即用
opensec nvd cve-search --keyword log4j --limit 5
opensec abuse.ch threatfox-search --ioc 185.220.101.34
opensec crtsh cert-search --domain example.com
opensec abuse.ch feodo-list --limit 10

# 添加 API Key 解锁更多数据源
opensec auth add virustotal --api-key
opensec auth add abuseipdb --api-key

# 多源 IP 情报聚合（杀手功能）
opensec enrichment ip-enrich 185.220.101.34
```

## 多源聚合

一条命令。五个数据源。并行查询。共识判定。

```bash
$ opensec enrichment ip-enrich 185.220.101.34

  Source        Status   Verdict      Detail
  AbuseIPDB     ok       Malicious    abuse_score: 100, country: DE, total_reports: 847
  VirusTotal    ok       Malicious    malicious: 12, as_owner: Hetzner
  GreyNoise     ok       Malicious    classification: malicious, noise: true
  ipinfo        ok       -            country: DE, org: Hetzner, city: Falkenstein
  ThreatFox     ok       Known IOC    threat_type: botnet_cc, malware: Cobalt Strike
```

只查询你已配置 Key 的数据源。ThreatFox 永久免费。

## 内置命令

### 无需 API Key

| 提供商 | 命令 | 说明 |
|--------|------|------|
| abuse.ch | `opensec abuse.ch urlhaus-query --url <url>` | URLhaus 恶意 URL 检查 |
| abuse.ch | `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar 恶意样本查询 |
| abuse.ch | `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC 搜索 |
| abuse.ch | `opensec abuse.ch feodo-list` | Feodo Tracker 僵尸网络 C&C 列表 |
| abuse.ch | `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL 恶意 SSL 证书搜索 |
| NVD | `opensec nvd cve-get <cve-id>` | CVE 详情查询 |
| NVD | `opensec nvd cve-search --keyword <term>` | CVE 关键词搜索 |
| crt.sh | `opensec crtsh cert-search --domain <domain>` | 证书透明度搜索 |

### 需要 API Key（免费额度）

| 提供商 | 命令 | 免费额度 |
|--------|------|---------|
| AbuseIPDB | `opensec abuseipdb ip-check <ip>` | 1,000 次/天 |
| VirusTotal | `opensec virustotal hash-lookup <hash>` | 500 次/天 |
| VirusTotal | `opensec virustotal ip-lookup <ip>` | 500 次/天 |
| VirusTotal | `opensec virustotal domain-lookup <domain>` | 500 次/天 |
| GreyNoise | `opensec greynoise ip-check <ip>` | 50 次/天 |
| ipinfo | `opensec ipinfo ip-lookup <ip>` | 50K 次/月 |
| Shodan | `opensec shodan host-lookup <ip>` | 有限免费 |

### 多源聚合

| 命令 | 聚合数据源 |
|------|-----------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VirusTotal + GreyNoise + ipinfo + ThreatFox |

### 侦查（Recon）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec recon subdomain-enum <domain>` | subfinder / amass | 子域名枚举 |
| `opensec recon tech-fingerprint <target>` | httpx / whatweb | 技术指纹识别 |
| `opensec recon port-scan <target>` | nmap / masscan | 端口扫描 |
| `opensec recon content-discover <url>` | ffuf / dirsearch | 目录/内容发现 |

### 漏洞扫描（Vuln）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec vuln nuclei-scan <target>` | nuclei | 基于模板的漏洞扫描 |
| `opensec vuln nikto-scan <target>` | nikto | Web 服务器扫描 |
| `opensec vuln header-audit <url>` | 纯 TS | 安全响应头分析（零依赖） |
| `opensec vuln tls-check <host>` | testssl.sh | TLS/SSL 配置检查 |
| `opensec vuln cors-check <url>` | 纯 TS | CORS 配置错误检查（零依赖） |
| `opensec vuln api-discover <url>` | kiterunner / ffuf | API 端点发现 |

### 密钥检测（Secrets）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec secrets trufflehog-scan <target>` | trufflehog | 仓库/文件系统密钥扫描 |

### 供应链（Supply Chain）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec supply-chain dep-audit [path]` | npm-audit + pip-audit + trivy | 依赖漏洞审计 |
| `opensec supply-chain ci-audit [path]` | 纯 TS | CI 配置安全检查（零依赖） |
| `opensec supply-chain sbom [path]` | syft | 软件物料清单生成 |

### 云安全（Cloud）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec cloud iac-scan [path]` | checkov / terrascan | 基础设施即代码扫描 |
| `opensec cloud container-scan <image>` | trivy / grype | 容器镜像漏洞扫描 |
| `opensec cloud kube-audit` | kube-bench | Kubernetes CIS 基准审计 |

### 取证（Forensics）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec forensics file-analyze <file>` | file + exiftool + strings + binwalk | 文件元数据与内容分析 |
| `opensec forensics binary-check <binary>` | checksec | 二进制安全特性检查 |
| `opensec forensics pcap-summary <pcap>` | tshark | PCAP 流量摘要 |
| `opensec forensics apk-analyze <apk>` | aapt + strings | Android APK 静态分析 |

### 密码学（Crypto）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec crypto hash-id <hash>` | 纯 TS | 识别哈希类型 + hashcat/john 格式（零依赖） |

### 渗透工具（Pentest）

| 命令 | 后端 | 说明 |
|------|------|------|
| `opensec pentest http-request <url>` | 纯 TS | 构造 HTTP 请求发送（零依赖） |
| `opensec pentest race-test <url>` | 纯 TS | 并发竞态条件测试（零依赖） |
| `opensec pentest fuzz <url>` | 纯 TS | 参数模糊测试（安全 Payload） |

### Agent 安全（Agent Security）

| 命令 | 说明 |
|------|------|
| `opensec agent-security scan-skill <path>` | 扫描 Claude Code Skills 的提示注入、数据泄露、凭据暴露 |
| `opensec agent-security mcp-audit <path>` | 审计 MCP 服务器工具描述的投毒与 rug-pull 风险 |
| `opensec agent-security grade-results <file>` | 评分 Agent 安全测试结果（SAFE/UNSAFE/BLOCKED/INCONCLUSIVE） |
| `opensec agent-security analyze-coverage <file>` | 分析攻击语料库对 OWASP ASI Top 10 和 MITRE ATLAS 的覆盖率 |
| `opensec agent-security defense-validation <file>` | 验证防御有效性（precision/recall/F1 评分） |
| `opensec agent-security manage-kb` | 管理 Agent 安全知识库（攻击模式、检测规则） |
| `opensec agent-security normalize-cases <file>` | 将原始测试源规范化为标准攻击用例格式 |
| `opensec agent-security generate-variants <file>` | 将套件清单展开为具体的变异测试用例 |
| `opensec agent-security write-report <file>` | 从评分结果生成 Agent 安全评估报告 |

### 静态分析与扫描流水线（SAST & Scan）

| 命令 | 说明 |
|------|------|
| `opensec scan full <path>` | 完整安全扫描流水线：发现、分析、报告 |
| `opensec scan discover <path>` | 构建安全项目地图（语言、框架、入口点） |
| `opensec scan analyze <path>` | 运行静态分析（semgrep、gitleaks）及自定义规则 |
| `opensec scan report <path>` | 生成扫描报告（JSON、SARIF、Markdown） |
| `opensec scan entrypoints <path>` | 查找 HTTP 路由、RPC Handler 等入口点 |
| `opensec scan git-signals <path>` | 从 Git 历史中提取安全相关提交 |
| `opensec scan context-builder <path>` | 构建面向 LLM 分析的安全代码上下文包 |
| `opensec scan triage-memory` | 管理分类记忆：假阳性跟踪与跳过逻辑 |
| `opensec scan benchmark <path>` | 运行扫描器基准测试，度量检测质量（precision/recall/F1） |

## Claude Code Skills

22 个 AI 驱动的调查与渗透工作流，可作为 Claude Code 斜杠命令使用：

| Skill | 说明 |
|-------|------|
| `ioc-investigate` | 跨多个威胁情报源的 IOC 深度分析 |
| `code-security-audit` | 自动化源代码安全审计 |
| `incident-response` | 引导式应急响应分类与证据收集 |
| `cve-impact-check` | 评估 CVE 对基础设施的影响 |
| `attack-surface-map` | 映射域名/组织的外部攻击面 |
| `domain-recon` | 全面域名侦查与情报收集 |
| `web-pentest` | Web 应用渗透测试工作流 |
| `api-pentest` | API 安全测试工作流 |
| `network-pentest` | 网络渗透测试工作流 |
| `supply-chain-audit` | 供应链安全审计 |
| `cloud-audit` | 云安全态势评估 |
| `whitebox-code-review` | 白盒代码安全审查 |
| `business-logic-test` | 业务逻辑漏洞测试 |
| `exploit-validation` | 漏洞利用验证与 PoC |
| `semantic-hunter` | 语义漏洞挖掘 |
| `security-triage` | 安全发现分类与优先级排序 |
| `missed-patch-hunter` | 查找遗漏补丁与不完整修复 |
| `detect-semantic-attack` | 检测代码中的语义攻击 |
| `agent-security-suite` | Agent/LLM 安全测试套件 |
| `agent-attack-research` | Agent 攻击研究与分析 |
| `ctf-toolkit` | CTF 竞赛解题工具包 |
| `ai-llm-pentest` | AI/LLM 应用渗透测试 |

## 输出格式

```bash
opensec nvd cve-get CVE-2024-3094                 # table（默认）
opensec nvd cve-get CVE-2024-3094 --format json    # JSON
opensec nvd cve-get CVE-2024-3094 --format csv     # CSV
opensec nvd cve-get CVE-2024-3094 --format yaml    # YAML
opensec nvd cve-get CVE-2024-3094 --json            # 简写
```

数据走 stdout，状态走 stderr。管道始终可用：

```bash
opensec nvd cve-search --keyword log4j --json | jq '.[].cve_id'
opensec abuse.ch feodo-list --format csv > botnet_c2.csv
echo "CVE-2024-3094" | opensec nvd cve-get --json
```

## 与 ProjectDiscovery 生态协作

遵循 `-json` / `-silent` / stdin 约定：

```bash
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec abuseipdb ip-check --json | jq 'select(.abuse_score > 80)'
cat hashes.txt | opensec virustotal hash-lookup --json
```

## 认证管理

```bash
opensec auth add virustotal --api-key     # 交互式输入，加密存储
opensec auth add abuseipdb --api-key
opensec auth list                          # 查看已配置的提供商
opensec auth test virustotal               # 验证连通性
opensec auth remove virustotal             # 删除凭据
```

凭据存储在 `~/.openseccli/auth/`，权限 600。环境变量覆盖：`OPENSECCLI_VIRUSTOTAL_API_KEY`。

## 贡献

**添加一个新的安全 API 只需要一个 YAML 文件。** 不需要写 TypeScript。

```yaml
# src/adapters/urlscan/scan.yaml
provider: urlscan
name: scan
description: Submit URL for scanning
strategy: API_KEY
auth: urlscan

args:
  url:
    type: string
    required: true

pipeline:
  - request:
      url: https://urlscan.io/api/v1/scan/
      method: POST
      headers:
        API-Key: "{{ auth.api_key }}"
      body:
        url: "{{ args.url }}"
  - map:
      template:
        uuid: "{{ item.uuid }}"
        result_url: "{{ item.result }}"

columns: [uuid, result_url]
```

完整指南见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

### 等待认领的 API

urlscan.io、Censys、SecurityTrails、Pulsedive、PhishTank、Hybrid Analysis、AlienVault OTX、EmailRep.io、IBM X-Force、Hunter.io、CIRCL hashlookup、MaxMind GeoLite2、Tor Exit Node List — [查看 Issues](../../issues)。

## 检测能力升级

vuln/scan 引擎的近期增强：

- **CSP 解析器** — 完整的 Content-Security-Policy 指令分析（`header-audit`）
- **Cookie 分析器** — SameSite、Secure、HttpOnly、Prefix 验证
- **Payload 库** — 内置 XSS、SQLi、路径穿越模糊测试 Payload
- **自定义 semgrep 规则** — 项目专用 SAST 规则（`scan/rules/`）

## 架构

基于 [OpenCLI](https://github.com/jackwener/opencli) 模式构建：

- **YAML + TypeScript** 双轨适配器
- **Pipeline 引擎** — `request → select → map → filter → sort → limit → enrich`
- **单例注册表** — `globalThis` 模式
- **Manifest 编译** — 构建时 YAML → JSON
- **插件系统** — `opensec plugin install github:user/repo`
- **生命周期钩子** — `onStartup`、`onBeforeExecute`、`onAfterExecute`

架构详情见 [BLUEPRINT.md](./BLUEPRINT.md)。

## 开源协议

[Apache-2.0](./LICENSE)
