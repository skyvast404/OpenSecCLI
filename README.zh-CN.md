<p align="center">
  <strong>一个 CLI，覆盖你的整个安全工作流。</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/openseccli"><img src="https://img.shields.io/npm/v/openseccli?style=flat-square&color=cb3837" alt="npm"></a>
  <a href="https://nodejs.org"><img src="https://img.shields.io/node/v/openseccli?style=flat-square&color=339933" alt="node"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/user/OpenSecCLI?style=flat-square" alt="license"></a>
  <img src="https://img.shields.io/badge/tests-337%20passed-brightgreen?style=flat-square" alt="tests">
  <img src="https://img.shields.io/badge/commands-84-blue?style=flat-square" alt="commands">
  <img src="https://img.shields.io/badge/claude%20code%20skills-35-blueviolet?style=flat-square" alt="skills">
</p>

<p align="center">
  <a href="./README.md">English</a> | 中文文档
</p>

---

<p align="center">
  <img src="demo/demo.gif" alt="OpenSecCLI Demo" width="800">
</p>

## OpenSecCLI 是什么？

OpenSecCLI 将 **84 条安全命令**、**20 个数据源**、**11 个安全领域** 统一到一个 CLI 里。威胁情报查询、漏洞扫描、渗透测试、云安全审计、Agent 安全评估 -- 全部使用统一的 JSON 输出和管道友好设计。

为**安全工程师**打造：一个工具替代二十个。为 **AI Agent** 打造：结构化输出、可预测的错误处理。

```bash
npm install -g openseccli
```

## 快速上手

```bash
# 多源威胁情报 -- 并行查询 5 个 API，返回共识判定
$ opensec enrichment ip-enrich 203.0.113.5

  Source        Status   Verdict      Detail
  AbuseIPDB     ok       Malicious    abuse_score: 100, country: DE, total_reports: 847
  VirusTotal    ok       Malicious    malicious: 12, as_owner: Hetzner
  GreyNoise     ok       Malicious    classification: malicious, noise: true
  ipinfo        ok       -            country: DE, org: Hetzner, city: Falkenstein
  ThreatFox     ok       Known IOC    threat_type: botnet_cc, malware: Cobalt Strike

# 安全响应头审计，A-F 评级（零外部依赖）
$ opensec vuln header-audit --url https://example.com

# 内置 XSS/SQLi/路径穿越 Payload 的参数模糊测试
$ opensec pentest fuzz --url "https://target.com/search?q=test" --payloads xss

# 扫描 MCP 服务器工具描述中的提示注入与 rug-pull 风险
$ opensec agent-security mcp-audit ./mcp-config.json

# CVE 查询 -- 无需 API Key
$ opensec nvd cve-get CVE-2024-3094
┌───────────────┬────────────┬──────────┬──────────┬─────────────────────┬──────────────────────────────────────┐
│ cve_id        │ cvss_score │ severity │ status   │ published           │ description                          │
├───────────────┼────────────┼──────────┼──────────┼─────────────────────┼──────────────────────────────────────┤
│ CVE-2024-3094 │ 10         │ CRITICAL │ Modified │ 2024-03-29T17:15:21 │ Malicious code was discovered in ... │
└───────────────┴────────────┴──────────┴──────────┴─────────────────────┴──────────────────────────────────────┘
```

## 为什么选 OpenSecCLI？

| | 没有 OpenSecCLI | 有 OpenSecCLI |
|---|---|---|
| **威胁情报** | 5 个 API，5 套认证，5 种输出格式 | `opensec enrichment ip-enrich <ip>` |
| **漏洞扫描** | 分别安装 nuclei + nikto + testssl + 自定义脚本 | `opensec vuln nuclei-scan <target>` |
| **Agent 安全** | 没有标准工具 | `opensec agent-security mcp-audit <path>` |
| **输出格式** | 每个工具的输出都不一样 | 统一 `--format json\|csv\|yaml\|table\|markdown` |
| **自动化** | 需要胶水脚本串联各工具 | stdin/stdout 管道、JSON 错误、空结果返回 exit 0 |

## 安装

### npm（推荐）

```bash
npm install -g openseccli
opensec --help
```

### Docker

```bash
# Lite（~200 MB）-- 纯 TS 适配器，无需外部工具
docker build -t opensec .
docker run -it opensec vuln header-audit --url https://example.com

# Full（~3 GB）-- 包含 nuclei、subfinder、semgrep、trivy 等 40+ 工具
docker build -t opensec-full --target full .
docker run -it opensec-full vuln nuclei-scan https://target.com
```

### 从源码构建

```bash
git clone https://github.com/user/OpenSecCLI.git
cd OpenSecCLI
npm install
npm run build
node dist/main.js --help
```

## 命令速览

**84 条命令**，覆盖 11 个安全领域。其中 10 条命令以**纯 TypeScript** 实现，零外部依赖。

<details>
<summary><strong>威胁情报</strong> -- 8 条命令（无需 API Key）</summary>

| 命令 | 说明 |
|------|------|
| `opensec abuse.ch urlhaus-query --url <url>` | URLhaus 恶意 URL 检查 |
| `opensec abuse.ch malwarebazaar-query --hash <hash>` | MalwareBazaar 恶意样本查询 |
| `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox IOC 搜索 |
| `opensec abuse.ch feodo-list` | Feodo Tracker 僵尸网络 C&C 列表 |
| `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL 恶意 SSL 证书搜索 |
| `opensec nvd cve-get <cve-id>` | CVE 详情 |
| `opensec nvd cve-search --keyword <term>` | CVE 关键词搜索 |
| `opensec crtsh cert-search --domain <domain>` | 证书透明度搜索 |

</details>

<details>
<summary><strong>威胁情报</strong> -- 7 条命令（免费 API Key）</summary>

| 命令 | 免费额度 |
|------|---------|
| `opensec abuseipdb ip-check <ip>` | 1,000 次/天 |
| `opensec virustotal hash-lookup <hash>` | 500 次/天 |
| `opensec virustotal ip-lookup <ip>` | 500 次/天 |
| `opensec virustotal domain-lookup <domain>` | 500 次/天 |
| `opensec greynoise ip-check <ip>` | 50 次/天 |
| `opensec ipinfo ip-lookup <ip>` | 50K 次/月 |
| `opensec shodan host-lookup <ip>` | 有限免费 |

</details>

<details>
<summary><strong>多源聚合</strong> -- 4 条命令</summary>

| 命令 | 聚合数据源 |
|------|-----------|
| `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VirusTotal + GreyNoise + ipinfo + ThreatFox |
| `opensec enrichment domain-enrich <domain>` | 多源域名情报 |
| `opensec enrichment hash-enrich <hash>` | 多源哈希信誉查询 |
| `opensec enrichment url-enrich <url>` | 多源 URL 分析 |

</details>

<details>
<summary><strong>侦查（Recon）</strong> -- 12 条命令</summary>

| 命令 | 后端 |
|------|------|
| `opensec recon subdomain-enum <domain>` | subfinder / amass |
| `opensec recon tech-fingerprint <target>` | httpx / whatweb |
| `opensec recon port-scan <target>` | nmap / masscan |
| `opensec recon fast-scan <target>` | masscan |
| `opensec recon content-discover <url>` | ffuf / dirsearch |
| `opensec recon dns-resolve <domain>` | dnsx |
| `opensec recon url-crawl <url>` | katana |
| `opensec recon url-archive <domain>` | gau |
| `opensec recon wayback-urls <domain>` | waybackurls |
| `opensec recon web-spider <url>` | gospider |
| `opensec recon param-discover <url>` | paramspider |
| `opensec recon osint-harvest <domain>` | theHarvester |

</details>

<details>
<summary><strong>漏洞扫描（Vuln）</strong> -- 9 条命令</summary>

| 命令 | 后端 |
|------|------|
| `opensec vuln nuclei-scan <target>` | nuclei |
| `opensec vuln nikto-scan <target>` | nikto |
| `opensec vuln header-audit <url>` | **纯 TS** -- CSP 解析、Cookie 分析、A-F 评级 |
| `opensec vuln tls-check <host>` | testssl.sh |
| `opensec vuln cors-check <url>` | **纯 TS** -- CORS 配置错误检测 |
| `opensec vuln api-discover <url>` | kiterunner / ffuf |
| `opensec vuln xss-scan <url>` | dalfox |
| `opensec vuln crlf-scan <url>` | crlfuzz |
| `opensec vuln graphql-audit <url>` | GraphQL 内省 |

</details>

<details>
<summary><strong>渗透工具（Pentest）</strong> -- 6 条命令</summary>

| 命令 | 后端 |
|------|------|
| `opensec pentest http-request <url>` | **纯 TS** -- 构造 HTTP 请求 |
| `opensec pentest race-test <url>` | **纯 TS** -- 并发竞态条件测试 |
| `opensec pentest fuzz <url>` | **纯 TS** -- XSS/SQLi/路径穿越 Payload 模糊测试 |
| `opensec pentest jwt-test <token>` | **纯 TS** -- JWT 漏洞测试 |
| `opensec pentest sqli-scan <url>` | sqlmap |
| `opensec pentest cmdi-scan <url>` | commix |

</details>

<details>
<summary><strong>SAST 与扫描流水线</strong> -- 11 条命令</summary>

| 命令 | 说明 |
|------|------|
| `opensec scan full <path>` | 完整流水线：发现、分析、报告 |
| `opensec scan discover <path>` | 构建安全项目地图 |
| `opensec scan analyze <path>` | 静态分析（semgrep、gitleaks）+ 自定义规则 |
| `opensec scan report <path>` | 生成报告（JSON、SARIF、Markdown） |
| `opensec scan entrypoints <path>` | 查找 HTTP 路由、RPC Handler |
| `opensec scan git-signals <path>` | 提取安全相关 Git 提交 |
| `opensec scan context-builder <path>` | 构建面向 LLM 的代码上下文包 |
| `opensec scan triage-memory` | 假阳性跟踪与跳过逻辑 |
| `opensec scan benchmark <path>` | 扫描器基准测试（precision/recall/F1） |
| `opensec scan gosec-scan <path>` | Go 安全扫描 |
| `opensec scan bandit-scan <path>` | Python 安全检查 |

</details>

<details>
<summary><strong>Agent 安全</strong> -- 9 条命令</summary>

| 命令 | 说明 |
|------|------|
| `opensec agent-security scan-skill <path>` | 扫描 Claude Code Skills 的提示注入与数据泄露 |
| `opensec agent-security mcp-audit <path>` | 审计 MCP 工具描述的投毒与 rug-pull 风险 |
| `opensec agent-security grade-results <file>` | 评分：SAFE / UNSAFE / BLOCKED / INCONCLUSIVE |
| `opensec agent-security analyze-coverage <file>` | 覆盖率 vs OWASP ASI Top 10 & MITRE ATLAS |
| `opensec agent-security defense-validation <file>` | 防御有效性（precision/recall/F1） |
| `opensec agent-security manage-kb` | 管理攻击模式与检测规则知识库 |
| `opensec agent-security normalize-cases <file>` | 规范化测试源为标准攻击用例格式 |
| `opensec agent-security generate-variants <file>` | 展开清单为变异测试用例 |
| `opensec agent-security write-report <file>` | 从评分结果生成评估报告 |

</details>

<details>
<summary><strong>供应链、云安全、密钥检测、取证、密码学、DAST</strong></summary>

**供应链**（4 条命令）

| 命令 | 后端 |
|------|------|
| `opensec supply-chain dep-audit [path]` | npm-audit + pip-audit + trivy |
| `opensec supply-chain ci-audit [path]` | **纯 TS** -- CI 配置安全检查 |
| `opensec supply-chain sbom [path]` | syft |
| `opensec supply-chain snyk-scan [path]` | snyk |

**云安全**（7 条命令）

| 命令 | 后端 |
|------|------|
| `opensec cloud iac-scan [path]` | checkov / terrascan |
| `opensec cloud container-scan <image>` | trivy / grype |
| `opensec cloud kube-audit` | kube-bench |
| `opensec cloud dockerfile-lint <path>` | hadolint |
| `opensec cloud kube-security` | kubesec |
| `opensec cloud container-lint <image>` | dockle |
| `opensec cloud cloud-posture` | prowler / scout suite |

**密钥检测**（1 条命令）

| 命令 | 后端 |
|------|------|
| `opensec secrets trufflehog-scan <target>` | trufflehog |

**取证**（4 条命令）

| 命令 | 后端 |
|------|------|
| `opensec forensics file-analyze <file>` | file + exiftool + strings + binwalk |
| `opensec forensics binary-check <binary>` | checksec |
| `opensec forensics pcap-summary <pcap>` | tshark |
| `opensec forensics apk-analyze <apk>` | aapt + strings |

**密码学**（1 条命令）

| 命令 | 后端 |
|------|------|
| `opensec crypto hash-id <hash>` | **纯 TS** -- 识别哈希类型 + hashcat/john 格式 |

**DAST**（1 条命令）

| 命令 | 后端 |
|------|------|
| `opensec dast zap-scan <target>` | OWASP ZAP |

</details>

## Claude Code Skills（30 个）

OpenSecCLI 附带 **30 个 AI 驱动的安全工作流**，以 Claude Code 斜杠命令形式使用。每个 Skill 编排多条 `opensec` 命令，构成完整的调查或渗透流程。

<details>
<summary><strong>威胁情报与应急响应</strong>（5 个）</summary>

| Skill | 用途 |
|-------|------|
| `/ioc-investigate` | 跨多个威胁情报源的 IOC 深度分析 |
| `/incident-response` | 引导式应急响应：分类、取证、遏制 |
| `/cve-impact-check` | 评估 CVE 对你的基础设施的影响 |
| `/threat-hunting` | 主动威胁狩猎：日志与遥测分析 |
| `/osint-deep-dive` | 开源情报深度调查 |

</details>

<details>
<summary><strong>渗透测试</strong>（6 个）</summary>

| Skill | 用途 |
|-------|------|
| `/web-pentest` | Web 应用渗透测试全流程 |
| `/api-pentest` | API 安全测试：认证、IDOR、注入、限流 |
| `/network-pentest` | 网络渗透：扫描、枚举、利用 |
| `/ai-llm-pentest` | AI/LLM 应用渗透：提示注入、越狱、数据泄露 |
| `/bug-bounty-workflow` | 端到端漏洞赏金工作流 |
| `/red-team-recon` | 红队侦查与初始访问 |

</details>

<details>
<summary><strong>代码与应用安全</strong>（6 个）</summary>

| Skill | 用途 |
|-------|------|
| `/code-security-audit` | 自动化源代码安全审计 |
| `/whitebox-code-review` | 白盒代码审查（污点分析） |
| `/semantic-hunter` | 超越模式匹配的语义漏洞挖掘 |
| `/detect-semantic-attack` | 检测语义攻击：后门、逻辑炸弹 |
| `/business-logic-test` | 业务逻辑漏洞测试 |
| `/missed-patch-hunter` | 查找不完整修复与遗漏补丁 |

</details>

<details>
<summary><strong>基础设施与供应链</strong>（5 个）</summary>

| Skill | 用途 |
|-------|------|
| `/supply-chain-audit` | 供应链安全审计 |
| `/cloud-audit` | 云安全态势评估 |
| `/container-security` | 容器与镜像安全评估 |
| `/devsecops-pipeline` | DevSecOps 流水线安全审查 |
| `/compliance-check` | 合规验证（SOC2、PCI-DSS、HIPAA） |

</details>

<details>
<summary><strong>Agent 安全与研究</strong>（4 个）</summary>

| Skill | 用途 |
|-------|------|
| `/agent-security-suite` | 完整的 Agent/LLM 安全测试套件 |
| `/agent-attack-research` | Agent 攻击研究与新技术发现 |
| `/dast-assessment` | 动态应用安全测试工作流 |
| `/ctf-toolkit` | CTF 竞赛解题工具包 |

</details>

<details>
<summary><strong>分类与侦查</strong>（4 个）</summary>

| Skill | 用途 |
|-------|------|
| `/attack-surface-map` | 映射域名/组织的外部攻击面 |
| `/domain-recon` | 全面域名侦查与情报收集 |
| `/security-triage` | 安全发现的分类与优先级排序 |
| `/exploit-validation` | 漏洞利用验证与 PoC 开发 |

</details>

## Agent 友好设计

OpenSecCLI 天生适合 AI Agent 和自动化流水线：

```bash
# 结构化 JSON 输出走 stdout，状态信息走 stderr
opensec nvd cve-search --keyword log4j --json 2>/dev/null | jq '.[0]'

# 空结果返回 exit 0 + 空数组（不是错误）
opensec abuse.ch threatfox-search --ioc "clean-domain.com" --json
# → []

# stdin 管道 -- 兼容 ProjectDiscovery 生态
subfinder -d target.com -silent | opensec enrichment domain-enrich --json
cat ips.txt | opensec abuseipdb ip-check --json | jq 'select(.abuse_score > 80)'
echo "CVE-2024-3094" | opensec nvd cve-get --json

# 5 种输出格式
opensec nvd cve-get CVE-2024-3094 --format json
opensec nvd cve-get CVE-2024-3094 --format csv
opensec nvd cve-get CVE-2024-3094 --format yaml
opensec nvd cve-get CVE-2024-3094 --format markdown
opensec nvd cve-get CVE-2024-3094                      # table（默认）
```

## 认证管理

```bash
opensec auth add virustotal --api-key     # 交互式输入，加密存储
opensec auth add abuseipdb --api-key
opensec auth list                          # 查看已配置的提供商
opensec auth test virustotal               # 验证连通性
opensec auth remove virustotal             # 删除凭据
```

凭据存储在 `~/.openseccli/auth/`，权限 `0600`。支持环境变量覆盖：`OPENSECCLI_VIRUSTOTAL_API_KEY`。

## 贡献

**添加一个新 API 只需一个 YAML 文件。** 不需要写 TypeScript。

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

更复杂的集成可以写 TypeScript 适配器。详见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

**插件系统：** 第三方适配器可通过 `opensec plugin install github:user/repo` 安装到 `~/.openseccli/plugins/`。

### 等待认领的 API

urlscan.io、Censys、SecurityTrails、Pulsedive、PhishTank、Hybrid Analysis、AlienVault OTX、EmailRep.io、IBM X-Force、Hunter.io、CIRCL hashlookup、MaxMind GeoLite2、Tor Exit Node List -- [查看 Issues](../../issues)。

## Autopilot — 一条命令搞定一切

```bash
$ opensec autopilot https://target.com

  ═══════════════════════════════════════════
   OpenSecCLI Autopilot 报告
  ═══════════════════════════════════════════
   目标: https://target.com
   评级:  C (54/100)
   发现: 43 项 (2 严重, 8 高危)
   耗时: 18.2s
  ═══════════════════════════════════════════

$ opensec report opensec-report/autopilot-report.json
# → 生成专业 HTML 报告
```

## MCP Server — AI Agent 集成

```bash
# 添加到 Claude Desktop / Cursor MCP 配置:
{
  "mcpServers": {
    "opensec": {
      "command": "npx",
      "args": ["openseccli", "mcp"]
    }
  }
}
# 任何 AI Agent 都可以调用 84 条安全命令作为工具
```

## 声明式工作流

```bash
$ opensec workflow run workflows/web-audit.yaml --target example.com

  [1/4] ✓ 安全头审计 (1.1s) — 11 项发现
  [2/4] ✓ CORS 检查 (3.3s) — 10 项发现
  [3/4] ✓ 证书检查 (0.5s) — 20 项发现
  [4/4] ✓ 技术指纹 (2.5s) — 1 项发现
```

## 架构

```
Commander.js CLI
    |
    +-- YAML 适配器 (15) --------> 流水线引擎: request -> select -> map -> filter -> sort -> limit -> enrich
    +-- TypeScript 适配器 (69) --> 直接实现，完全控制
    |
    +-- 单例注册表 (globalThis)
    +-- Manifest 编译 (YAML -> JSON, 构建时)
    +-- 插件系统 (~/.openseccli/plugins/, 生命周期钩子)
    +-- 输出格式化器 (table | json | csv | yaml | markdown)
```

双轨适配器系统：**YAML** 用于简单 API 封装（一个文件，无需编码），**TypeScript** 用于复杂逻辑（解析器、多步工作流、纯 TS 扫描器）。两者以相同方式注册到命令树中。

架构详情见 [BLUEPRINT.md](./BLUEPRINT.md)。

## Star 趋势

[![Star History Chart](https://api.star-history.com/svg?repos=skyvast404/OpenSecCLI&type=Date)](https://star-history.com/#skyvast404/OpenSecCLI&Date)

## 开源协议

[Apache-2.0](./LICENSE)
