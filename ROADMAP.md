# OpenSecCLI Roadmap

## 核心洞察

OpenSecCLI 当前最大的问题：**每次扫描都是一次性的**。没有历史、没有趋势、没有对比。这意味着用户随时可以换掉它，因为没有数据锁定。

竞争态势：HexStrike AI 已有 150+ 工具在 Kali Linux；GitHub Copilot 正在内置安全扫描；ProjectDiscovery 在建云版。**唯一的出路是从"工具聚合器"变成"安全数据平台"。**

---

## Milestone 1: 安全数据平台 (v0.3.0)

> **核心价值：数据重力 — 一旦有了 6 个月的扫描历史，用户就不会离开。**

### 1.1 Finding Database (`opensec db`)

```bash
# 每次扫描自动存入本地 SQLite
opensec autopilot https://target.com
# → 43 findings saved to ~/.openseccli/findings.db

# 查看变化
opensec db diff --since 7d
# → 3 new | 2 resolved | 1 regressed

# 标记误报
opensec db dismiss FINDING-123 --reason "accepted risk"

# 趋势查询
opensec db trend --target example.com --period 30d
# → Critical: 5→3→2 (improving)

# 搜索历史
opensec db search "sql injection" --severity critical
```

**技术方案：** SQLite (better-sqlite3)，~500 行。每个命令的输出处理器写入 DB。

**为什么是护城河：** DefectDojo 做同样的事但需要 Django + Postgres + Celery + Redis（4 个服务）。OpenSecCLI 用一个 SQLite 文件实现同样功能。

### 1.2 Attack Surface Diff

```bash
opensec db diff --target example.com
# 新增子域名: staging.example.com (首次发现于 3 天前)
# 新增端口: 8443/tcp on 203.0.113.5 (首次发现于 1 天前)
# 关闭端口: 22/tcp on 203.0.113.5 (7 天前还开着)
# 新增漏洞: CVE-2024-XXX (header-audit 3 天前首次检测到)
```

### 1.3 CI/CD GitHub Action (`openseccli/action`)

```yaml
- uses: openseccli/action@v1
  with:
    scan: autopilot
    depth: standard
    fail-on: critical,high
    comment-on-pr: true      # PR 内联评论
    compare-baseline: true    # 和 main 分支对比
```

**为什么重要：** 嵌入每个 PR = 不可替代。和 Finding DB 结合 = PR 评论说"这个 PR 引入了 2 个新的 high-severity 问题"。

---

## Milestone 2: AI 安全引擎 (v0.4.0)

> **核心价值：AI 驱动的误报消除 — 从 80% 误报率降到 10%。**

### 2.1 AI Triage (`opensec triage`)

```bash
opensec scan analyze --path . --format json | opensec triage
#
# Finding: SQL injection in src/api/users.ts:42
# Attacker analysis: String concatenation in query, no parameterization → EXPLOITABLE
# Defender analysis: No ORM, no prepared statements, no WAF → NO MITIGATION
# Verdict: CONFIRMED (confidence: 92%)
#
# Finding: XSS in src/views/search.ts:67
# Attacker analysis: User input in template → potential
# Defender analysis: React auto-escaping active, dangerouslySetInnerHTML not used → MITIGATED
# Verdict: FALSE POSITIVE (confidence: 88%)
#
# Results: 12 findings → 3 confirmed, 2 needs-review, 7 false positives
```

**技术方案：** 调用 Claude API（用户提供 ANTHROPIC_API_KEY），对每个 finding 做攻防对抗分析。已有 `security-triage` Skill 的方法论，把它变成 CLI 命令。

### 2.2 Agent Security 深化

```bash
# MCP 注册表扫描 — 批量检查 MCP 服务器
opensec agent-security registry-scan --registry mcp-registry.json

# 运行时监控 — 代理模式，监控 AI Agent 的工具调用
opensec agent-security monitor --proxy localhost:8080
# → 检测异常行为: "code-review 工具正在读取 ~/.ssh/id_rsa"

# 供应链验证 — 验证 MCP 包完整性
opensec agent-security verify --package @modelcontextprotocol/server-filesystem
```

**为什么现在：** Axios 2026.03.24: "谁会成为 AI 安全的 CrowdStrike？" 这是抢地盘的窗口期。

---

## Milestone 3: 专业场景深化 (v0.5.0)

> **核心价值：从通用工具变成特定场景的最佳选择。**

### 3.1 Engagement Session Manager

```bash
opensec session start --target example.com --name "Q2-pentest"

# 后续所有命令自动关联到 session
opensec recon subdomain-enum --domain example.com
opensec vuln nuclei-scan --target example.com
opensec pentest fuzz --url "https://example.com/api?q=test"

# 查看进度
opensec session status
# → Recon: 80% | Vuln Scan: 60% | Pentest: 20%
# → 找到 45 个子域名, 12 个开放端口, 8 个漏洞

# 对比上次
opensec session diff --previous "Q1-pentest"
# → 新增 3 个子域名, 关闭 2 个端口, 1 个漏洞已修复

# 生成渗透报告
opensec session report --format html
```

### 3.2 合规证据收集器

```bash
opensec compliance collect --framework soc2 --path .
# → 自动运行: dep-audit, ci-audit, header-audit, trufflehog-scan, sbom
# → 映射到 SOC 2 控制点
# → 生成证据包: compliance-evidence/

opensec compliance report --framework pci-dss
# → PCI DSS 6.5.x 合规报告 (HTML)

opensec compliance sbom --format cyclonedx --vex
# → CycloneDX SBOM + VEX 文档 (联邦合规)
```

**为什么：** 企业每年付 $20-80k 给 Vanta/Drata。开源替代 = 巨大吸引力。SBOM 联邦法规截止日期 2026.09。

### 3.3 API 安全套件

```bash
opensec api discover --target https://app.example.com
# → 从 JS bundles、OpenAPI specs、流量中发现未文档化 API

opensec api inventory --openapi spec.yaml
# → 导入并跟踪 API 清单

opensec api auth-test --target https://api.example.com --token $JWT
# → BOLA/BFLA/broken auth 测试（带认证状态）

opensec api diff --old spec-v1.yaml --new spec-v2.yaml
# → 检测新增攻击面和破坏性变更
```

---

## Milestone 4: 持续监控 (v1.0.0)

> **核心价值：从一次性扫描变成 24/7 安全监控。**

### 4.1 Watch Mode

```bash
opensec watch start \
  --workflow web-audit.yaml \
  --target example.com \
  --interval 24h \
  --alert webhook:https://hooks.slack.com/xxx

# 后台运行，每 24 小时扫描一次
# 新发现 → Slack 通知
# 变化 → 自动 diff
# 历史 → 写入 Finding DB
```

### 4.2 MCP 安全网关

```bash
opensec gateway start --port 8080
# AI Agent 所有 MCP 调用经过此网关
# 自动审计、限速、权限控制
# 检测异常行为并告警
```

---

## 时间线

```
2026 Q2          2026 Q3          2026 Q4          2027 Q1
  |                |                |                |
  v0.3.0           v0.4.0           v0.5.0           v1.0.0
  Finding DB       AI Triage        Session Mgr      Watch Mode
  Attack Diff      Agent Security   Compliance       MCP Gateway
  GitHub Action    Deep Dive        API Suite
```

## 竞争防线

| 时间 | 护城河 |
|------|--------|
| Now | 84 命令 + 35 Skills + MCP（但可被复制） |
| v0.3.0 | Finding DB 数据重力（一旦有历史数据就不会走） |
| v0.4.0 | AI Triage 智能（需要安全领域知识，不好抄） |
| v0.5.0 | Session + 合规（企业级功能，生态效应） |
| v1.0.0 | 持续监控 + 网关（平台效应） |

## 不做的事

| 功能 | 为什么不做 |
|------|-----------|
| GUI Dashboard | 违反 CLI-first 定位，让 Grafana 消费 DB |
| 完整 CSPM | 太广，Wiz 花了 $32B |
| EDR/XDR | 需要内核代理，不是 CLI 能做的 |
| SIEM 集成 | DefectDojo 已做，让他们从 DB 导入 |
| 更多工具包装（>150） | 深度 > 广度，84 个深度集成 > 150 个薄包装 |
| 付费 SaaS | 先建护城河，再谈商业化 |
