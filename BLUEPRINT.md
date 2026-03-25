# OpenSecCLI — 项目蓝图

> 参照 [OpenCLI](https://github.com/jackwener/opencli) 架构，面向信息安全场景的开源 CLI Hub。

---

## 1. 架构对照

OpenCLI 把网站/桌面应用/本地工具统一成 CLI 命令。OpenSecCLI 做同样的事，但面向安全能力：

| OpenCLI 概念 | OpenSecCLI 对应 | 说明 |
|-------------|----------------|------|
| `src/clis/twitter/` | `src/adapters/abuseipdb/` | 每个安全 API/工具一个目录 |
| YAML Adapter | YAML Adapter（同） | 声明式定义 API 调用，贡献者只写 YAML |
| TypeScript Adapter | TypeScript Adapter（同） | 复杂逻辑（多源聚合、分页、子进程） |
| Strategy: PUBLIC/COOKIE/HEADER | Strategy: FREE/API_KEY/OAUTH | 安全 API 认证模型 |
| Browser Pipeline | HTTP Pipeline | 安全场景以 API 调用为主，浏览器为辅 |
| `explore → synthesize` | `probe → generate`（Phase 2） | 自动发现安全 API 能力并生成 adapter |
| Plugin System | Plugin System（同） | 社区贡献的 adapter 包 |
| cli-manifest.json | cli-manifest.json（同） | 编译时生成，消除运行时解析开销 |

---

## 2. 目录结构

严格对照 OpenCLI 的文件组织：

```
openseccli/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                 # 主 CI：test + lint + audit
│   │   ├── release.yml            # npm publish 自动化
│   │   └── security.yml           # 依赖安全扫描
│   ├── ISSUE_TEMPLATE/
│   │   ├── adapter-request.yml    # "我想要 XX API 的 adapter"
│   │   ├── bug-report.yml
│   │   └── feature-request.yml
│   └── PULL_REQUEST_TEMPLATE.md
│
├── src/
│   ├── main.ts                    # 入口：PATH 设置、discovery、completion
│   ├── cli.ts                     # Commander.js 命令定义
│   ├── registry.ts                # globalThis 单例命令注册表
│   ├── registry-api.ts            # 插件公共 API（re-export）
│   ├── execution.ts               # 命令执行引擎（参数校验→认证→请求→输出）
│   ├── discovery.ts               # 双模发现（manifest 快速路径 + 文件系统回退）
│   ├── build-manifest.ts          # 构建时编译 YAML/TS → cli-manifest.json
│   ├── output.ts                  # 统一输出格式化（table/json/csv/yaml/markdown）
│   ├── errors.ts                  # 错误类型层级（CliError 基类 + 语义子类）
│   ├── hooks.ts                   # 生命周期钩子（onStartup/onBeforeExecute/onAfterExecute）
│   ├── types.ts                   # 类型定义
│   ├── constants.ts               # 常量（字段角色映射、参数分类）
│   ├── logger.ts                  # 统一日志（info/warn/error/verbose/debug → stderr）
│   ├── runtime.ts                 # 运行时配置（超时、环境变量）
│   ├── auth/                      # 认证管理（替代 OpenCLI 的 browser session）
│   │   ├── index.ts               # auth 入口
│   │   ├── store.ts               # 凭据存储（keychain → 加密文件 → env 回退）
│   │   ├── strategies.ts          # FREE / API_KEY / OAUTH / CERT
│   │   └── refresh.ts             # Token 自动刷新
│   ├── pipeline/                  # Pipeline 执行引擎（对照 OpenCLI pipeline/）
│   │   ├── executor.ts            # 步骤链式执行 + 重试
│   │   ├── steps/
│   │   │   ├── request.ts         # HTTP 请求（单次 + 批量并发）
│   │   │   ├── transform.ts       # select / map / filter / sort / limit
│   │   │   ├── enrich.ts          # 多源聚合（OpenSecCLI 特有）
│   │   │   ├── subprocess.ts      # 本地工具子进程调用（nmap/nuclei 等）
│   │   │   └── download.ts        # 文件下载
│   │   └── template.ts            # {{ }} 模板表达式引擎
│   ├── adapters/                   # 安全能力适配器（对照 OpenCLI src/clis/）
│   │   ├── abuse.ch/              # ─── 零 Key 区 ───
│   │   │   ├── urlhaus-query.yaml
│   │   │   ├── malwarebazaar-query.yaml
│   │   │   ├── threatfox-search.yaml
│   │   │   ├── feodo-list.yaml
│   │   │   └── sslbl-search.yaml
│   │   ├── nvd/
│   │   │   ├── cve-get.yaml
│   │   │   └── cve-search.yaml
│   │   ├── crtsh/
│   │   │   └── cert-search.yaml
│   │   ├── whois/
│   │   │   └── domain-lookup.ts   # 需要子进程调 whois
│   │   ├── abuseipdb/             # ─── 免费 Key 区 ───
│   │   │   └── ip-check.yaml
│   │   ├── virustotal/
│   │   │   ├── hash-lookup.yaml
│   │   │   ├── ip-lookup.yaml
│   │   │   └── domain-lookup.yaml
│   │   ├── greynoise/
│   │   │   └── ip-check.yaml
│   │   ├── shodan/
│   │   │   ├── host-lookup.yaml
│   │   │   └── search.yaml
│   │   ├── ipinfo/
│   │   │   └── ip-lookup.yaml
│   │   └── _enrichment/           # ─── 多源聚合（杀手功能）───
│   │       ├── ip-enrich.ts       # 并行查 N 个源 → 合并 → 共识判定
│   │       ├── domain-enrich.ts
│   │       └── hash-enrich.ts
│   └── external/                  # 外部 CLI 集成（对照 OpenCLI external.ts）
│       ├── index.ts
│       └── registry.yaml          # nmap, nuclei, subfinder, httpx 等
│
├── tests/
│   ├── unit/                      # 参数校验、输出格式化、模板引擎
│   ├── adapter/                   # 各 adapter 测试（mock API 响应）
│   └── e2e/                       # 端到端（安装→auth→查询→pipe）
│
├── scripts/
│   ├── clean-dist.cjs
│   ├── copy-yaml.cjs
│   ├── build-manifest.cjs
│   └── postinstall.js
│
├── docs/                          # VitePress 文档站
│   ├── .vitepress/
│   ├── guide/
│   │   ├── getting-started.md
│   │   ├── authentication.md
│   │   └── piping.md
│   ├── adapters/                  # 每个 adapter 的文档（自动生成）
│   ├── developer/
│   │   ├── writing-yaml-adapter.md
│   │   ├── writing-ts-adapter.md
│   │   └── architecture.md
│   └── zh/                        # 中文文档
│
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── README.md
├── README.zh-CN.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE                        # Apache-2.0
├── BLUEPRINT.md                   # 本文件
└── cli-specification.md           # CLI 设计规范
```

---

## 3. 核心模块设计

### 3.1 命令注册表（registry.ts）

对照 OpenCLI 的 `globalThis.__opencli_registry__` 模式：

```typescript
// 认证策略枚举（替代 OpenCLI 的 PUBLIC/COOKIE/HEADER/INTERCEPT/UI）
export enum Strategy {
  FREE      = 'FREE',       // 无需认证
  API_KEY   = 'API_KEY',    // API Key（最常见）
  OAUTH     = 'OAUTH',      // OAuth 2.0
  CERT      = 'CERT',       // 客户端证书
}

export interface Arg {
  type: 'string' | 'number' | 'boolean'
  required?: boolean
  default?: unknown
  choices?: string[]
  help?: string
}

export interface CliCommand {
  provider: string            // 对应 OpenCLI 的 site（如 'virustotal'）
  name: string                // 动作名（如 'lookup'）
  description: string
  strategy: Strategy
  auth?: string               // 引用的认证配置名
  func?: (ctx: ExecContext, args: Record<string, unknown>) => Promise<unknown>
  pipeline?: PipelineStep[]
  args: Record<string, Arg>
  columns: string[]
  timeout?: number
}

// 全局单例注册表
const REGISTRY_KEY = '__openseccli_registry__'

export function getRegistry(): Map<string, CliCommand> {
  if (!(globalThis as any)[REGISTRY_KEY]) {
    (globalThis as any)[REGISTRY_KEY] = new Map()
  }
  return (globalThis as any)[REGISTRY_KEY]
}

export function cli(options: CliOptions): CliCommand {
  const command: CliCommand = {
    provider: options.provider,
    name: options.name,
    description: options.description ?? '',
    strategy: options.strategy ?? Strategy.FREE,
    auth: options.auth,
    func: options.func,
    pipeline: options.pipeline,
    args: options.args ?? {},
    columns: options.columns ?? [],
    timeout: options.timeout,
  }
  getRegistry().set(`${options.provider}/${options.name}`, command)
  return command
}

export function fullName(cmd: CliCommand): string {
  return `${cmd.provider}/${cmd.name}`
}
```

### 3.2 执行引擎（execution.ts）

对照 OpenCLI 的 `executeCommand()` 生命周期：

```typescript
export async function executeCommand(
  commandId: string,
  rawArgs: Record<string, unknown>,
  options: { format: string }
): Promise<void> {
  const registry = getRegistry()
  const command = registry.get(commandId)
  if (!command) throw new CommandNotFoundError(commandId)

  // 1. 参数校验 + 类型转换（对照 coerceAndValidateArgs）
  const args = coerceAndValidateArgs(command.args, rawArgs)

  // 2. 生命周期钩子：onBeforeExecute
  await fireHook('onBeforeExecute', { command: commandId, args })

  // 3. 认证上下文（替代 OpenCLI 的浏览器 session）
  const authCtx = command.strategy !== Strategy.FREE
    ? await resolveAuth(command.auth ?? command.provider)
    : null

  // 4. 懒加载 TS 模块（对照 manifest lazy-load）
  if (!command.func && !command.pipeline) {
    await lazyLoadModule(commandId)
  }

  // 5. 执行（func 或 pipeline）
  const startedAt = Date.now()
  let result: unknown

  try {
    if (command.func) {
      result = await runWithTimeout(
        command.func({ auth: authCtx, args, log }, args),
        command.timeout ?? DEFAULT_COMMAND_TIMEOUT
      )
    } else if (command.pipeline) {
      result = await executePipeline(command.pipeline, { auth: authCtx, args })
    }
  } catch (error) {
    await fireHook('onAfterExecute', { command: commandId, args, error })
    throw error
  }

  // 6. 输出格式化
  const elapsed = Date.now() - startedAt
  render(result, {
    format: options.format,
    columns: command.columns,
    source: command.provider,
    elapsed,
  })

  // 7. 生命周期钩子：onAfterExecute
  await fireHook('onAfterExecute', { command: commandId, args, startedAt })
}
```

### 3.3 Pipeline 步骤（pipeline/）

对照 OpenCLI 的 pipeline executor，但以 HTTP 请求为主（非浏览器）：

```
数据流：每一步的输出 → 下一步的输入

request  →  select  →  map  →  filter  →  sort  →  limit
  │           │         │        │          │         │
 HTTP 响应   取嵌套路径  字段映射   条件过滤    排序     截断
```

#### 步骤类型

| 步骤 | 对照 OpenCLI | 说明 |
|------|-------------|------|
| `request` | `fetch` | HTTP 请求，支持批量 + 并发 |
| `select` | `select` | 取嵌套路径：`data.results` |
| `map` | `map` | 字段映射 + 模板表达式 |
| `filter` | `filter` | 条件过滤 |
| `sort` | `sort` | 排序 |
| `limit` | `limit` | 截断 |
| `enrich` | *新增* | 并行查多个 API → 合并结果 |
| `subprocess` | *新增* | 调用本地工具（nmap/nuclei） |
| `download` | `download` | 文件下载 |

#### YAML Pipeline 示例

```yaml
# src/adapters/abuseipdb/ip-check.yaml
provider: abuseipdb
name: ip-check
description: Check IP reputation on AbuseIPDB
strategy: API_KEY
auth: abuseipdb

args:
  ip:
    type: string
    required: true
    help: IP address to check
  days:
    type: number
    default: 90
    help: Max age of reports in days

pipeline:
  - request:
      url: https://api.abuseipdb.com/api/v2/check
      headers:
        Key: "{{ auth.api_key }}"
        Accept: application/json
      params:
        ipAddress: "{{ args.ip }}"
        maxAgeInDays: "{{ args.days }}"

  - select:
      path: data

  - map:
      template:
        ip: "{{ item.ipAddress }}"
        abuse_score: "{{ item.abuseConfidenceScore }}"
        country: "{{ item.countryCode }}"
        isp: "{{ item.isp }}"
        usage_type: "{{ item.usageType }}"
        domain: "{{ item.domain }}"
        total_reports: "{{ item.totalReports }}"
        last_reported: "{{ item.lastReportedAt }}"

columns: [ip, abuse_score, country, isp, total_reports, last_reported]
```

#### enrich 步骤（OpenSecCLI 特有）

这是 OpenCLI 没有的步骤，也是本项目的差异化杀手功能：

```yaml
# src/adapters/_enrichment/ip-enrich.yaml
provider: enrichment
name: ip-enrich
description: Enrich IP from multiple threat intelligence sources
strategy: FREE    # 至少有免费源可用

args:
  ip:
    type: string
    required: true
    help: IP address to enrich

pipeline:
  - enrich:
      target: "{{ args.ip }}"
      parallel: true
      timeout: 10
      sources:
        - provider: abuseipdb
          adapter: ip-check
          key_field: abuse_score
          label: AbuseIPDB
        - provider: greynoise
          adapter: ip-check
          key_field: classification
          label: GreyNoise
        - provider: virustotal
          adapter: ip-lookup
          key_field: malicious_votes
          label: VirusTotal
        - provider: ipinfo
          adapter: ip-lookup
          key_field: org
          label: ipinfo
        - provider: abuse.ch
          adapter: threatfox-search
          key_field: threat_type
          label: ThreatFox
      consensus:
        field: verdict            # 自动生成共识判定字段
        rules:
          - condition: "abuse_score > 80 || malicious_votes > 5"
            value: MALICIOUS
          - condition: "abuse_score > 30 || classification == 'malicious'"
            value: SUSPICIOUS
          - default: CLEAN

columns: [source, verdict, detail]
```

### 3.4 认证管理（auth/）

替代 OpenCLI 的 Browser Session 管理，因为安全 API 以 Key-based auth 为主：

```
opensec auth add virustotal --api-key        # 交互式输入 Key
opensec auth add shodan --api-key            # 同上
opensec auth list                             # 查看已配置的认证
opensec auth test virustotal                  # 测试连通性
opensec auth remove virustotal                # 删除
```

存储位置（对照 OpenCLI 的 `~/.opencli/`）：

```
~/.openseccli/
├── config.yaml            # 全局配置
├── auth/                  # 凭据（加密存储，600 权限）
│   ├── virustotal.enc
│   ├── abuseipdb.enc
│   └── shodan.enc
├── plugins/               # 社区插件
└── clis/                  # 用户自定义 adapter
```

### 3.5 错误类型（errors.ts）

对照 OpenCLI 的 `CliError` 层级，适配安全场景：

```typescript
export class CliError extends Error {
  constructor(
    public code: string,
    message: string,
    public hint?: string
  ) {
    super(message)
    this.name = 'CliError'
  }
}

// 对照 OpenCLI 的语义错误子类
export class AuthRequiredError extends CliError {
  constructor(provider: string) {
    super('AUTH_REQUIRED',
      `${provider} 需要 API Key`,
      `运行 opensec auth add ${provider} --api-key 配置凭据`
    )
  }
}

export class AuthExpiredError extends CliError {
  constructor(provider: string) {
    super('AUTH_EXPIRED',
      `${provider} 的 API Key 已失效`,
      `运行 opensec auth test ${provider} 检查，或 opensec auth add ${provider} --api-key 重新配置`
    )
  }
}

export class RateLimitError extends CliError {
  constructor(provider: string, retryAfter?: number) {
    super('RATE_LIMITED',
      `${provider} API 速率限制（${retryAfter ? retryAfter + 's 后重试' : '请稍后重试'}）`,
      `使用 --delay 参数降低请求速率，或升级 API 套餐`
    )
  }
}

export class ToolNotFoundError extends CliError {
  constructor(tool: string, installHint: string) {
    super('TOOL_NOT_FOUND',
      `未找到 ${tool} 命令`,
      `安装方法：${installHint}`
    )
  }
}

export class CommandNotFoundError extends CliError {
  constructor(commandId: string) {
    super('COMMAND_NOT_FOUND',
      `未知命令: ${commandId}`,
      `运行 opensec list 查看所有可用命令`
    )
  }
}

export class TimeoutError extends CliError {
  constructor(seconds: number) {
    super('TIMEOUT',
      `操作超时 (${seconds}s)`,
      `设置 OPENSECCLI_TIMEOUT 环境变量增加超时时间`
    )
  }
}

export class EmptyResultError extends CliError {
  constructor(message: string) {
    super('NO_DATA', message)
  }
}

export class ArgumentError extends CliError {
  constructor(message: string) {
    super('INVALID_ARGUMENT', message)
  }
}

export const ERROR_ICONS: Record<string, string> = {
  AUTH_REQUIRED:   '🔒',
  AUTH_EXPIRED:    '🔑',
  RATE_LIMITED:    '⏳',
  TOOL_NOT_FOUND:  '🔧',
  COMMAND_NOT_FOUND:'❓',
  TIMEOUT:         '⏱️',
  NO_DATA:         '📭',
  INVALID_ARGUMENT:'❌',
}
```

### 3.6 输出格式化（output.ts）

完全对照 OpenCLI 的 `render()` + `RenderOptions`：

```typescript
export interface RenderOptions {
  format?: 'table' | 'json' | 'csv' | 'yaml' | 'markdown'
  columns?: string[]
  source?: string
  elapsed?: number
  footerExtra?: string
}

export function render(
  data: unknown,
  options: RenderOptions = {}
): void {
  const format = options.format ?? (process.stdout.isTTY ? 'table' : 'json')
  const output = formatters[format](data, options)
  process.stdout.write(output + '\n')
}

// table 格式使用 cli-table3，与 OpenCLI 一致
// json 格式：JSON.stringify(data, null, 2)
// csv 格式：正确转义逗号/引号/换行
// yaml 格式：js-yaml 120 字符行宽
// markdown 格式：pipe-delimited 表格
```

### 3.7 CLI 命令（cli.ts）

对照 OpenCLI 的 Commander.js 结构：

```
opensec                            # 显示帮助
opensec list                       # 列出所有可用命令（对照 OpenCLI list）
opensec doctor                     # 环境诊断（对照 OpenCLI doctor）
opensec auth <add|list|test|remove> # 认证管理
opensec completion <bash|zsh|fish>  # Shell 补全（对照 OpenCLI completion）

# 安全能力命令（自动从 adapter 注册）
opensec <provider> <action> [args] [flags]

# 示例
opensec abuseipdb ip-check 1.2.3.4
opensec nvd cve-get CVE-2024-1234
opensec virustotal hash-lookup <sha256>
opensec enrichment ip-enrich 1.2.3.4

# 通用 flags（所有命令统一）
--format, -f     table|json|csv|yaml|markdown（默认 table）
--output, -o     输出到文件
--verbose, -v    详细输出
--debug          调试模式
--quiet, -q      静默模式
--timeout        超时秒数
--no-color       禁用颜色
--json           --format json 的快捷方式（兼容 ProjectDiscovery 生态）
--silent         --quiet 的别名（兼容 ProjectDiscovery 生态）

# 插件管理（对照 OpenCLI plugin）
opensec plugin install github:user/repo
opensec plugin uninstall <name>
opensec plugin list
opensec plugin update <name>
```

### 3.8 双模发现（discovery.ts）

完全对照 OpenCLI 的快速路径 + 文件系统回退：

```
快速路径（生产）：
  cli-manifest.json → 直接注册命令元数据 → TS 模块按需懒加载

回退路径（开发）：
  扫描 src/adapters/**/*.yaml → registerYamlAdapter()
  扫描 src/adapters/**/*.ts   → 动态 import

插件发现：
  扫描 ~/.openseccli/plugins/ → 同上
```

---

## 4. YAML Adapter 规范

这是贡献者要写的**全部内容**。一个 YAML 文件 = 一个 CLI 命令。

### 4.1 完整 Schema

```yaml
# 必填
provider: string         # API 提供商名（目录名）
name: string             # 动作名（文件名，不含 .yaml）
description: string      # 一行描述

# 认证
strategy: FREE | API_KEY | OAUTH | CERT    # 默认 FREE
auth: string             # 引用的认证配置名（默认同 provider）

# 参数
args:
  <arg_name>:
    type: string | number | boolean
    required: boolean    # 默认 false
    default: any
    choices: string[]
    help: string

# 执行
pipeline:
  - request: { ... }    # HTTP 请求
  - select: { ... }     # 取嵌套路径
  - map: { ... }        # 字段映射
  - filter: { ... }     # 条件过滤
  - sort: { ... }       # 排序
  - limit: { ... }      # 截断
  - enrich: { ... }     # 多源聚合
  - subprocess: { ... } # 本地工具调用

# 输出
columns: string[]        # 表格列名
```

### 4.2 模板表达式

对照 OpenCLI 的 `{{ }}` 引擎：

```
{{ args.ip }}                      # 参数引用
{{ auth.api_key }}                 # 认证凭据引用
{{ item.field }}                   # 当前项字段
{{ item.score > 80 ? 'HIGH' : 'LOW' }}  # 三元表达式
{{ item.tags | join(', ') }}       # 过滤器：join
{{ item.title | truncate(50) }}    # 过滤器：truncate
{{ item.hash | upper }}            # 过滤器：upper/lower
{{ item.url | urlencode }}         # 过滤器：urlencode
{{ index + 1 }}                    # 数组索引
{{ value || 'N/A' }}               # 默认值
```

安全约束（对照 OpenCLI）：
- VM 沙箱执行，50ms 超时
- 禁止 `constructor`、`prototype`、`process`、`require`
- 最大表达式长度 2000 字符

### 4.3 从零写一个 Adapter 的步骤

```bash
# 1. 创建目录和文件
mkdir -p src/adapters/abuseipdb
touch src/adapters/abuseipdb/ip-check.yaml

# 2. 写 YAML（参考 4.1 Schema）
# 3. 开发模式测试
npm run dev -- abuseipdb ip-check 1.2.3.4

# 4. 写测试
touch tests/adapter/abuseipdb.test.ts

# 5. 构建 manifest 验证
npm run build-manifest

# 6. 提 PR
```

---

## 5. 种子 Adapter 清单

### Phase 0 — 零 API Key（装完即用）

全部使用免费无认证的 API，用户 `npm install -g openseccli` 后立刻能体验。

| Provider | Adapter | 命令 | API |
|----------|---------|------|-----|
| abuse.ch | urlhaus-query | `opensec abuse.ch urlhaus-query --url <url>` | URLhaus |
| abuse.ch | malwarebazaar-query | `opensec abuse.ch malwarebazaar-query --hash <sha256>` | MalwareBazaar |
| abuse.ch | threatfox-search | `opensec abuse.ch threatfox-search --ioc <ioc>` | ThreatFox |
| abuse.ch | feodo-list | `opensec abuse.ch feodo-list` | Feodo Tracker |
| abuse.ch | sslbl-search | `opensec abuse.ch sslbl-search --hash <sha1>` | SSLBL |
| nvd | cve-get | `opensec nvd cve-get CVE-2024-1234` | NVD API |
| nvd | cve-search | `opensec nvd cve-search --keyword log4j` | NVD API |
| crtsh | cert-search | `opensec crtsh cert-search --domain example.com` | crt.sh |

**为什么选这 8 个**：abuse.ch 全家桶无速率限制 + NVD 是漏洞管理标配 + crt.sh 是资产发现入门。覆盖 SOC 分析师最高频的三类操作：IOC 查询、CVE 查询、证书透明度。

### Phase 1 — 免费 Key（注册即用）

| Provider | Adapter | 命令 |
|----------|---------|------|
| abuseipdb | ip-check | `opensec abuseipdb ip-check <ip>` |
| virustotal | hash-lookup | `opensec virustotal hash-lookup <sha256>` |
| virustotal | ip-lookup | `opensec virustotal ip-lookup <ip>` |
| virustotal | domain-lookup | `opensec virustotal domain-lookup <domain>` |
| greynoise | ip-check | `opensec greynoise ip-check <ip>` |
| ipinfo | ip-lookup | `opensec ipinfo ip-lookup <ip>` |
| shodan | host-lookup | `opensec shodan host-lookup <ip>` |

### Phase 1.5 — 杀手功能：多源聚合

| Adapter | 命令 | 聚合源 |
|---------|------|--------|
| ip-enrich | `opensec enrichment ip-enrich <ip>` | AbuseIPDB + VT + GreyNoise + ipinfo + ThreatFox |
| domain-enrich | `opensec enrichment domain-enrich <domain>` | VT + crt.sh + Shodan + WHOIS |
| hash-enrich | `opensec enrichment hash-enrich <hash>` | VT + MalwareBazaar + ThreatFox |

---

## 6. package.json

对照 OpenCLI 的依赖和脚本结构：

```jsonc
{
  "name": "openseccli",
  "version": "0.1.0",
  "description": "The open-source security CLI hub — query, enrich, automate.",
  "license": "Apache-2.0",
  "type": "module",
  "engines": { "node": ">=20.0.0" },
  "main": "dist/main.js",
  "bin": { "opensec": "dist/main.js" },
  "exports": {
    ".": "./dist/main.js",
    "./registry": "./dist/registry-api.js"
  },
  "scripts": {
    "dev": "tsx src/main.ts",
    "build": "npm run clean-dist && tsc && npm run copy-yaml && npm run build-manifest",
    "build-manifest": "node dist/build-manifest.js",
    "clean-dist": "node scripts/clean-dist.cjs",
    "copy-yaml": "node scripts/copy-yaml.cjs",
    "start": "node dist/main.js",
    "postinstall": "node scripts/postinstall.js || true",
    "typecheck": "tsc --noEmit",
    "lint": "tsc --noEmit",
    "prepublishOnly": "npm run build",
    "test": "vitest run --project unit",
    "test:adapter": "vitest run --project adapter",
    "test:all": "vitest run",
    "test:e2e": "vitest run --project e2e",
    "docs:dev": "vitepress dev docs",
    "docs:build": "vitepress build docs"
  },
  "dependencies": {
    "chalk": "^5.3.0",
    "cli-table3": "^0.6.5",
    "commander": "^14.0.3",
    "js-yaml": "^4.1.0"
  },
  "devDependencies": {
    "@types/js-yaml": "^4.0.9",
    "@types/node": "^22.13.10",
    "tsx": "^4.19.3",
    "typescript": "^6.0.2",
    "vitepress": "^1.6.4",
    "vitest": "^4.1.0"
  }
}
```

与 OpenCLI 的差异：
- 去掉 `turndown`（HTML→Markdown，安全场景不需要）
- 去掉 `ws`（WebSocket 浏览器桥，安全场景以 API 为主）
- 其余依赖保持一致

---

## 7. 执行路线

```
Phase 0（第 1-2 周）— 框架 + 8 个零 Key Adapter
  ├─ src/main.ts + cli.ts + registry.ts（CLI 骨架）
  ├─ src/pipeline/（request + transform 步骤）
  ├─ src/output.ts（table/json/csv）
  ├─ src/discovery.ts + build-manifest.ts（双模发现）
  ├─ src/errors.ts + logger.ts（错误 + 日志）
  ├─ 8 个 abuse.ch + NVD + crt.sh YAML adapter
  ├─ README（GIF 演示 + Quick Start）
  ├─ CONTRIBUTING.md（10 分钟添加 adapter 教程）
  └─ CI（test + lint + security audit）

Phase 1（第 3-4 周）— Auth + 7 个免费 Key Adapter + 多源聚合
  ├─ src/auth/（凭据存储 + opensec auth 命令）
  ├─ 7 个 API Key adapter（VT + AbuseIPDB + GreyNoise + ipinfo + Shodan）
  ├─ src/pipeline/steps/enrich.ts（多源聚合步骤）
  ├─ 3 个 enrich adapter（ip/domain/hash）
  ├─ opensec doctor 命令
  └─ opensec completion 命令

Phase 2（第 5-8 周）— 生态
  ├─ src/external/（nmap/nuclei/subfinder 集成）
  ├─ src/pipeline/steps/subprocess.ts
  ├─ Plugin 系统（opensec plugin install）
  ├─ VitePress 文档站
  ├─ 20+ good-first-issue
  └─ 社区推广（awesome-security、Hacker News、V2EX、安全客）
```

---

## 8. 兼容 ProjectDiscovery 生态

ProjectDiscovery 是安全 CLI 领域的最大生态（nuclei 27K 星）。兼容它的约定可以让用户零成本接入：

```bash
# ProjectDiscovery 约定          OpenSecCLI 实现
-json                            --json（--format json 别名）
-silent                          --silent（--quiet 别名）
stdin 输入                       支持 pipe 输入
stdout 逐行 JSON                 --json 模式逐行输出（非数组）

# 实际组合使用
subfinder -d example.com -silent | opensec enrichment domain-enrich --json
echo "1.2.3.4" | opensec enrichment ip-enrich --json | nuclei -t cves/
cat iocs.txt | opensec abuse.ch threatfox-search --json | jq '.threat_type'
```

---

## 9. 吸引贡献者的关键设计

| 机制 | 对照 OpenCLI | 说明 |
|------|-------------|------|
| YAML Adapter | ✓ 相同 | 贡献者不需要写 TypeScript，只写 YAML |
| cli-manifest.json | ✓ 相同 | 构建时编译，贡献者不需要关心性能 |
| Plugin 系统 | ✓ 相同 | `opensec plugin install github:user/repo` |
| Adapter 脚手架 | OpenCLI 无 | `opensec adapter new` 交互式生成模板 |
| Mock 测试 | OpenCLI 手动 | 自动生成 API mock（录制真实响应） |
| Issue 模板 | ✓ 相同 | "Adapter Request" 模板让用户提需求 |
| good-first-issue | ✓ 相同 | 每个待封装 API = 一个 issue |

**贡献一个新 adapter 的完整流程**：

```bash
# 1. Fork + Clone
git clone https://github.com/yourname/OpenSecCLI && cd OpenSecCLI

# 2. 脚手架（自动生成 YAML 模板 + 测试文件）
npm run dev -- adapter new
? Provider name: urlscan
? Action name: scan
? API URL: https://urlscan.io/api/v1/scan/
? Strategy: API_KEY
? Auth config name: urlscan
→ Created: src/adapters/urlscan/scan.yaml
→ Created: tests/adapter/urlscan.test.ts

# 3. 填写 YAML（已有骨架，只需填参数和字段映射）
# 4. 测试
npm test

# 5. 提 PR
```
