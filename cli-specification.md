# 信息安全能力 CLI 化规范

> 版本：1.0 | 维护：信息安全部 | 最后更新：2026-03-24

---

## 目录

1. [为什么要 CLI 化](#1-为什么要-cli-化)
2. [架构总览](#2-架构总览)
3. [命名规范](#3-命名规范)
4. [命令结构](#4-命令结构)
5. [参数设计](#5-参数设计)
6. [认证与凭据](#6-认证与凭据)
7. [输出规范](#7-输出规范)
8. [错误处理](#8-错误处理)
9. [配置管理](#9-配置管理)
10. [安全要求](#10-安全要求)
11. [测试规范](#11-测试规范)
12. [实战模板](#12-实战模板)
13. [Review Checklist](#13-review-checklist)

---

## 1. 为什么要 CLI 化

| 问题 | CLI 化如何解决 |
|------|---------------|
| 能力散落在各处（脚本、Web 平台、内部工具） | 统一入口，`sectool <能力> <动作>` |
| 重复操作耗时（登录 Web → 点击 → 导出） | 一条命令完成，可写进 cron |
| 无法组合使用 | pipe 串联：`sectool vuln list \| sectool ticket create` |
| 难以自动化和集成 | CI/CD、SOAR 剧本直接调用 |
| 交接成本高 | `--help` 即文档，新人自助上手 |

---

## 2. 架构总览

### 2.1 分层模型

```
┌─────────────────────────────────────────────┐
│  CLI 入口层     命令解析、参数校验、帮助文档     │
├─────────────────────────────────────────────┤
│  适配器层       封装具体能力的调用逻辑          │
│                ┌──────────┐ ┌──────────┐     │
│                │ 本地工具  │ │ Web API  │     │
│                │ 适配器    │ │ 适配器   │     │
│                └──────────┘ └──────────┘     │
├─────────────────────────────────────────────┤
│  公共层         认证、输出格式化、错误处理、日志  │
├─────────────────────────────────────────────┤
│  能力层         实际的工具/API/平台             │
│                nuclei, nmap, SIEM API, ...   │
└─────────────────────────────────────────────┘
```

### 2.2 两类适配器

| 类型 | 适用场景 | 实现方式 |
|------|---------|---------|
| **本地工具适配器** | 封装已有的扫描器、脚本、二进制 | 子进程调用 + 输出解析 |
| **Web API 适配器** | 封装威胁情报、SIEM、漏洞平台等 | HTTP 请求 + 响应映射 |

---

## 3. 命名规范

### 3.1 命令命名

采用 **`名词 动词`** 层级结构（noun-verb pattern）：

```bash
# 格式
sectool <资源> <动作> [参数]

# 示例
sectool vuln list                     # 列出漏洞
sectool vuln scan --target 10.0.0.0/24  # 扫描漏洞
sectool threat search --ioc 1.2.3.4   # 查询威胁情报
sectool asset export --format csv      # 导出资产
sectool cert check --domain example.com # 检查证书
```

**为什么不用 `scan-vuln`（动词-名词）？**
- 名词-动词可扩展：`vuln` 下可以挂 `list`、`scan`、`export`、`assign`
- 与主流工具一致：`kubectl get pods`、`gh issue list`、`docker container ls`

### 3.2 命名规则

| 规则 | 正确 | 错误 |
|------|------|------|
| 全小写，连字符分词 | `sectool port-scan run` | `sectool PortScan Run` |
| 资源名用**单数** | `sectool vuln list` | `sectool vulns list` |
| 动词用通用词汇 | `list`, `get`, `create`, `delete`, `scan`, `search`, `export` | `fetch-all`, `remove`, `do-scan` |
| 不超过 3 层嵌套 | `sectool vuln scan` | `sectool vuln scan internal network` |

### 3.3 标准动词表

| 动词 | 语义 | 示例 |
|------|------|------|
| `list` | 列出多条记录 | `sectool vuln list` |
| `get` | 获取单条记录 | `sectool vuln get CVE-2024-1234` |
| `search` | 按条件搜索 | `sectool threat search --ioc 1.2.3.4` |
| `scan` | 执行扫描任务 | `sectool port scan --target 10.0.0.0/24` |
| `create` | 创建资源 | `sectool ticket create --vuln-id 123` |
| `update` | 更新资源 | `sectool vuln update --id 123 --status fixed` |
| `delete` | 删除资源 | `sectool rule delete --id 456` |
| `export` | 导出数据 | `sectool asset export --format csv` |
| `check` | 合规/状态检查 | `sectool cert check --domain example.com` |
| `run` | 执行任务/剧本 | `sectool playbook run --name incident-response` |

---

## 4. 命令结构

### 4.1 基本结构

```
sectool <资源> <动作> [位置参数] [--选项 值] [--开关]
                │         │          │            │
                │         │          │            └─ 布尔开关 (--verbose, --dry-run)
                │         │          └─ 键值对选项 (--format json)
                │         └─ 必填的直接参数 (CVE-2024-1234)
                └─ 资源 + 动作 (vuln get)
```

### 4.2 帮助系统（每个命令必须实现）

```bash
# 顶层帮助：列出所有资源
$ sectool --help
Security Toolkit CLI v1.0.0

Usage: sectool <command> [flags]

Commands:
  vuln        漏洞管理（扫描、查询、跟踪）
  threat      威胁情报查询
  asset       资产管理
  cert        证书检查
  port        端口扫描
  playbook    安全剧本执行
  config      配置管理

Flags:
  -h, --help       显示帮助
  -V, --version    显示版本
  -v, --verbose    详细输出
      --debug      调试模式
      --profile    指定配置档案（默认：default）

Run "sectool <command> --help" for more information.

# 二级帮助：列出资源下的动作
$ sectool vuln --help
Vulnerability management

Usage: sectool vuln <action> [flags]

Actions:
  list       列出漏洞（支持过滤和排序）
  get        获取单个漏洞详情
  scan       执行漏洞扫描
  export     导出漏洞数据
  assign     分配漏洞给处理人

# 三级帮助：具体动作的完整用法
$ sectool vuln scan --help
Execute vulnerability scan

Usage: sectool vuln scan [flags]

Required:
  -t, --target <CIDR|HOST>   扫描目标（IP/CIDR/域名）

Options:
  -p, --profile <name>       扫描模板（default: quick）
                              可选：quick, full, compliance
      --port <range>          端口范围（default: top-1000）
  -o, --output <file>        结果保存路径
      --format <type>         输出格式：table, json, csv（default: table）
      --timeout <seconds>     超时时间（default: 300）
      --severity <level>      最低严重级别过滤：low, medium, high, critical
      --dry-run               仅显示将执行的操作，不实际扫描

Examples:
  sectool vuln scan -t 10.0.0.0/24
  sectool vuln scan -t example.com --profile full --severity high
  sectool vuln scan -t 10.0.0.1 --port 1-65535 --format json -o result.json
```

### 4.3 命令分组参考

```
资产发现与管理:
  asset       资产发现、盘点、标签
  port        端口扫描与服务识别

漏洞管理:
  vuln        漏洞扫描、查询、跟踪
  cert        SSL/TLS 证书检查

威胁情报:
  threat      IOC 查询、情报订阅
  intel       情报源管理

安全运营:
  alert       告警查询与处置
  playbook    SOAR 剧本管理与执行
  ticket      工单创建与跟踪

合规与审计:
  baseline    基线检查
  audit       审计日志查询
  policy      策略管理
```

---

## 5. 参数设计

### 5.1 参数类型优先级

```
位置参数（positional）：用于唯一标识符，最多 1 个
  sectool vuln get CVE-2024-1234
                   └─ 位置参数

命名选项（--flag value）：用于所有其他输入
  sectool vuln list --severity high --limit 50
                    └─ 命名选项       └─ 命名选项

布尔开关（--flag）：用于启用/禁用行为
  sectool vuln scan -t 10.0.0.1 --dry-run --verbose
                                └─ 开关    └─ 开关
```

### 5.2 通用参数（所有命令统一）

以下参数在所有命令中保持**一致的名称和行为**：

| 长标志 | 短标志 | 类型 | 说明 |
|--------|--------|------|------|
| `--help` | `-h` | bool | 显示帮助 |
| `--version` | `-V` | bool | 显示版本 |
| `--verbose` | `-v` | bool | 详细输出 |
| `--debug` | | bool | 调试模式（打印请求/响应/堆栈） |
| `--quiet` | `-q` | bool | 静默模式（仅输出数据） |
| `--format` | `-f` | enum | 输出格式：`table`(默认), `json`, `csv`, `yaml` |
| `--output` | `-o` | path | 输出到文件（默认 stdout） |
| `--profile` | | string | 使用的配置档案 |
| `--no-color` | | bool | 禁用颜色 |
| `--dry-run` | | bool | 仅预览，不执行 |
| `--yes` | `-y` | bool | 跳过确认提示（用于脚本） |
| `--timeout` | | int | 超时秒数 |
| `--limit` | `-n` | int | 限制返回条数 |

### 5.3 参数设计原则

```
原则 1: 80% 场景零 flag
  ✓ sectool vuln list                     # 默认最近 20 条，按时间倒序
  ✗ sectool vuln list --limit 20 --sort created_at --order desc

原则 2: 必填参数最小化
  ✓ sectool vuln scan -t 10.0.0.1        # 只需目标，其余都有合理默认值
  ✗ sectool vuln scan -t 10.0.0.1 -p quick --port top-1000 --timeout 300

原则 3: 长短标志并存（常用选项）
  ✓ -t / --target, -f / --format, -o / --output
  ✗ 只有 --target 没有 -t

原则 4: 选项顺序无关
  ✓ sectool vuln scan --format json -t 10.0.0.1
  ✓ sectool vuln scan -t 10.0.0.1 --format json
  （两者行为完全一致）

原则 5: 枚举参数用 choices 约束
  --severity <low|medium|high|critical>
  --format <table|json|csv|yaml>
  输入不在 choices 中时，给出明确提示和可选值列表

原则 6: 秘密永远不走命令行参数
  ✗ sectool config set --api-key sk-12345       # 泄露到 shell history 和 ps
  ✓ sectool auth login                           # 交互式提示输入
  ✓ SECTOOL_API_KEY=sk-12345 sectool ...         # 环境变量（仅 CI 场景）
  ✓ sectool auth login --token-file ~/.secrets/token  # 文件引用
```

### 5.4 参数校验

所有参数必须在**入口层**校验，不要让无效输入传到适配器层：

```python
# Python (Click) 示例
@click.option('--target', '-t', required=True,
              callback=validate_target,
              help='扫描目标（IP/CIDR/域名）')
def scan(target):
    ...

def validate_target(ctx, param, value):
    """校验目标格式"""
    import ipaddress
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    # 尝试域名格式
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$', value):
        return value
    raise click.BadParameter(
        f'无效的目标格式: {value}\n'
        f'支持的格式: IP (10.0.0.1), CIDR (10.0.0.0/24), 域名 (example.com)'
    )
```

```go
// Go (Cobra) 示例
var scanCmd = &cobra.Command{
    Use:   "scan",
    Short: "执行漏洞扫描",
    Args:  cobra.NoArgs,
    PreRunE: func(cmd *cobra.Command, args []string) error {
        target, _ := cmd.Flags().GetString("target")
        if !isValidTarget(target) {
            return fmt.Errorf(
                "无效的目标格式: %s\n支持: IP, CIDR, 域名", target)
        }
        return nil
    },
    RunE: runScan,
}
```

```typescript
// TypeScript (Commander.js) 示例
program
  .command('scan')
  .requiredOption('-t, --target <host>', '扫描目标')
  .hook('preAction', (thisCommand) => {
    const target = thisCommand.opts().target
    if (!isValidTarget(target)) {
      throw new InvalidArgumentError(
        `无效的目标格式: ${target}\n支持: IP, CIDR, 域名`
      )
    }
  })
  .action(runScan)
```

---

## 6. 认证与凭据

### 6.1 认证方式优先级

```
优先级从高到低（优先用更安全的方式）：

1. 系统密钥链（macOS Keychain / Linux Secret Service）
   最安全，硬件级加密，推荐本地开发使用

2. 加密凭据文件（chmod 600）
   ~/.config/sectool/credentials.enc
   次优，适合不支持密钥链的环境

3. 环境变量
   SECTOOL_API_KEY=...
   仅用于 CI/CD 和容器环境，交互式使用时不推荐

4. 交互式登录（OAuth / Device Code）
   sectool auth login
   引导用户完成认证，token 存入密钥链
```

### 6.2 认证流程实现

```bash
# 首次使用：交互式认证
$ sectool auth login
? 选择认证方式:
  > API Key（从平台设置页获取）
    SSO 登录（浏览器跳转）
    Device Code（无浏览器环境）

? 请输入 API Key: ●●●●●●●●●●●●
✓ 认证成功，凭据已保存到系统密钥链
  Profile: default
  User: zhangsan@company.com
  Expires: 2026-06-24

# 后续使用：自动读取凭据
$ sectool vuln list
# 自动从密钥链读取 token，无需再次输入

# 多账号/多环境
$ sectool auth login --profile staging
$ sectool vuln list --profile staging

# 查看当前认证状态
$ sectool auth status
Profile   User                  Expires      Status
default   zhangsan@company.com  2026-06-24   ✓ Active
staging   zhangsan@staging.com  2026-04-01   ✓ Active

# CI/CD 环境
$ export SECTOOL_API_KEY="sk-..."
$ export SECTOOL_API_URL="https://api.internal.company.com"
$ sectool vuln list --format json
```

### 6.3 Token 刷新

```
┌─────────────┐    expired?    ┌──────────────┐    success?    ┌────────┐
│ 读取 Token  │───────────────>│ 用 Refresh   │──────────────>│ 更新   │
│ 从密钥链    │    yes         │ Token 刷新   │    yes        │ 密钥链 │
└─────────────┘                └──────────────┘               └────────┘
      │ no                            │ no
      ▼                               ▼
  正常请求                    提示: sectool auth login
```

### 6.4 凭据存储规范

```
~/.config/sectool/
├── config.yaml            # 非敏感配置（API 地址、默认参数等）
├── profiles/
│   ├── default.yaml       # 默认 profile 配置
│   └── staging.yaml       # staging 环境配置
└── credentials.enc        # 加密的凭据文件（备用，优先用密钥链）

权限要求：
  ~/.config/sectool/           drwx------  (700)
  ~/.config/sectool/config.yaml  -rw-------  (600)
  ~/.config/sectool/credentials.enc  -rw-------  (600)
```

**绝对禁止**：
- 凭据写入代码仓库（即使是 `.gitignore` 的文件）
- 凭据作为命令行参数传入（`--api-key sk-xxx`）
- 明文存储 token 到配置文件
- 日志中打印 token（即使是 debug 模式，也要脱敏：`sk-...a1b2`）

---

## 7. 输出规范

### 7.1 流分离原则

```
stdout：纯数据输出（可以被 pipe 消费）
stderr：状态信息、进度条、警告、错误、debug 日志
```

这是 Unix 可组合性的基础。违反此原则会导致 pipe 链断裂：

```bash
# 正确：进度在 stderr，数据在 stdout，pipe 只传数据
$ sectool vuln scan -t 10.0.0.0/24 2>/dev/null | jq '.[] | .cve_id'
"CVE-2024-1234"
"CVE-2024-5678"

# 错误：进度混在 stdout 里，jq 解析失败
$ sectool vuln scan -t 10.0.0.0/24 | jq '.'
# parse error: Scanning 10.0.0.1... is not valid JSON
```

### 7.2 输出格式

每个命令**必须**支持以下格式（通过 `--format` 切换）：

#### Table（默认，人类阅读）

```
$ sectool vuln list --severity high
CVE ID           Severity   Asset          Status    Discovered
CVE-2024-1234    Critical   10.0.0.5       Open      2026-03-20
CVE-2024-5678    High       web.company.com Fixed     2026-03-18

Showing 2 of 2 vulnerabilities (filtered: severity >= high) · 0.3s
```

#### JSON（机器消费，默认）

```bash
$ sectool vuln list --severity high --format json
[
  {
    "cve_id": "CVE-2024-1234",
    "severity": "critical",
    "asset": "10.0.0.5",
    "status": "open",
    "discovered": "2026-03-20T14:30:00Z"
  },
  {
    "cve_id": "CVE-2024-5678",
    "severity": "high",
    "asset": "web.company.com",
    "status": "fixed",
    "discovered": "2026-03-18T09:15:00Z"
  }
]
```

#### CSV（报表/电子表格）

```bash
$ sectool vuln list --format csv
cve_id,severity,asset,status,discovered
CVE-2024-1234,critical,10.0.0.5,open,2026-03-20T14:30:00Z
CVE-2024-5678,high,web.company.com,fixed,2026-03-18T09:15:00Z
```

### 7.3 TTY 检测

根据输出是否连接终端，自动调整行为：

```
                    交互终端（TTY）          管道/文件（非 TTY）
─────────────────────────────────────────────────────────────
颜色               ✓ 彩色                   ✗ 纯文本
进度条             ✓ 动态更新               ✗ 不显示
表格边框           ✓ 显示                   ✗ 仅分隔符
Footer 统计        ✓ 显示                   ✗ 不显示
默认格式           table                    json（如果检测到 pipe）
```

```python
# Python 检测示例
import sys

def get_default_format():
    if sys.stdout.isatty():
        return 'table'
    return 'json'  # pipe 场景默认 JSON，方便 jq 处理
```

### 7.4 JSON 输出契约

JSON 输出必须遵循统一的 envelope 格式：

```jsonc
// 列表接口
{
  "data": [...],           // 数据数组，永远是数组
  "meta": {
    "total": 150,          // 总数（用于分页）
    "limit": 20,           // 当前页大小
    "offset": 0            // 当前偏移
  }
}

// 单条接口
{
  "data": {...}            // 单个对象
}

// 操作结果
{
  "data": {
    "id": "scan-abc123",
    "status": "started"
  },
  "message": "扫描已启动，预计 5 分钟完成"
}
```

**不要**在正常输出中包含 `success: true` 或 `error: null` 等冗余字段。成功就返回数据，失败通过 exit code + stderr 表达。

### 7.5 退出码

| 退出码 | 含义 | 示例场景 |
|--------|------|---------|
| `0` | 成功 | 正常完成 |
| `1` | 运行时错误 | API 不可达、认证过期 |
| `2` | 参数错误 | 缺少必填参数、格式不合法 |
| `3` | 认证失败 | Token 过期或无效 |
| `4` | 权限不足 | 无权访问该资源 |
| `5` | 资源不存在 | 查询的 CVE/资产不存在 |
| `10` | 扫描发现问题 | 扫描完成但发现高危漏洞（用于 CI 门禁） |
| `130` | 用户中断 | Ctrl-C |

**CI/CD 集成**：退出码 `10` 专门用于"扫描成功但发现安全问题"的场景，便于在流水线中做门禁判断：

```bash
sectool vuln scan -t $DEPLOY_TARGET --severity critical --format json
if [ $? -eq 10 ]; then
  echo "发现高危漏洞，阻断部署"
  exit 1
fi
```

---

## 8. 错误处理

### 8.1 错误三要素

每条错误信息必须包含三部分：**发生了什么 + 在哪里 + 怎么修**。

```bash
# ✗ 差：用户不知道怎么办
Error: connection refused

# ✓ 好：三要素完整
✗ Error: 无法连接到 SIEM API (https://siem.company.com:8443)
  原因: Connection refused (端口未开放或防火墙阻断)
  解决:
    1. 确认 SIEM 服务正在运行: curl -s https://siem.company.com:8443/health
    2. 检查网络连通性: nc -zv siem.company.com 8443
    3. 如果使用 VPN，确认 VPN 已连接
```

### 8.2 常见错误场景模板

```bash
# 认证失败
✗ Error: API Token 已过期 (expired: 2026-03-20)
  运行 `sectool auth login` 重新认证

# 参数错误
✗ Error: --severity 值无效: "urgent"
  可选值: low, medium, high, critical

# 超时
✗ Error: 扫描超时 (300s)
  目标: 10.0.0.0/24 (256 hosts)
  建议:
    1. 缩小扫描范围: sectool vuln scan -t 10.0.0.0/28
    2. 增加超时: sectool vuln scan -t 10.0.0.0/24 --timeout 600
    3. 使用快速模板: sectool vuln scan -t 10.0.0.0/24 --profile quick

# 权限不足
✗ Error: 无权执行漏洞扫描 (role: viewer, required: operator)
  联系管理员提升权限，或使用 --profile 切换到有权限的账号

# 依赖缺失
✗ Error: 未找到 nuclei 命令
  安装方法:
    macOS:  brew install nuclei
    Linux:  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    Docker: docker pull projectdiscovery/nuclei:latest
```

### 8.3 诊断级别

```bash
# 正常模式：简洁的错误信息
$ sectool vuln scan -t 10.0.0.1
✗ Error: 扫描引擎初始化失败
  运行 `sectool doctor` 检查环境

# Verbose 模式：更多上下文
$ sectool vuln scan -t 10.0.0.1 -v
[INFO] 加载扫描模板: ~/.config/sectool/templates/quick.yaml
[INFO] 初始化 nuclei 引擎...
[WARN] nuclei 版本 3.1.0 低于推荐版本 3.2.0
✗ Error: 扫描引擎初始化失败 - nuclei 进程退出码 127
  运行 `sectool doctor` 检查环境

# Debug 模式：完整诊断（仅开发/排错时使用）
$ sectool vuln scan -t 10.0.0.1 --debug
[DEBUG] Config loaded: ~/.config/sectool/config.yaml
[DEBUG] Profile: default
[DEBUG] API URL: https://api.internal.company.com
[DEBUG] Token: sk-...a1b2 (expires: 2026-06-24)
[DEBUG] nuclei path: /usr/local/bin/nuclei
[DEBUG] nuclei version: 3.1.0
[DEBUG] Spawning: nuclei -target 10.0.0.1 -t /path/to/templates -json
[DEBUG] nuclei stderr: [FATAL] template directory not found
✗ Error: 扫描引擎初始化失败 - 模板目录不存在
  Expected: /path/to/templates
  运行 `sectool doctor` 检查环境
```

### 8.4 doctor 命令

每个 CLI 工具**应当**提供 `doctor` 子命令，用于一键诊断环境：

```bash
$ sectool doctor
Checking environment...

  ✓ sectool version 1.0.0
  ✓ Config file: ~/.config/sectool/config.yaml
  ✓ Auth status: authenticated (zhangsan@company.com, expires 2026-06-24)
  ✓ API connectivity: https://api.internal.company.com (200 OK, 45ms)
  ✗ nuclei: not found
    Install: brew install nuclei
  ✓ nmap: 7.94 (/usr/local/bin/nmap)
  ✓ Python: 3.12.0
  ⚠ Disk space: 2.1 GB free (recommend 10 GB+ for scan results)

Issues found: 1 error, 1 warning
```

---

## 9. 配置管理

### 9.1 配置文件位置（遵循 XDG 规范）

```
~/.config/sectool/              # XDG_CONFIG_HOME/sectool
├── config.yaml                 # 全局配置
├── profiles/
│   ├── default.yaml            # 默认环境
│   └── staging.yaml            # 测试环境
└── templates/                  # 自定义扫描模板等

项目级配置（可选）：
./sectool.yaml                  # 项目根目录，优先于全局配置
./.env                          # 环境变量（gitignore!）
```

### 9.2 配置优先级（高到低）

```
1. 命令行 flag          sectool vuln list --limit 50
2. 环境变量             SECTOOL_LIMIT=50
3. 项目配置             ./sectool.yaml
4. Profile 配置         ~/.config/sectool/profiles/default.yaml
5. 全局配置             ~/.config/sectool/config.yaml
6. 内置默认值           limit: 20
```

### 9.3 配置文件示例

```yaml
# ~/.config/sectool/config.yaml
api:
  url: https://api.internal.company.com
  timeout: 30

defaults:
  format: table
  limit: 20
  severity: low       # 默认显示所有级别

scan:
  default_profile: quick
  max_concurrent: 10
  output_dir: ~/sectool-results

logging:
  level: info         # info | warn | error | debug
  file: ~/.local/state/sectool/sectool.log
```

```yaml
# ~/.config/sectool/profiles/staging.yaml
api:
  url: https://staging-api.internal.company.com

defaults:
  severity: medium    # staging 环境只关注 medium+
```

### 9.4 环境变量命名

统一前缀 `SECTOOL_`，层级用 `_` 分隔：

```bash
SECTOOL_API_URL=https://api.internal.company.com
SECTOOL_API_TIMEOUT=30
SECTOOL_DEFAULT_FORMAT=json
SECTOOL_LOG_LEVEL=debug
SECTOOL_PROFILE=staging

# 敏感变量（仅 CI/CD 使用）
SECTOOL_API_KEY=sk-...
```

---

## 10. 安全要求

### 10.1 输入安全

#### 命令注入防御

封装本地工具时，**绝对禁止**拼接字符串构造命令：

```python
# ✗ 致命错误：命令注入
def scan(target):
    os.system(f"nmap {target}")
    # 如果 target = "10.0.0.1; rm -rf /"  → 灾难

# ✓ 正确：使用参数数组，由 OS 处理转义
def scan(target):
    subprocess.run(
        ["nmap", "-oX", "-", target],
        capture_output=True,
        check=True
    )
```

```go
// ✗ 致命错误
exec.Command("sh", "-c", fmt.Sprintf("nmap %s", target))

// ✓ 正确
exec.Command("nmap", "-oX", "-", target)
```

```typescript
// ✗ 致命错误
exec(`nmap ${target}`)

// ✓ 正确
execFile('nmap', ['-oX', '-', target])
```

#### 路径遍历防御

```python
# ✗ 路径遍历
def export(filename):
    path = f"/var/sectool/exports/{filename}"
    # filename = "../../etc/passwd" → 读取系统文件

# ✓ 正确：规范化并校验
def export(filename):
    base = Path("/var/sectool/exports")
    target = (base / filename).resolve()
    if not str(target).startswith(str(base.resolve())):
        raise SecurityError("路径越界")
```

#### 输入白名单校验

```python
# 所有外部输入必须校验格式
VALID_CVE = re.compile(r'^CVE-\d{4}-\d{4,}$')
VALID_IP = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
VALID_CIDR = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$')
VALID_DOMAIN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$')

def validate_target(value: str) -> str:
    if VALID_IP.match(value) or VALID_CIDR.match(value) or VALID_DOMAIN.match(value):
        return value
    raise ValueError(f"无效目标: {value}")
```

### 10.2 输出安全

```
规则 1: 日志脱敏
  ✗ [DEBUG] Authorization: Bearer sk-abc123def456
  ✓ [DEBUG] Authorization: Bearer sk-...f456

规则 2: 错误信息不泄露内部架构
  ✗ Error: PostgreSQL connection failed at 10.0.1.50:5432 (db: sectool_prod, user: admin)
  ✓ Error: 数据库连接失败，请联系管理员

规则 3: --debug 输出加警告
  ⚠ Debug mode enabled. Output may contain sensitive information. Do not share.

规则 4: 扫描结果标记敏感级别
  输出文件自动加分类标记：
  # Classification: INTERNAL - Company Confidential
```

### 10.3 依赖安全

```
规则 1: 最小依赖原则
  只引入必要的依赖，减少供应链攻击面

规则 2: 锁文件必须提交
  package-lock.json / poetry.lock / go.sum 必须进版本控制

规则 3: 依赖审计
  npm audit / pip-audit / govulncheck 纳入 CI

规则 4: 禁止 eval/exec 动态代码执行
  绝不在用户输入上执行 eval()、exec()、Function() 等
```

### 10.4 权限与审计

```yaml
# 所有涉及写操作的命令必须记录审计日志
audit:
  enabled: true
  file: ~/.local/state/sectool/audit.log
  format: json
  events:
    - scan.started
    - scan.completed
    - vuln.status_changed
    - config.modified
    - auth.login
    - auth.logout

# 审计日志格式
{
  "timestamp": "2026-03-24T10:30:00Z",
  "user": "zhangsan",
  "action": "vuln.scan.started",
  "params": {"target": "10.0.0.0/24", "profile": "full"},
  "source_ip": "192.168.1.100"
}
```

---

## 11. 测试规范

### 11.1 测试层级

```
层级 1: 单元测试（覆盖率 ≥ 80%）
  - 参数解析与校验
  - 输出格式化
  - 数据转换逻辑
  - 错误处理路径

层级 2: 集成测试
  - API 适配器（Mock Server）
  - 本地工具适配器（Mock 子进程输出）
  - 认证流程
  - 配置加载优先级

层级 3: E2E 测试
  - 关键用户流程（auth login → scan → export）
  - 退出码验证
  - pipe 兼容性（输出能被 jq/grep 正确消费）
```

### 11.2 测试示例

```python
# 单元测试：参数校验
def test_validate_target_valid_ip():
    assert validate_target("10.0.0.1") == "10.0.0.1"

def test_validate_target_valid_cidr():
    assert validate_target("10.0.0.0/24") == "10.0.0.0/24"

def test_validate_target_rejects_injection():
    with pytest.raises(ValueError):
        validate_target("10.0.0.1; rm -rf /")

def test_validate_target_rejects_path_traversal():
    with pytest.raises(ValueError):
        validate_target("../../etc/passwd")

# 集成测试：API 适配器
def test_vuln_list_returns_table(mock_api, cli_runner):
    mock_api.get("/api/vulns").respond(200, json=SAMPLE_VULNS)
    result = cli_runner.invoke(["vuln", "list"])
    assert result.exit_code == 0
    assert "CVE-2024-1234" in result.stdout

def test_vuln_list_json_format(mock_api, cli_runner):
    mock_api.get("/api/vulns").respond(200, json=SAMPLE_VULNS)
    result = cli_runner.invoke(["vuln", "list", "--format", "json"])
    data = json.loads(result.stdout)
    assert len(data["data"]) == 2

# E2E 测试：pipe 兼容性
def test_pipe_json_to_jq(cli_runner):
    result = cli_runner.invoke(["vuln", "list", "--format", "json"])
    jq_result = subprocess.run(
        ["jq", ".[0].cve_id"],
        input=result.stdout, capture_output=True, text=True
    )
    assert jq_result.returncode == 0
    assert "CVE-" in jq_result.stdout
```

### 11.3 CI 集成

```yaml
# .github/workflows/ci.yml
name: CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Unit Tests
        run: make test-unit
      - name: Integration Tests
        run: make test-integration
      - name: Coverage Check
        run: |
          make coverage
          # 覆盖率低于 80% 则失败
      - name: Security Audit
        run: make audit
```

---

## 12. 实战模板

### 12.1 模板 A：封装本地工具（以 nmap 为例）

```python
"""sectool port scan — 封装 nmap 端口扫描"""
import subprocess
import json
import xml.etree.ElementTree as ET

import click

from sectool.output import render
from sectool.errors import ToolNotFoundError, ScanError
from sectool.validation import validate_target


@click.command("scan")
@click.option("-t", "--target", required=True, callback=validate_target,
              help="扫描目标（IP/CIDR/域名）")
@click.option("-p", "--ports", default="--top-ports 1000",
              help="端口范围（默认 top 1000）")
@click.option("--timeout", default=300, type=int,
              help="超时秒数")
@click.pass_context
def port_scan(ctx, target, ports, timeout):
    """执行端口扫描"""
    # 1. 检查依赖
    if not shutil.which("nmap"):
        raise ToolNotFoundError(
            tool="nmap",
            install_hint="brew install nmap (macOS) | apt install nmap (Linux)"
        )

    # 2. 构造命令（参数数组，防注入）
    cmd = ["nmap", "-oX", "-", "-sV", target]
    if ports.startswith("--"):
        cmd.append(ports)
    else:
        cmd.extend(["-p", ports])

    # 3. 执行（dry-run 支持）
    if ctx.obj.get("dry_run"):
        click.echo(f"[DRY RUN] {' '.join(cmd)}", err=True)
        return

    click.echo(f"扫描中: {target}...", err=True)  # 进度到 stderr
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        raise ScanError(
            f"扫描超时 ({timeout}s)",
            hint=f"缩小范围或增加 --timeout"
        )

    if result.returncode != 0:
        raise ScanError(f"nmap 退出码 {result.returncode}", detail=result.stderr)

    # 4. 解析 XML 输出 → 结构化数据
    hosts = parse_nmap_xml(result.stdout)

    # 5. 输出
    render(hosts, format=ctx.obj["format"], columns=[
        "ip", "hostname", "port", "protocol", "state", "service", "version"
    ])


def parse_nmap_xml(xml_str: str) -> list[dict]:
    """解析 nmap XML 输出为结构化数据"""
    root = ET.fromstring(xml_str)
    results = []
    for host in root.findall("host"):
        ip = host.find("address").get("addr")
        hostname = ""
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name", "")

        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            service = port.find("service")
            results.append({
                "ip": ip,
                "hostname": hostname,
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "state": port.find("state").get("state"),
                "service": service.get("name", "") if service is not None else "",
                "version": service.get("product", "") if service is not None else "",
            })
    return results
```

### 12.2 模板 B：封装 Web API（以威胁情报平台为例）

```python
"""sectool threat search — 封装威胁情报 API"""
import click

from sectool.api import api_client
from sectool.output import render
from sectool.errors import ApiError, AuthError
from sectool.validation import validate_ioc


@click.command("search")
@click.argument("ioc", callback=validate_ioc)
@click.option("--source", type=click.Choice(["all", "virustotal", "otx", "misp"]),
              default="all", help="情报源")
@click.option("-n", "--limit", default=20, type=int, help="最大返回条数")
@click.pass_context
def threat_search(ctx, ioc, source, limit):
    """查询 IOC 威胁情报

    IOC 支持：IP、域名、文件 Hash（MD5/SHA1/SHA256）、URL
    """
    client = api_client(ctx.obj["profile"])

    # API 请求
    try:
        response = client.get("/api/v1/threat/search", params={
            "ioc": ioc,
            "source": source,
            "limit": limit,
        })
    except AuthError:
        raise AuthError("Token 已过期，运行 `sectool auth login` 重新认证")

    data = response.json()

    if not data.get("data"):
        click.echo(f"未找到 {ioc} 的威胁情报", err=True)
        raise SystemExit(5)  # 资源不存在

    # 输出
    render(data["data"], format=ctx.obj["format"], columns=[
        "ioc", "type", "threat_level", "source",
        "first_seen", "last_seen", "tags"
    ])
```

### 12.3 模板 C：封装 Web API（Go + Cobra 版本）

```go
package cmd

import (
    "encoding/json"
    "fmt"
    "os"

    "github.com/spf13/cobra"
    "company.com/sectool/pkg/api"
    "company.com/sectool/pkg/output"
    "company.com/sectool/pkg/validate"
)

var threatSearchCmd = &cobra.Command{
    Use:   "search <ioc>",
    Short: "查询 IOC 威胁情报",
    Long:  "IOC 支持：IP、域名、文件 Hash（MD5/SHA1/SHA256）、URL",
    Args:  cobra.ExactArgs(1),
    PreRunE: func(cmd *cobra.Command, args []string) error {
        return validate.IOC(args[0])
    },
    RunE: func(cmd *cobra.Command, args []string) error {
        ioc := args[0]
        source, _ := cmd.Flags().GetString("source")
        limit, _ := cmd.Flags().GetInt("limit")
        format, _ := cmd.Root().PersistentFlags().GetString("format")

        client := api.NewClient(api.FromProfile(profileFlag))

        results, err := client.ThreatSearch(cmd.Context(), ioc, source, limit)
        if err != nil {
            return fmt.Errorf("查询失败: %w", err)
        }

        if len(results) == 0 {
            fmt.Fprintf(os.Stderr, "未找到 %s 的威胁情报\n", ioc)
            os.Exit(5)
        }

        return output.Render(results, format, []string{
            "ioc", "type", "threat_level", "source",
            "first_seen", "last_seen", "tags",
        })
    },
}

func init() {
    threatCmd.AddCommand(threatSearchCmd)
    threatSearchCmd.Flags().StringP("source", "s", "all", "情报源: all, virustotal, otx, misp")
    threatSearchCmd.Flags().IntP("limit", "n", 20, "最大返回条数")
}
```

### 12.4 模板 D：封装 Web API（TypeScript + Commander.js 版本）

```typescript
import { Command } from 'commander'
import { apiClient } from '../lib/api'
import { render } from '../lib/output'
import { validateIOC } from '../lib/validation'

export function registerThreatSearch(parent: Command) {
  parent
    .command('search <ioc>')
    .description('查询 IOC 威胁情报（IP/域名/Hash/URL）')
    .option('-s, --source <name>', '情报源: all, virustotal, otx, misp', 'all')
    .option('-n, --limit <number>', '最大返回条数', '20')
    .hook('preAction', (cmd) => {
      const ioc = cmd.args[0]
      if (!validateIOC(ioc)) {
        throw new Error(
          `无效的 IOC 格式: ${ioc}\n` +
          `支持: IP, 域名, MD5, SHA1, SHA256, URL`
        )
      }
    })
    .action(async (ioc: string, opts) => {
      const client = apiClient(opts.parent?.opts().profile)
      const limit = parseInt(opts.limit, 10)

      const { data } = await client.get('/api/v1/threat/search', {
        params: { ioc, source: opts.source, limit },
      })

      if (!data.data?.length) {
        process.stderr.write(`未找到 ${ioc} 的威胁情报\n`)
        process.exit(5)
      }

      render(data.data, {
        format: opts.parent?.opts().format ?? 'table',
        columns: ['ioc', 'type', 'threat_level', 'source',
                   'first_seen', 'last_seen', 'tags'],
      })
    })
}
```

---

## 13. Review Checklist

提交新的 CLI 命令时，Code Review 必须逐项检查：

### 命令设计

- [ ] 命名遵循 `名词 动词` 惯例
- [ ] 动词来自标准动词表
- [ ] `--help` 包含完整用法、选项说明和 Examples
- [ ] 80% 使用场景零 flag 即可完成

### 参数

- [ ] 通用参数（`--format`、`--verbose`、`--limit`）名称和行为与全局一致
- [ ] 必填参数最小化（≤ 2 个）
- [ ] 常用选项有短标志（`-t`、`-f`、`-o`）
- [ ] 所有参数在入口层校验，有清晰的错误提示
- [ ] 枚举参数使用 choices 约束
- [ ] 无秘密/凭据通过命令行参数传入

### 输出

- [ ] stdout 仅输出数据，状态/进度/错误走 stderr
- [ ] 支持 `--format table/json/csv` 三种格式（至少）
- [ ] JSON 输出遵循统一 envelope 格式
- [ ] TTY/非 TTY 下行为正确（颜色、进度条）
- [ ] 退出码符合规范（0/1/2/3/4/5/10）
- [ ] 输出能被 `jq`、`grep` 正确消费

### 错误

- [ ] 每条错误包含三要素：发生了什么 + 在哪里 + 怎么修
- [ ] `--verbose` 提供更多上下文
- [ ] `--debug` 提供完整诊断信息
- [ ] 网络错误有超时和重试策略
- [ ] 不在错误信息中泄露内部架构细节

### 安全

- [ ] 本地工具调用使用参数数组（非字符串拼接）
- [ ] 输入经过白名单校验（IP、CIDR、域名、CVE ID 格式）
- [ ] 文件路径有遍历防御
- [ ] 日志中敏感信息已脱敏
- [ ] 无 `eval()`/`exec()` 动态执行用户输入
- [ ] 依赖已审计，锁文件已提交

### 测试

- [ ] 单元测试覆盖参数校验（包括注入场景）
- [ ] 集成测试覆盖 API 调用（Mock）
- [ ] 退出码测试
- [ ] 测试覆盖率 ≥ 80%

### 配置

- [ ] 配置文件遵循 XDG 规范
- [ ] 环境变量使用统一前缀
- [ ] 优先级正确：flag > env > 项目配置 > 全局配置

---

## 附录 A：框架选型参考

| 语言 | 推荐框架 | 适用场景 | 启动性能 |
|------|---------|---------|---------|
| **Python** | Typer / Click | 快速原型、安全脚本封装 | ~50ms |
| **Go** | Cobra + Viper | 高性能分发、需要单二进制 | ~5ms |
| **TypeScript** | Commander.js | 前端团队、Node 生态集成 | ~18ms |
| **Rust** | clap | 极致性能、系统级工具 | ~2ms |

**选型建议**：
- **内部工具快速封装** → Python (Typer)，开发最快
- **需要分发给非技术人员** → Go (Cobra)，单二进制无依赖
- **团队已有 Node 基础设施** → TypeScript (Commander.js)
- **高频调用的基础工具** → Go 或 Rust，启动快

## 附录 B：推荐阅读

- [Command Line Interface Guidelines (clig.dev)](https://clig.dev/) — CLI 设计圣经
- [12 Factor CLI Apps](https://medium.com/@jdxcode/12-factor-cli-apps-dd3c227a0e46) — 12 原则
- [GitHub CLI 源码](https://github.com/cli/cli) — 最佳实践参考实现
- [OpenCLI 项目](https://github.com/jackwener/opencli) — Web 能力 CLI 化的参考框架

## 附录 C：快速启动

新建一个 CLI 命令的最小步骤：

```bash
# 1. 从模板创建（以 Python 为例）
cp templates/command_template.py src/commands/my_command.py

# 2. 实现三个函数
#    - validate_args()  → 参数校验
#    - execute()        → 核心逻辑
#    - format_output()  → 输出映射

# 3. 注册到主命令
#    在 src/cli.py 中添加子命令注册

# 4. 写测试
cp templates/command_test_template.py tests/test_my_command.py

# 5. 跑测试 + lint
make test lint

# 6. 提交 PR，按 Review Checklist 自检
```
