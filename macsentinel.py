#!/usr/bin/env python3
"""
MacSentinel v1.0.0
macOS 恶意域名监控溯源工具 — DNSMonitor JSON 解析 + 深度溯源 + 威胁情报 + 告警推送

功能:
  - DNSMonitor JSON 输出实时解析
  - 目标域名 DNS 查询检测（子串/后缀/精确三种匹配模式）
  - 深度进程溯源（环境变量、动态库、进程树、网络连接、打开文件）
  - 进程退出后溯源（系统日志、持久化检测、临时文件分析）
  - 威胁情报标注（签名分析、路径风险、轻量黑名单）
  - 飞书 Webhook 告警推送（频率限制 + 去重）
  - DNSMonitor 异常自动重启（指数退避）
  - 退出时可选清理网络扩展

使用:
  sudo python3 macsentinel.py            # 启动监控
  sudo python3 macsentinel.py status     # 查看运行状态
  sudo python3 macsentinel.py setup      # 配置向导
"""

import subprocess
import json
import time
import os
import sys
import signal
from datetime import datetime
from urllib.request import urlopen, Request
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from collections import OrderedDict

VERSION = "1.0.0"

# =============================================================================
# 配置区（按需修改）
# =============================================================================

# 外部配置文件路径（优先级高于下方默认值，文件不存在则使用默认值）
CONFIG_FILE = os.environ.get("MONITOR_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json"))

# ----- 监控目标 -----

# 目标域名列表（支持三种匹配模式，通过前缀指定）
# 前缀说明：
#   无前缀  = 子串匹配（默认），如 "evil.com" 匹配 evil.com / abc.evil.com / notevil.com
#   . 前缀  = 后缀匹配，如 ".evil.com" 匹配 evil.com / abc.evil.com，不匹配 notevil.com
#   = 前缀  = 精确匹配，如 "=evil.com" 仅匹配 evil.com，不匹配 abc.evil.com
TARGET_DOMAINS = [
    "cdn.pynice.com",
]

# ----- 飞书通知 -----

# 飞书 Webhook URL（优先从环境变量 FEISHU_WEBHOOK 读取，为空则禁用推送）
FEISHU_WEBHOOK = os.environ.get("FEISHU_WEBHOOK", "")

# 飞书推送频率上限（条/分钟）
# 超限时跳过推送，但告警溯源日志不受影响完整保留
FEISHU_MAX_PER_MINUTE = 30

# ----- DNSMonitor -----

# DNSMonitor 可执行文件路径（一般无需修改）
DNSMON_BIN = "/Applications/DNSMonitor.app/Contents/MacOS/DNSMonitor"

# 退出时是否清理 DNSMonitor 网络扩展
# True  = 自动清理（推荐），False = 保留（手动管理）
CLEANUP_NETEXT = True

# ----- 日志配置 -----

# 简要日志路径模板（按日分文件，每次写入时动态计算日期）
LOGFILE_TEMPLATE = "./monitor_{date}.log"
ALERT_LOGFILE_TEMPLATE = "./monitor_alert_{date}.log"

# 单个日志文件大小上限（字节），超限后滚动丢弃旧日志
# 1GB = 1073741824，512MB = 536870912
MAX_LOG_SIZE = 1073741824

# ----- 告警去重 -----

# 同一 PID + 同一域名在 N 秒内只触发一次告警
# 建议：短命进程(如 curl)设 3s，C2 心跳类设 300s
ALERT_DEDUP_SECONDS = 30

# 单次溯源超时时间（秒），超时后放弃当前溯源继续处理后续 DNS 事件
TRACE_TIMEOUT_SECONDS = 15

# ----- 威胁情报（内置轻量黑名单） -----

# 已知恶意域名（不在此列表的域名不会被拦截，仅用于风险标注）
MALICIOUS_DOMAINS = [
    "pynice.com",
    "cdn.pynice.com",
]

# 高风险路径模式（匹配进程二进制路径）
HIGH_RISK_PATHS = [
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "/Users/Shared/",
    "/private/var/",
]

# 本机主机名（自动获取，无需修改）
HOSTNAME = os.uname().nodename


def _load_external_config():
    """从外部 JSON 配置文件加载配置，覆盖默认值"""
    global TARGET_DOMAINS, FEISHU_WEBHOOK, FEISHU_MAX_PER_MINUTE
    global DNSMON_BIN, CLEANUP_NETEXT, MAX_LOG_SIZE, ALERT_DEDUP_SECONDS
    global TRACE_TIMEOUT_SECONDS, CACHE_MAX_SIZE, DEDUP_TTL_SECONDS
    global MALICIOUS_DOMAINS, HIGH_RISK_PATHS

    if not os.path.isfile(CONFIG_FILE):
        return

    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            cfg = json.load(f)

        mappings = {
            "target_domains": "TARGET_DOMAINS",
            "feishu_webhook": "FEISHU_WEBHOOK",
            "feishu_max_per_minute": "FEISHU_MAX_PER_MINUTE",
            "dnsmon_bin": "DNSMON_BIN",
            "cleanup_netext": "CLEANUP_NETEXT",
            "max_log_size": "MAX_LOG_SIZE",
            "alert_dedup_seconds": "ALERT_DEDUP_SECONDS",
            "trace_timeout_seconds": "TRACE_TIMEOUT_SECONDS",
            "cache_max_size": "CACHE_MAX_SIZE",
            "dedup_ttl_seconds": "DEDUP_TTL_SECONDS",
            "malicious_domains": "MALICIOUS_DOMAINS",
            "high_risk_paths": "HIGH_RISK_PATHS",
        }

        for json_key, global_name in mappings.items():
            if json_key in cfg:
                globals()[global_name] = cfg[json_key]

        if "feishu_webhook" not in cfg:
            FEISHU_WEBHOOK = os.environ.get("FEISHU_WEBHOOK", FEISHU_WEBHOOK)

        print(f"[配置] 已加载外部配置: {CONFIG_FILE}")
    except Exception as e:
        print(f"[配置] 外部配置加载失败，使用默认值: {e}")


_load_external_config()

# 全局状态
g_dnsmon_proc = None
g_heartbeat_time = time.time()
# 缓存最大条目数，防内存泄漏
CACHE_MAX_SIZE = 1000
# 告警去重条目最大存活时间（秒），过期自动清理
DEDUP_TTL_SECONDS = 300

# 飞书推送频率状态
g_feishu_timestamps = []

# 告警去重状态: {(pid, domain): last_hit_time}
g_recent_hits = {}

# 进程上下文缓存（LRU）
g_process_cache = OrderedDict()


def _rotate_log(filepath):
    """日志文件超限后滚动：将当前文件重命名为 .1，丢弃旧的 .1"""
    try:
        if os.path.exists(filepath) and os.path.getsize(filepath) > MAX_LOG_SIZE:
            bak = filepath + '.1'
            if os.path.exists(bak):
                os.remove(bak)
            os.rename(filepath, bak)
            print(f"[日志滚动] {filepath} 超限，已滚动到 {bak}")
    except Exception as e:
        # 日志滚动失败不影响监控主流程
        print(f"[日志滚动] 失败: {e}")


def _current_log_path(template):
    """根据当前日期动态计算日志文件路径"""
    return template.format(date=datetime.now().strftime('%Y%m%d'))


def _write_log(filepath, msg):
    """写日志（含大小检查 + 滚动）"""
    try:
        _rotate_log(filepath)
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        line = f"[{ts}] {msg}"
        print(line)
        with open(filepath, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception as e:
        print(f"[日志写入失败] {e}")
        print(f"[日志原文] {msg[:200]}")


def log(msg):
    """简要日志：日常运行事件"""
    _write_log(_current_log_path(LOGFILE_TEMPLATE), msg)


def log_alert(msg):
    """告警溯源日志：触发命中后的详细溯源信息"""
    _write_log(_current_log_path(ALERT_LOGFILE_TEMPLATE), msg)


def _trim_cache(cache, max_size=CACHE_MAX_SIZE, name="cache"):
    """限制缓存大小，LRU 淘汰最久未访问的条目"""
    if isinstance(cache, OrderedDict):
        while len(cache) > max_size:
            cache.popitem(last=False)
        if len(cache) > max_size * 0.8:
            old_count = len(cache)
            remove_count = old_count - max_size // 2
            for _ in range(remove_count):
                cache.popitem(last=False)
            log(f"[缓存] {name}: {old_count} → {len(cache)} 条 (LRU淘汰)")
    else:
        if len(cache) > max_size:
            old_count = len(cache)
            keys_to_remove = list(cache.keys())[:max_size // 2]
            for k in keys_to_remove:
                del cache[k]
            log(f"[缓存] {name}: {old_count} → {len(cache)} 条 (超{CACHE_MAX_SIZE}截断)")


def _cleanup_dedup():
    """清理过期的告警去重条目"""
    global g_recent_hits
    now = time.time()
    expired = [k for k, v in g_recent_hits.items() if now - v > DEDUP_TTL_SECONDS]
    for k in expired:
        del g_recent_hits[k]
    if expired:
        log(f"[缓存] 去重条目清理: 移除 {len(expired)} 条过期 (TTL={DEDUP_TTL_SECONDS}s)")


def check_feishu_rate():
    """检查飞书推送是否超频，返回是否允许推送"""
    global g_feishu_timestamps
    now = time.time()
    # 清理 60s 前的记录
    g_feishu_timestamps = [t for t in g_feishu_timestamps if now - t < 60]
    if len(g_feishu_timestamps) >= FEISHU_MAX_PER_MINUTE:
        return False
    g_feishu_timestamps.append(now)
    return True


def check_alert_dedup(pid, domain):
    """检查是否需要在 N 秒内对同一 PID+域名去重"""
    global g_recent_hits
    now = time.time()
    key = (str(pid), domain)
    last_time = g_recent_hits.get(key, 0)
    if now - last_time < ALERT_DEDUP_SECONDS:
        return False  # 去重，跳过
    g_recent_hits[key] = now
    return True


def send_feishu(title, content):
    """发送飞书卡片消息（受频率限制）"""
    if not FEISHU_WEBHOOK:
        return

    if not check_feishu_rate():
        log(f"[Feishu推送] 跳过: 已达频率上限 ({FEISHU_MAX_PER_MINUTE}/分钟)")
        return

    msg = {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": "red"
            },
            "elements": [
                {
                    "tag": "div",
                    "text": {"tag": "lark_md", "content": content}
                }
            ]
        }
    }
    try:
        data = json.dumps(msg, ensure_ascii=False).encode('utf-8')
        req = Request(FEISHU_WEBHOOK, data=data, headers={"Content-Type": "application/json"})
        resp = urlopen(req, timeout=10)
        log(f"[Feishu推送] 成功: HTTP {resp.status}")
    except Exception as e:
        log(f"[Feishu推送] 失败: {e}")


def run_cmd(cmd, timeout=5):
    """执行命令并返回输出"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


# ============================================================
# 威胁情报与风险评估
# ============================================================

def assess_risk(proc_path, codesign_info, proc_name):
    """
    综合评估进程风险等级
    返回: (等级, [风险标签列表])
    """
    risk_level = "low"  # low / medium / high
    tags = []

    # 1. 代码签名分析
    has_valid_signature = bool(codesign_info)
    is_apple_signed = "Apple Root CA" in codesign_info if codesign_info else False
    team_not_set = "TeamIdentifier=not set" in codesign_info if codesign_info else False

    if not has_valid_signature:
        tags.append("⚠️ 无代码签名")
        risk_level = "medium"
    elif team_not_set and not is_apple_signed:
        tags.append("⚠️ 无团队签名")
        risk_level = "medium"
    elif is_apple_signed:
        tags.append("🍎 苹果官方签名")

    # 2. 路径风险分析
    if proc_path:
        for pattern in HIGH_RISK_PATHS:
            if pattern in proc_path:
                tags.append(f"⚠️ 可疑路径: {proc_path}")
                risk_level = "high"
                break
        if "/usr/bin/" in proc_path or "/bin/" in proc_path or "/usr/sbin/" in proc_path:
            tags.append("📦 系统命令")
        elif "/Applications/" in proc_path:
            tags.append("📱 应用软件")

    # 3. 进程名分析
    suspicious_names = ["curl", "wget", "nslookup", "dig", "python", "perl", "bash", "sh", "osascript"]
    if any(sn in proc_name.lower() for sn in suspicious_names):
        if risk_level == "low":
            risk_level = "medium"
        tags.append(f"⚡ 可执行命令: {proc_name}")

    return risk_level, tags


# ============================================================
# 进程树构建
# ============================================================

def get_process_tree(pid, max_depth=10):
    """递归获取进程树，返回结构化文本"""
    lines = []
    seen = set()

    def _walk(current_pid, depth):
        if depth > max_depth or current_pid in seen or not current_pid:
            return
        seen.add(current_pid)
        cmd = run_cmd(f"ps -p {current_pid} -o command= 2>/dev/null")
        if not cmd:
            return
        indent = "  " * depth
        prefix = "└─ " if depth > 0 else "   "
        lines.append(f"{indent}{prefix}PID={current_pid} {cmd[:120]}")
        ppid = run_cmd(f"ps -p {current_pid} -o ppid= 2>/dev/null").strip()
        _walk(ppid, depth + 1)

    _walk(pid, 0)
    # 如果只有自己，也标记一下
    return "\n".join(lines) if lines else f"PID={pid} (进程树不可用)"


# ============================================================
# 持久化检测
# ============================================================

def check_persistence(proc_path, domain):
    """检查 LaunchAgents/Daemons 中是否引用进程路径或域名"""
    results = []
    search_dirs = [
        os.path.expanduser("~/Library/LaunchAgents"),
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/System/Library/LaunchAgents",
        "/System/Library/LaunchDaemons",
    ]

    search_terms = []
    if proc_path:
        # 提取文件名和后缀
        basename = os.path.basename(proc_path)
        name_no_ext = os.path.splitext(basename)[0]
        search_terms.extend([basename, name_no_ext])
    if domain:
        domain_main = domain.split(".")[-2] if len(domain.split(".")) >= 2 else domain
        search_terms.append(domain_main)

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        for term in search_terms:
            cmd = f'grep -rli "{term}" "{d}" 2>/dev/null | head -3'
            found = run_cmd(cmd)
            if found:
                for path in found.split('\n'):
                    if path.strip():
                        results.append(f"  • {path} (包含: {term})")

    return results[:6]


def check_temp_files(proc_path, start_time_str):
    """检查进程启动后是否有新创建的临时文件（仅关注 /tmp、/var/tmp）"""
    results = []
    target_dirs = ["/tmp", "/var/tmp"]

    # 尝试解析启动时间
    try:
        start_ts = datetime.strptime(start_time_str, "%a  %m/%d %H:%M:%S %Y")
        start_str = start_ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        start_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            from datetime import timedelta
            start_ts = datetime.now() - timedelta(minutes=5)
            start_str = start_ts.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return results

    for d in target_dirs:
        if not os.path.isdir(d):
            continue
        cmd = f'find "{d}" -newermt "{start_str}" -type f 2>/dev/null | head -5'
        found = run_cmd(cmd)
        if found:
            for path in found.split('\n'):
                if path.strip():
                    results.append(f"  • {path}")

    return results[:10]


def check_crash_reports(pid):
    """检查进程是否有崩溃报告"""
    crash_dir = os.path.expanduser("~/Library/Logs/DiagnosticReports")
    if not os.path.isdir(crash_dir):
        return []
    cmd = f'ls -lt "{crash_dir}" 2>/dev/null | grep -i "_{pid}_" | head -3'
    found = run_cmd(cmd)
    if found:
        return [f"  • {line}" for line in found.split('\n') if line.strip()]
    return []


# ============================================================
# 深度溯源函数（核心增强）
# ============================================================

def trace_process(pid, proc_name, proc_path, domain, dns_answers):
    """深度溯源进程，返回格式化文本"""
    lines = []
    lines.append(f"**🖥 主机:** {HOSTNAME}")
    lines.append(f"**🕐 时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**🌐 域名:** {domain}")
    if dns_answers:
        lines.append(f"**📡 DNS解析:**")
        for a in dns_answers[:5]:
            lines.append(f"  - {a}")
    lines.append("")
    lines.append("---")
    lines.append("")

    log(f"[溯源] 开始深度溯源 PID={pid}, Name={proc_name}")

    # ⚡ 第一步：快速捕获进程运行时上下文（在进程退出前完成）
    # 先查缓存：同一 PID 可能在之前命中时已捕获过上下文
    global g_process_cache
    pid_key = str(pid)
    cached = g_process_cache.get(pid_key, {})
    if pid_key in g_process_cache:
        g_process_cache.move_to_end(pid_key)

    # ps 查询极快(~10ms)，必须在 codesign 等慢操作之前执行
    cmd = run_cmd(f"ps -p {pid} -o command= 2>/dev/null")
    user = run_cmd(f"ps -p {pid} -o user= 2>/dev/null")
    ppid = run_cmd(f"ps -p {pid} -o ppid= 2>/dev/null").strip()
    start_time = run_cmd(f"ps -p {pid} -o lstart= 2>/dev/null")

    # 如果进程已退出但有缓存，用缓存的 PPID 继续查父进程
    if not ppid and cached.get("ppid"):
        ppid = cached["ppid"]
        user = cached.get("user", user)

    # 快速捕获父进程链（即使子进程已退出，父进程可能还活着）
    parent_cmd = ""
    parent_user = ""
    grandparent_cmd = ""
    if ppid:
        # 也查父进程缓存
        if not cmd and cached.get("parent_cmd"):
            parent_cmd = cached["parent_cmd"]
            parent_user = cached.get("parent_user", "")
            grandparent_cmd = cached.get("grandparent_cmd", "")
        else:
            parent_cmd = run_cmd(f"ps -p {ppid} -o command= 2>/dev/null")
            parent_user = run_cmd(f"ps -p {ppid} -o user= 2>/dev/null")
            gppid = run_cmd(f"ps -p {ppid} -o ppid= 2>/dev/null").strip()
            if gppid:
                grandparent_cmd = run_cmd(f"ps -p {gppid} -o command= 2>/dev/null")

    # 保存到缓存（供该 PID 的后续命中使用）
    if cmd or ppid:
        g_process_cache[pid_key] = {
            "ppid": ppid,
            "user": user,
            "cmd": cmd,
            "start_time": start_time,
            "parent_cmd": parent_cmd,
            "parent_user": parent_user,
            "grandparent_cmd": grandparent_cmd,
        }
        g_process_cache.move_to_end(pid_key)

    # 第二步：获取代码签名信息（可能较慢 ~1-3s）
    codesign_info = ""
    if proc_path and os.path.isfile(proc_path):
        codesign_info = run_cmd(
            f'codesign -dvv "{proc_path}" 2>&1 | grep -E "Identifier|TeamIdentifier|Authority" | head -5')

    # 风险评估
    risk_level, risk_tags = assess_risk(proc_path, codesign_info, proc_name)
    if risk_level == "high":
        status_tag = "🔴 高风险"
    elif risk_level == "medium":
        status_tag = "🟡 中风险"
    else:
        status_tag = "🟢 低风险"

    lines.append(f"**🎯 风险评级:** {status_tag}")
    if risk_tags:
        for t in risk_tags:
            lines.append(f"  {t}")
    lines.append("")

    # DNSMonitor 捕获的发起进程信息
    lines.append("**📋 发起进程 (DNSMonitor 捕获)**")
    lines.append(f"- PID: {pid}")
    lines.append(f"- Name: {proc_name}")
    lines.append(f"- Path: `{proc_path}`")
    lines.append("")

    log(f"[溯源] 风险评级: {status_tag}, PID={pid}, Name={proc_name}")

    if cmd:
        lines.append(f"**🟢 进程存活 (PID: {pid})**")
        lines.append(f"- User: {user}")
        lines.append(f"- Cmd: `{cmd}`")
        lines.append(f"- Start: {start_time}")
        lines.append(f"- PPID: {ppid}")
        lines.append("")
        log(f"[溯源] 进程存活: user={user}, ppid={ppid}")

        if ppid:
            tree = get_process_tree(int(pid))
            if tree:
                lines.append("**🌲 进程树**")
                lines.append(f"```\n{tree}\n```")
                lines.append("")

        if ppid and parent_cmd:
            lines.append("**👆 父进程**")
            lines.append(f"- PID: {ppid}, User: {parent_user}")
            lines.append(f"- Cmd: `{parent_cmd}`")
            if grandparent_cmd:
                lines.append(f"- Grandparent: `{grandparent_cmd}`")
            lines.append("")

        env_output = run_cmd(
            f"ps ewww -p {pid} 2>/dev/null | tr ' ' '\\n' | grep -iE "
            f"'(API_KEY|TOKEN|PASSWD|SECRET|PROXY|C2|http|HOST|USERNAME|PASSWORD|KEY|SECRET|SALT)' "
            f"| head -8")
        if env_output:
            masked_lines = []
            for line in env_output.split('\n'):
                if '=' in line:
                    k, _, v = line.partition('=')
                    if len(v) > 4:
                        v = v[:4] + '****'
                    masked_lines.append(f"{k}={v}")
                else:
                    masked_lines.append(line)
            env_output = '\n'.join(masked_lines)
            lines.append("**🔑 环境变量 (可疑项，已脱敏)**")
            lines.append(f"```\n{env_output}\n```")
            lines.append("")
            log(f"[溯源] 环境变量: {len(env_output.split(chr(10)))} 条可疑")

        # 一次性 lsof 获取所有信息，避免多次调用
        lsof_raw = run_cmd(f"lsof -nP -p {pid} 2>/dev/null | grep -v '^COMMAND'")

        if lsof_raw:
            dylibs_lines = []
            listen_lines = []
            net_lines = []
            files_lines = []
            temp_lines = []
            cwd_line = ""

            for lsof_line in lsof_raw.split('\n'):
                if not lsof_line.strip():
                    continue
                if '.dylib' in lsof_line and '/usr/lib' not in lsof_line and '/System' not in lsof_line:
                    parts = lsof_line.split()
                    if parts:
                        dylibs_lines.append(parts[-1])
                if 'TCP' in lsof_line:
                    if 'LISTEN' in lsof_line:
                        listen_lines.append(lsof_line)
                    else:
                        net_lines.append(lsof_line)
                if '/usr/lib' not in lsof_line and '/System' not in lsof_line and '/dev/' not in lsof_line and '.dylib' not in lsof_line and '/Library/Preferences' not in lsof_line:
                    files_lines.append(lsof_line)
                if any(p in lsof_line for p in ['/tmp/', '/var/tmp/', '/private/tmp/', '/Downloads/', '/Caches/']):
                    temp_lines.append(lsof_line)

            cwd_line = run_cmd(
                f"lsof -p {pid} -Fn 2>/dev/null | grep -A1 'fcwd' | grep '^n' | sed 's/^n//'")

            if dylibs_lines:
                dylibs = '\n'.join(sorted(set(dylibs_lines))[:10])
                lines.append("**📚 加载的动态库 (非系统)**")
                lines.append(f"```\n{dylibs}\n```")
                lines.append("")
                log(f"[溯源] 动态库: {len(dylibs_lines)} 个非系统库")

            if listen_lines:
                listen_out = '\n'.join(listen_lines[:5])
                lines.append("**👂 监听端口**")
                lines.append(f"```\n{listen_out}\n```")
                lines.append("")
                log(f"[溯源] 监听端口: 发现")

            if net_lines:
                net_out = '\n'.join(net_lines[:10])
                lines.append("**🔗 网络连接 (已建立)**")
                lines.append(f"```\n{net_out}\n```")
                lines.append("")
                log(f"[溯源] 网络连接: {len(net_lines)} 条")

            if files_lines:
                files_out = '\n'.join(files_lines[:20])
                lines.append("**📂 打开的文件**")
                lines.append(f"```\n{files_out}\n```")
                lines.append("")

            if temp_lines:
                temp_out = '\n'.join(temp_lines[:10])
                lines.append("**⚠️ 可疑文件 (临时/下载/缓存目录)**")
                lines.append(f"```\n{temp_out}\n```")
                lines.append("")

            if cwd_line:
                lines.append(f"**📁 工作目录:** `{cwd_line}`")
                lines.append("")

    else:
        # ========== 进程已退出，但父进程信息已提前捕获 ==========
        lines.append(f"**🔴 进程已退出 (PID: {pid})**")
        if user:
            lines.append(f"- User: {user}")
        if cmd:
            lines.append(f"- Cmd: `{cmd}`")
        if start_time:
            lines.append(f"- Start: {start_time}")
        lines.append("")

        # 显示已捕获的父进程链（即使在子进程退出后）
        if ppid and parent_cmd:
            lines.append("**👆 调用者（父进程，已提前捕获）**")
            lines.append(f"- PID: {ppid}, User: {parent_user}")
            lines.append(f"- Cmd: `{parent_cmd}`")
            if grandparent_cmd:
                lines.append(f"- Grandparent: `{grandparent_cmd}`")
            lines.append("")
            log(f"[溯源] 进程已退出，但捕获到调用链: PPID={ppid} {parent_cmd[:80]}")

        # 尝试从系统日志获取信息
        syslog_output = run_cmd(
            f"log show --predicate 'processID == {pid}' --last 10m --style compact 2>/dev/null | "
            f"head -10")
        if syslog_output:
            lines.append("**📋 近期系统日志**")
            lines.append(f"```\n{syslog_output[:1000]}\n```")
            lines.append("")
            log(f"[溯源] 系统日志: 获取到 {len(syslog_output)} 字符")

        # 持久化检测
        persist_results = check_persistence(proc_path, domain)
        if persist_results:
            lines.append("**🔁 持久化检测 (LaunchAgents/Daemons)**")
            for r in persist_results:
                lines.append(r)
            lines.append("")
            log(f"[溯源] 持久化: 发现 {len(persist_results)} 项")

        # 临时文件检测
        temp_files = check_temp_files(proc_path, start_time)
        if temp_files:
            lines.append("**🗑️ 近期创建文件**")
            for t in temp_files:
                lines.append(t)
            lines.append("")

        # Crash 报告
        crashes = check_crash_reports(pid)
        if crashes:
            lines.append("**💥 崩溃报告**")
            for c in crashes:
                lines.append(c)
            lines.append("")

    # ===== 以下为无论进程是否存活都能获取的信息 =====

    # 代码签名
    if codesign_info:
        lines.append("**🔏 代码签名**")
        lines.append(f"```\n{codesign_info}\n```")
        lines.append("")
        log(f"[溯源] 代码签名: 完成")

    # SHA256
    sha = ""
    if proc_path and os.path.isfile(proc_path):
        sha = run_cmd(f'shasum -a 256 "{proc_path}" 2>/dev/null | awk \'{{print $1}}\'')
        if sha:
            lines.append(f"**#️⃣ SHA256:** `{sha}`")
            log(f"[溯源] SHA256: {sha[:20]}...")

    if proc_path and os.path.isfile(proc_path):
        try:
            st = os.stat(proc_path)
            mtime = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            size_kb = st.st_size / 1024
            lines.append(f"**📅 二进制修改时间:** {mtime}")
            lines.append(f"**📦 文件大小:** {size_kb:.1f} KB")
        except Exception:
            pass

    log(f"[溯源] 溯源完成，共 {len(lines)} 行")
    return "\n".join(lines)


# ============================================================
# DNSMonitor JSON 解析器
# ============================================================

def parse_dnsmonitor_json(stream):
    """
    解析 DNSMonitor -json 输出流
    Yields: (process_dict, packet_dict, timestamp, qnames)
    """
    line_count = 0
    parse_ok = 0
    parse_fail = 0

    log("[解析器] DNSMonitor JSON 解析器启动")

    for raw_line in stream:
        line = raw_line.strip()
        line_count += 1

        if not line:
            continue

        # 跳过非 JSON 行（DNSMonitor 有时会输出 log 前缀）
        if not line.startswith("{"):
            continue

        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            parse_fail += 1
            continue

        parse_ok += 1

        process = obj.get("Process", {})
        packet = obj.get("Packet", {})
        timestamp = obj.get("Timestamp", "")

        if not process or not packet:
            continue

        questions = packet.get("Questions", [])
        qnames = [q.get("Question Name", "") for q in questions]

        if parse_ok % 100 == 0:
            log(f"[解析器] 状态: 已解析 {parse_ok} 条 (总行 {line_count}, 失败 {parse_fail})")

        yield process, packet, timestamp, qnames

    log(f"[解析器] 停止。总行数:{line_count} 成功:{parse_ok} 失败:{parse_fail}")


def _domain_match(domain_pattern, qname):
    """根据前缀选择匹配模式：
    无前缀  = 子串匹配 (domain in qname)
    . 前缀  = 后缀匹配 (qname == domain 或 qname 以 .domain 结尾)
    = 前缀  = 精确匹配 (qname == domain)
    """
    qname_lower = qname.lower().rstrip('.')
    if domain_pattern.startswith('='):
        target = domain_pattern[1:].lower().rstrip('.')
        return qname_lower == target
    elif domain_pattern.startswith('.'):
        target = domain_pattern[1:].lower().rstrip('.')
        return qname_lower == target or qname_lower.endswith('.' + target)
    else:
        target = domain_pattern.lower().rstrip('.')
        return target in qname_lower


def check_domain_match_json(packet, target_domains):
    """检查 packet 中是否包含目标域名"""
    questions = packet.get("Questions", [])
    for q in questions:
        qname = q.get("Question Name", "")
        for domain in target_domains:
            if _domain_match(domain, qname):
                return domain.lstrip('=.')
    return None


def extract_dns_answers_json(packet):
    """从 JSON packet 中提取 DNS 解析结果"""
    result = []
    answers = packet.get("Answers", [])
    for a in answers:
        parts = []
        name = a.get("Name", "")
        host = a.get("Host Address", "")
        cname = a.get("Canonical Name", "")
        if name:
            parts.append(name)
        if cname:
            parts.append(f"CNAME {cname}")
        if host:
            parts.append(f"A {host}")
        result.append(" ".join(parts) if parts else str(a))
    authorities = packet.get("Authorities", [])
    for a in authorities:
        name = a.get("Name", "")
        if name:
            result.append(f"Authority: {name}")
    return result


# ============================================================
# DNSMonitor 进程管理
# ============================================================

def start_dnsmonitor():
    """启动 DNSMonitor 进程"""
    proc = subprocess.Popen(
        [DNSMON_BIN, "-json", "-daemon"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1
    )
    return proc


def stop_dnsmonitor(proc):
    """停止 DNSMonitor 进程"""
    if proc and proc.poll() is None:
        log("[DNSMonitor] 正在停止...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log("[DNSMonitor] 强制终止")
            proc.kill()
            proc.wait(timeout=3)
        log("[DNSMonitor] 已停止")


def cleanup_netext():
    """清理 DNSMonitor 网络扩展"""
    if not CLEANUP_NETEXT:
        return
    log("[清理] 清理 DNSMonitor 网络扩展...")
    # 方案1: systemextensionsctl 卸载
    run_cmd(
        f"systemextensionsctl uninstall 2>&1 | grep -i dnsmonitor || true",
        timeout=3
    )
    # 方案2: 确保所有 DNSMonitor 进程退出
    run_cmd("pkill -f DNSMonitor 2>/dev/null")
    log("[清理] 网络扩展清理完成")


# ============================================================
# 信号处理
# ============================================================

g_shutdown_flag = False
g_hit_count = 0


def signal_handler(signum, frame):
    """信号处理函数 - 设置退出标志并终止 DNSMonitor 以解除 readline 阻塞"""
    global g_shutdown_flag, g_dnsmon_proc
    signame = signal.Signals(signum).name
    log(f"[信号] 收到 {signame}，准备关闭...")
    g_shutdown_flag = True
    # 终止 DNSMonitor 以解除 stdout readline 阻塞
    if g_dnsmon_proc and g_dnsmon_proc.poll() is None:
        log("[信号] 终止 DNSMonitor 以解除阻塞...")
        g_dnsmon_proc.terminate()


# ============================================================
# 主函数
# ============================================================

def main():
    global g_dnsmon_proc, g_heartbeat_time, g_hit_count

    # 启动前检查
    if not os.path.isfile(DNSMON_BIN):
        print(f"[!] DNSMonitor not found: {DNSMON_BIN}")
        sys.exit(1)

    if os.geteuid() != 0:
        print("[!] Need root. Run with: sudo python3 macsentinel.py")
        sys.exit(1)

    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log(f"╔═══════════════════════════════════════════╗")
    log(f"║     MacSentinel v{VERSION}                  ║")
    log(f"╚═══════════════════════════════════════════╝")
    log(f"[启动] PID: {os.getpid()}")
    log(f"[配置] 监控域名: {TARGET_DOMAINS}")
    log(f"[配置] 清理网络扩展: {CLEANUP_NETEXT}")

    # 启动通知
    try:
        send_feishu(
            "🟢 MacSentinel 已启动",
            f"**主机:** {HOSTNAME}\n"
            f"**目标域名:** {', '.join(TARGET_DOMAINS)}\n"
            f"**启动时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**增强功能:** 深度溯源 + 威胁情报 + 自动恢复"
        )
    except Exception as e:
        log(f"[启动通知] 飞书异常: {e}")

    # 主循环
    dnsmon_restart_count = 0
    restart_backoff = 3
    MAX_RESTART_BACKOFF = 300
    while not g_shutdown_flag:
        log("[DNSMonitor] 启动中...")
        g_dnsmon_proc = start_dnsmonitor()

        if g_dnsmon_proc.poll() is not None:
            log(f"[DNSMonitor] 启动失败 (exit={g_dnsmon_proc.returncode})")
            log(f"[DNSMonitor] {restart_backoff}s 后重试...")
            time.sleep(restart_backoff)
            restart_backoff = min(restart_backoff * 2, MAX_RESTART_BACKOFF)
            continue

        log(f"[DNSMonitor] 运行中 (PID: {g_dnsmon_proc.pid})")
        dnsmon_restart_count += 1
        g_heartbeat_time = time.time()
        restart_backoff = 3

        # 解析 DNSMonitor 输出
        try:
            for process_info, packet, timestamp, qnames in parse_dnsmonitor_json(g_dnsmon_proc.stdout):
                if g_shutdown_flag:
                    break

                # 心跳日志（每 5 分钟无命中时）
                now = time.time()
                if now - g_heartbeat_time > 300:
                    log(f"[心跳] 运行中... 总命中: {g_hit_count}")
                    _trim_cache(g_process_cache, name="process_cache")
                    _cleanup_dedup()
                    g_heartbeat_time = now

                # 记录所有 DNS 查询（调试用）
                if qnames:
                    pid = process_info.get("pid", "?")
                    name = process_info.get("name", "?")
                    log(f"[DNS查询] pid={pid} name={name} q={qnames}")

                # 检查是否命中
                matched_domain = check_domain_match_json(packet, TARGET_DOMAINS)
                if not matched_domain:
                    continue

                # === 命中 ===
                g_hit_count += 1
                pid = process_info.get("pid", "")
                name = process_info.get("name", "")
                path = process_info.get("path", "")
                dns_answers = extract_dns_answers_json(packet)

                log(f"🚨 [命中 #{g_hit_count}] domain={matched_domain} pid={pid} name={name}")
                log(f"[命中] DNS解析: {dns_answers}")

                # 深度溯源（单次处理设超时，避免单个命中阻塞后续 DNS 处理）
                trace_result = ""
                try:
                    trace_start = time.time()
                    with ThreadPoolExecutor(max_workers=1) as executor:
                        future = executor.submit(trace_process, pid, name, path, matched_domain, dns_answers)
                        try:
                            trace_result = future.result(timeout=TRACE_TIMEOUT_SECONDS)
                        except FuturesTimeoutError:
                            log(f"[命中] 溯源超时 ({TRACE_TIMEOUT_SECONDS}s)，跳过本次溯源")
                            trace_result = f"**⚠️ 溯源超时 ({TRACE_TIMEOUT_SECONDS}s)，内容不完整**"
                    trace_elapsed = time.time() - trace_start
                    log(f"[命中] 溯源完成，耗时 {trace_elapsed:.1f}s")
                except Exception as e:
                    log(f"[命中] 溯源异常: {e}")
                    trace_result = f"**⚠️ 溯源过程异常: {e}**"

                # ★ 无论飞书是否推送，告警溯源日志必须完整保留 ★
                try:
                    log_alert(f"=== 告警 #{g_hit_count} ===")
                    log_alert(f"域名: {matched_domain} | PID: {pid} | 进程: {name} | 路径: {path}")
                    log_alert(f"DNS解析: {dns_answers}")
                    if trace_result:
                        log_alert("")
                        log_alert(trace_result)
                    log_alert("=" * 60)
                except Exception as e:
                    log(f"[命中] 告警日志写入异常: {e}")

                # 推送飞书（受频率限制，超限时跳过推送但不丢日志）
                if trace_result:
                    send_feishu(f"🚨 MacSentinel 告警: {matched_domain}", trace_result)

                log(f"[命中] 告警处理完成 (#{g_hit_count})")

        except Exception as e:
            if not g_shutdown_flag:
                log(f"[错误] 解析循环异常: {e}")
                import traceback
                log(traceback.format_exc())

        # DNSMonitor 已退出，检查是否需要重启
        if not g_shutdown_flag:
            log(f"[DNSMonitor] 进程已退出 (exit={g_dnsmon_proc.poll()}), {restart_backoff}s 后重启...")
            stop_dnsmonitor(g_dnsmon_proc)
            time.sleep(restart_backoff)
            restart_backoff = min(restart_backoff * 2, MAX_RESTART_BACKOFF)

    # === 优雅关闭 ===
    log(f"[关闭] 守护进程关闭中... 总命中: {g_hit_count}")

    stop_dnsmonitor(g_dnsmon_proc)

    if CLEANUP_NETEXT:
        cleanup_netext()

    try:
        send_feishu(
            "🔴 MacSentinel 已停止",
            f"**主机:** {HOSTNAME}\n"
            f"**停止时间:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"**本次运行命中:** {g_hit_count} 次\n"
            f"**DNSMonitor 重启:** {dnsmon_restart_count} 次"
        )
    except Exception as e:
        log(f"[关闭通知] 飞书异常: {e}")

    log(f"[关闭] 守护进程退出。总命中: {g_hit_count}")


def _show_status():
    """显示当前监控守护进程的运行状态"""
    print(f"\n{'='*50}")
    print(f"  MacSentinel v{VERSION} - 运行状态")
    print(f"{'='*50}")

    pid_out = run_cmd("pgrep -f 'python3.*macsentinel.py' 2>/dev/null")
    dnsmon_out = run_cmd("pgrep -f DNSMonitor 2>/dev/null")

    daemon_alive = bool(pid_out) and pid_out != str(os.getpid())
    dnsmon_alive = bool(dnsmon_out)

    print(f"  守护进程: {'🟢 运行中' if daemon_alive else '🔴 未运行'}")
    if daemon_alive:
        print(f"    PID: {pid_out}")
    print(f"  DNSMonitor: {'🟢 运行中' if dnsmon_alive else '🔴 未运行'}")
    if dnsmon_alive:
        print(f"    PID: {dnsmon_out}")

    today = datetime.now().strftime('%Y%m%d')
    log_path = f"./monitor_{today}.log"
    alert_path = f"./monitor_alert_{today}.log"

    if os.path.isfile(log_path):
        size = os.path.getsize(log_path)
        hits = 0
        with open(log_path, 'r', encoding='utf-8') as f:
            for line in f:
                if '🚨 [命中' in line:
                    hits += 1
        print(f"  今日命中: {hits} 次")
        print(f"  简要日志: {log_path} ({size/1024:.1f} KB)")
    else:
        print(f"  今日命中: (日志不存在)")

    if os.path.isfile(alert_path):
        size = os.path.getsize(alert_path)
        print(f"  告警日志: {alert_path} ({size/1024:.1f} KB)")

    print(f"  监控域名: {TARGET_DOMAINS}")
    print(f"  飞书推送: {'已配置' if FEISHU_WEBHOOK else '未配置'}")
    print(f"{'='*50}\n")


def _input(prompt, default=""):
    """带默认值的输入"""
    if default:
        result = input(f"{prompt} [{default}]: ").strip()
    else:
        result = input(f"{prompt}: ").strip()
    return result if result else default


def _load_current_config():
    """加载当前配置（从 config.json 或源码默认值）"""
    cfg = {
        "target_domains": TARGET_DOMAINS,
        "feishu_webhook": FEISHU_WEBHOOK,
        "feishu_max_per_minute": FEISHU_MAX_PER_MINUTE,
        "dnsmon_bin": DNSMON_BIN,
        "cleanup_netext": CLEANUP_NETEXT,
        "max_log_size": MAX_LOG_SIZE,
        "alert_dedup_seconds": ALERT_DEDUP_SECONDS,
        "trace_timeout_seconds": TRACE_TIMEOUT_SECONDS,
        "cache_max_size": CACHE_MAX_SIZE,
        "dedup_ttl_seconds": DEDUP_TTL_SECONDS,
        "malicious_domains": MALICIOUS_DOMAINS,
        "high_risk_paths": HIGH_RISK_PATHS,
    }
    if os.path.isfile(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            cfg.update(saved)
        except Exception:
            pass
    return cfg


def _show_current_config(cfg):
    """展示当前配置摘要"""
    print(f"\n  📋 当前配置:")
    print(f"  ┌─────────────────────────────────────────────────┐")

    domains = cfg.get("target_domains", [])
    domain_str = ", ".join(domains) if domains else "(无)"
    print(f"  │ 监控域名:   {domain_str:<33} │")

    webhook = cfg.get("feishu_webhook", "")
    if webhook:
        masked = webhook[:50] + "..." if len(webhook) > 50 else webhook
        print(f"  │ 飞书推送:   {'已配置':<33} │")
    else:
        print(f"  │ 飞书推送:   {'未配置':<33} │")

    print(f"  │ 去重窗口:   {cfg.get('alert_dedup_seconds', 30)}s{' '*30} │")
    print(f"  │ 溯源超时:   {cfg.get('trace_timeout_seconds', 15)}s{' '*30} │")
    print(f"  │ DNSMonitor: {cfg.get('dnsmon_bin', ''):<33} │")
    print(f"  │ 清理扩展:   {'是' if cfg.get('cleanup_netext', True) else '否':<33} │")
    print(f"  └─────────────────────────────────────────────────┘")


def _run_setup():
    """交互式配置向导"""
    cfg = _load_current_config()

    print(f"\n╔════════════════════════════════════════════════╗")
    print(f"║     MacSentinel v{VERSION} - 配置向导            ║")
    print(f"╚════════════════════════════════════════════════╝")

    has_config = os.path.isfile(CONFIG_FILE)
    if has_config:
        _show_current_config(cfg)
        print()
        modify = input("  是否修改配置? [y/N]: ").strip().lower()
        if modify != 'y':
            print("  已取消。")
            return
    else:
        print(f"\n  未找到配置文件 ({CONFIG_FILE})，开始初始化配置...\n")

    # ── 第1步: 监控域名 ──
    print(f"  ── 第1步: 监控域名 ──")
    print(f"  匹配模式说明:")
    print(f"    无前缀 = 子串匹配  (evil.com → 匹配 evil.com / abc.evil.com / notevil.com)")
    print(f"    . 前缀 = 后缀匹配  (.evil.com → 匹配 evil.com / abc.evil.com)")
    print(f"    = 前缀 = 精确匹配  (=evil.com → 仅匹配 evil.com)")
    current_domains = cfg.get("target_domains", [])
    if current_domains:
        print(f"  当前: {', '.join(current_domains)}")
    domain_input = _input("  输入目标域名（逗号分隔）", ", ".join(current_domains) if current_domains else "")
    if domain_input:
        cfg["target_domains"] = [d.strip() for d in domain_input.split(",") if d.strip()]
    print()

    # ── 第2步: 飞书通知 ──
    print(f"  ── 第2步: 飞书通知 ──")
    current_webhook = cfg.get("feishu_webhook", "")
    if current_webhook:
        print(f"  当前: {current_webhook[:60]}{'...' if len(current_webhook) > 60 else ''}")
    else:
        print(f"  当前: 未配置（告警仅写入本地日志）")
    webhook_input = _input("  飞书 Webhook URL（留空禁用推送）", current_webhook)
    cfg["feishu_webhook"] = webhook_input
    if webhook_input:
        freq = _input("  推送频率上限（条/分钟）", str(cfg.get("feishu_max_per_minute", 30)))
        try:
            cfg["feishu_max_per_minute"] = int(freq)
        except ValueError:
            pass
    print()

    # ── 第3步: 高级配置 ──
    print(f"  ── 第3步: 高级配置 ──")

    dedup = _input("  告警去重窗口（秒）", str(cfg.get("alert_dedup_seconds", 30)))
    try:
        cfg["alert_dedup_seconds"] = int(dedup)
    except ValueError:
        pass

    trace_timeout = _input("  溯源超时（秒）", str(cfg.get("trace_timeout_seconds", 15)))
    try:
        cfg["trace_timeout_seconds"] = int(trace_timeout)
    except ValueError:
        pass

    dnsmon = _input("  DNSMonitor 路径", cfg.get("dnsmon_bin", DNSMON_BIN))
    cfg["dnsmon_bin"] = dnsmon

    cleanup = _input("  退出时清理网络扩展 (y/n)", "y" if cfg.get("cleanup_netext", True) else "n")
    cfg["cleanup_netext"] = cleanup.lower() != 'n'
    print()

    # ── 第4步: 威胁情报（可选） ──
    print(f"  ── 第4步: 威胁情报（可选） ──")
    current_malicious = cfg.get("malicious_domains", [])
    if current_malicious:
        print(f"  当前恶意域名: {', '.join(current_malicious)}")
    malicious_input = _input("  已知恶意域名（逗号分隔，留空跳过）", ", ".join(current_malicious) if current_malicious else "")
    if malicious_input:
        cfg["malicious_domains"] = [d.strip() for d in malicious_input.split(",") if d.strip()]

    current_risk_paths = cfg.get("high_risk_paths", [])
    print(f"  当前高风险路径: {', '.join(current_risk_paths)}")
    risk_input = _input("  高风险路径（逗号分隔，留空保持默认）", ", ".join(current_risk_paths))
    if risk_input:
        cfg["high_risk_paths"] = [p.strip() for p in risk_input.split(",") if p.strip()]
    print()

    # ── 确认保存 ──
    print(f"  ── 配置预览 ──")
    _show_current_config(cfg)
    print()
    confirm = input("  确认保存到 config.json? [Y/n]: ").strip().lower()
    if confirm == 'n':
        print("  已取消，配置未保存。")
        return

    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"\n  ✅ 配置已保存到: {CONFIG_FILE}")
        print(f"  使用以下命令启动监控:")
        print(f"    sudo python3 macsentinel.py")
        print()
    except Exception as e:
        print(f"\n  ❌ 保存失败: {e}")
        print(f"  请检查文件权限或路径是否可写。")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "status":
            _show_status()
        elif cmd == "setup":
            _run_setup()
        else:
            print(f"MacSentinel v{VERSION} — macOS 恶意域名监控溯源工具")
            print(f"")
            print(f"用法:")
            print(f"  sudo python3 macsentinel.py            # 启动监控")
            print(f"  sudo python3 macsentinel.py status     # 查看运行状态")
            print(f"  sudo python3 macsentinel.py setup      # 配置向导")
    else:
        main()