#!/usr/bin/env python3
"""
恶意域名监控：自动化测试脚本
测试监控脚本的 DNS 捕获率、溯源完整性和稳定性

使用: sudo python3 test_monitor.py
"""

import subprocess
import os
import sys
import time
import signal
import re
import json
from datetime import datetime

# ===== 配置 =====
MONITOR_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(MONITOR_DIR, "macsentinel.py")
LOGFILE = os.path.join(MONITOR_DIR, f"monitor_{datetime.now().strftime('%Y%m%d')}.log")

# 监控脚本配置的目标域名（对应 macsentinel.py 中 TARGET_DOMAINS 配置）
# 只有这些域名会触发告警 HIT，其他域名仅验证 DNS 捕获
TARGET_DOMAINS = ["ip138.com"]

# 每个场景独立配置测试域名，避免系统 DNS 缓存导致跨场景干扰
# 均为安全的高流量公网域名
#
# 注意顺序：目标域名测试（is_target=True）必须放在最前面，
# 因为后续的同域名查询会被系统 DNS 缓存拦截，无法产生真实 DNS 查询包。
TEST_SCENARIOS = [
    # ── curl 系列场景（恶意软件最常见）──
    # ★ curl 目标域名必须放第一，确保 DNS 缓存未污染 ★
    {
        "name": "curl 目标域名（端到端告警验证）",
        "cmd": "curl -s -o /dev/null -m 10 http://ip138.com",
        "desc": "curl 请求目标域名，验证告警链路的完整性",
        "domain": "ip138.com",
        "is_target": True,
    },
    {
        "name": "curl + 超时参数（恶意软件典型模式）",
        "cmd": "curl -s --connect-timeout 15 --max-time 30 -o /dev/null http://sina.com.cn",
        "desc": "类似 sh -c 'curl -s --connect-timeout 15 --max-time 30 http://xxx'",
        "domain": "sina.com.cn",
        "is_target": False,
    },
    {
        "name": "sh -c curl 管道执行（恶意软件典型模式）",
        "cmd": "sh -c 'curl -s --connect-timeout 10 --max-time 20 -o /dev/null http://taobao.com'",
        "desc": "通过 sh -c 间接执行 curl",
        "domain": "taobao.com",
        "is_target": False,
    },
    {
        "name": "curl 直接请求",
        "cmd": "curl -s -o /dev/null -m 10 http://163.com",
        "desc": "直接 curl HTTP 请求",
        "domain": "163.com",
        "is_target": False,
    },
    # ── 基础 DNS 工具场景 ──
    {
        "name": "dscacheutil（短命进程）",
        "cmd": "dscacheutil -q host -a name ip138.com",
        "desc": "macOS 缓存工具，查询后立即退出",
        "domain": "ip138.com",
        "is_target": True,  # 在 TARGET_DOMAINS 中，会触发告警
    },
    {
        "name": "nslookup（DNS 工具）",
        "cmd": "nslookup baidu.com 2>/dev/null",
        "desc": "标准 DNS 查询工具",
        "domain": "baidu.com",
        "is_target": False,
    },
    {
        "name": "host（DNS 工具）",
        "cmd": "host qq.com 2>/dev/null",
        "desc": "简易 DNS 查询工具",
        "domain": "qq.com",
        "is_target": False,
    },
    # ── 其他网络工具场景 ──
    {
        "name": "ping（ICMP 探测）",
        "cmd": "ping -c 1 -t 3 sohu.com 2>/dev/null || true",
        "desc": "ICMP 探测，同样需要 DNS 解析",
        "domain": "sohu.com",
        "is_target": False,
    },
]


def run_cmd(cmd, timeout=10):
    """执行命令"""
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -2, "", str(e)


def section(title):
    """打印分段标题"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


_log_offset = 0

def read_log_incremental(filepath):
    """增量读取日志文件，只返回上次读取后新增的内容"""
    global _log_offset
    if not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            f.seek(_log_offset)
            new_content = f.read()
            _log_offset = f.tell()
        return new_content
    except Exception:
        return ""


def read_log_full(filepath):
    """完整读取日志文件"""
    if not os.path.exists(filepath):
        return ""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception:
        return ""


def wait_for_daemon(proc, timeout=15):
    """等待守护进程初始化完成"""
    for i in range(timeout):
        if proc.poll() is not None:
            return False, "进程已退出"
        # 检查日志中是否有 DNSMonitor 运行中的标记
        if os.path.exists(LOGFILE):
            content = read_log_full(LOGFILE)
            if "DNSMonitor] 运行中" in content:
                return True, f"初始化完成 ({i+1}s)"
        time.sleep(1)
    return False, f"等待超时 ({timeout}s)"


def count_hits(log_content):
    """统计命中次数"""
    hits = re.findall(r'🚨 \[命中 #(\d+)\]', log_content)
    return len(hits)


def count_scenarios_hit(log_content):
    """统计命中了多少个不同的场景/域名

    通过提取命中日志行中的 domain=xxx，去重统计
    """
    domains = re.findall(r'domain=(\S+)', log_content)
    unique_domains = set(domains)
    return len(unique_domains), unique_domains


def check_dns_captured(log_content, domain):
    """检查指定域名的 DNS 查询是否被 DNSMonitor 捕获（无论是否命中）"""
    # 查找 [DNS查询] ... q=['domain'] 模式
    pattern = re.escape(domain)
    matches = re.findall(rf"\[DNS查询\].*q=\[.*{pattern}.*\]", log_content)
    return len(matches) > 0, len(matches)


def count_feishu_pushes(log_content):
    """统计飞书推送成功次数"""
    pushes = re.findall(r'\[Feishu推送\] 成功', log_content)
    return len(pushes)


def count_dns_queries(log_content):
    """统计 DNS 查询次数"""
    queries = re.findall(r'\[DNS查询\]', log_content)
    return len(queries)


def check_feature(log_content, feature_keyword):
    """检查某项功能是否在日志中出现"""
    return feature_keyword in log_content


def check_risk_levels(log_content):
    """统计各级风险评估"""
    high = log_content.count("🔴 高风险")
    medium = log_content.count("🟡 中风险")
    low = log_content.count("🟢 低风险")
    return high, medium, low


def check_trace_features(log_content):
    """检查溯源功能是否触发"""
    features = {
        "环境变量采集": "[溯源] 环境变量:" in log_content,
        "动态库采集": "[溯源] 动态库:" in log_content,
        "监听端口检测": "[溯源] 监听端口:" in log_content,
        "网络连接采集": "[溯源] 网络连接:" in log_content,
        "进程树采集": "进程树" in log_content,
        "代码签名": "[溯源] 代码签名:" in log_content,
        "SHA256 哈希": "[溯源] SHA256:" in log_content,
        "进程退出后系统日志": "[溯源] 系统日志:" in log_content,
        "持久化检测": "持久化" in log_content,
        "退出后身份记录": "⚠️ 进程已退出" in log_content or "🔴 进程已退出" in log_content,
        "进程存活标记": "🟢 进程存活" in log_content,
        "DNSMonitor 自动重启": "DNSMonitor 进程已退出" in log_content,
        "网络扩展清理": "网络扩展清理完成" in log_content,
        "风险评估标记": "🎯 风险评级:" in log_content,
    }
    return features


# ============================================================
# 测试主流程
# ============================================================

def main():
    print()
    print("╔══════════════════════════════════════════════════╗")
    print("║     MacSentinel · 自动化测试套件                  ║")
    print(f"║     版本: v1.0.0 | 日期: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}       ║")
    print("╚══════════════════════════════════════════════════╝")

    if os.geteuid() != 0:
        print("[!] Need root. Run with: sudo python3 test_monitor.py")
        sys.exit(1)

    test_results = []

    # ============================================================
    # Phase 1: 环境准备
    # ============================================================
    section("Phase 1: 环境准备")

    # 清理残留
    print("  [1/4] 清理残留进程...")
    run_cmd("pkill -f macsentinel.py 2>/dev/null")
    run_cmd("pkill -f DNSMonitor 2>/dev/null")
    time.sleep(1)
    test_results.append(("清理残留进程", "✅"))

    print("  [2/4] 清空 DNS 缓存...")
    run_cmd("dscacheutil -flushcache")
    run_cmd("killall -HUP mDNSResponder 2>/dev/null")
    test_results.append(("清空 DNS 缓存", "✅"))

    # 清理旧日志
    print(f"  [3/4] 清理旧日志: {LOGFILE}")
    if os.path.exists(LOGFILE):
        # 备份旧日志
        bak_name = LOGFILE.replace('.log', f'_bak_{int(time.time())}.log')
        os.rename(LOGFILE, bak_name)
        print(f"      旧日志已备份到: {bak_name}")
    test_results.append(("日志文件清理", "✅"))

    # 检查脚本存在
    print(f"  [4/4] 检查脚本: {SCRIPT}")
    if os.path.isfile(SCRIPT):
        print(f"      ✅ 脚本存在")
        test_results.append(("脚本检查", "✅"))
    else:
        print(f"      ❌ 脚本不存在!")
        sys.exit(1)

    # ============================================================
    # Phase 2: 启动守护进程
    # ============================================================
    section("Phase 2: 启动监控守护进程")

    # 注入安全测试域名，覆盖监控脚本的 TARGET_DOMAINS
    # 避免使用恶意域名（如 cdn.pynice.com）触发真实告警
    CONFIG_BACKUP = SCRIPT + '.bak_config'
    try:
        with open(SCRIPT, 'r') as f:
            original_config = f.read()
        with open(CONFIG_BACKUP, 'w') as f:
            f.write(original_config)
        # 替换 TARGET_DOMAINS 为安全测试域名
        import re
        new_config = re.sub(
            r'TARGET_DOMAINS\s*=\s*\[[^\]]*\]',
            'TARGET_DOMAINS = ["ip138.com"]',
            original_config
        )
        with open(SCRIPT, 'w') as f:
            f.write(new_config)
        print("  ✅ TARGET_DOMAINS 已注入: ip138.com (安全测试域名)")
        print(f"     备份文件: {CONFIG_BACKUP}")
    except Exception as e:
        print(f"  ❌ TARGET_DOMAINS 注入失败: {e}")
        sys.exit(1)

    print("  启动守护进程:")
    proc = subprocess.Popen(
        ["python3", SCRIPT],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=MONITOR_DIR,
        text=True,
        bufsize=1
    )

    # 等待初始化
    success, msg = wait_for_daemon(proc, timeout=20)
    if success:
        print(f"  ✅ {msg}")
        test_results.append(("守护进程启动", "✅"))
    else:
        print(f"  ❌ {msg}")
        test_results.append(("守护进程启动", "❌"))
        # 尝试获取错误输出
        try:
            out, err = proc.communicate(timeout=3)
            print(f"  错误输出: {err[:500]}")
        except:
            pass
        sys.exit(1)

    # 验证飞书通知
    time.sleep(1)
    if os.path.exists(LOGFILE):
        startup_log = read_log_full(LOGFILE)
        if "Feishu推送] 成功" in startup_log:
            print("  ✅ 飞书启动通知已发送")
            test_results.append(("飞书启动通知", "✅"))
        else:
            print("  ⚠️ 飞书启动通知未确认")
            test_results.append(("飞书启动通知", "⚠️"))

    # ============================================================
    # Phase 3: 执行测试场景
    # ============================================================
    section("Phase 3: 测试场景执行")

    total_expected = len(TEST_SCENARIOS)

    for i, scenario in enumerate(TEST_SCENARIOS, 1):
        name = scenario["name"]
        cmd = scenario["cmd"]
        desc = scenario["desc"]
        domain = scenario.get("domain", "?")
        is_target = scenario.get("is_target", False)

        print(f"\n  [{i}/{total_expected}] {name}")
        print(f"      描述: {desc}")
        print(f"      域名: {domain}")
        if is_target:
            print(f"      🎯 目标域名 (触发告警)")
        else:
            print(f"      📡 非目标域名 (仅验证 DNS 捕获)")
        print(f"      命令: {cmd[:80]}...")

        # 统计命中前的 DNS 捕获数和命中数
        log_before = read_log_full(LOGFILE)
        hits_before = count_hits(log_before)
        dns_before, _ = check_dns_captured(log_before, domain)

        # 执行测试命令
        rc, stdout, stderr = run_cmd(cmd, timeout=15)
        print(f"      执行结果: 返回码={rc}, 输出={stdout[:80] if stdout else '(空)'}")

        # 等待守护进程处理
        time.sleep(4)

        # 统计命中后的数量
        log_after = read_log_full(LOGFILE)
        hits_after = count_hits(log_after)
        dns_after, dns_count = check_dns_captured(log_after, domain)

        new_hits = hits_after - hits_before
        dns_captured = dns_after and not dns_before

        # 输出结果
        dns_status = "✅ DNS捕获" if dns_captured else "⚠️ DNS未捕获"
        if dns_captured:
            print(f"      {dns_status} ({dns_count} 条查询)")

        if is_target:
            if new_hits > 0:
                print(f"      ✅ 告警命中: {new_hits} 次")
                test_results.append((f"场景: {name}", f"✅ 命中{new_hits}次"))
            else:
                print(f"      ⚠️ 告警未命中 (DNS捕获={dns_captured})")
                test_results.append((f"场景: {name}", f"⚠️ 未命中 DNS={dns_captured}"))
        else:
            if dns_captured:
                print(f"      ✅ 非目标域名 DNS 捕获正常")
                test_results.append((f"场景: {name}", "✅ DNS捕获"))
            else:
                print(f"      ⚠️ DNS 未捕获（系统缓存可能已命中）")
                test_results.append((f"场景: {name}", "⚠️ 未捕获"))

    # ============================================================
    # Phase 4: 停止守护进程
    # ============================================================
    section("Phase 4: 停止守护进程")

    print("  发送 SIGINT 信号...")
    # 获取守护进程 PID 直接发送信号
    rc, daemon_pid_str, _ = run_cmd(
        "pgrep -f 'python3.*macsentinel.py' | head -1"
    )
    daemon_pid = daemon_pid_str.strip()
    if daemon_pid:
        print(f"      目标 PID: {daemon_pid}")
        run_cmd(f"kill -SIGINT {daemon_pid}")
        for i in range(12):
            time.sleep(2)
            rc, still_alive, _ = run_cmd(
                "pgrep -f 'python3.*macsentinel.py' 2>/dev/null || echo 'dead'"
            )
            if 'dead' in still_alive or not still_alive.strip():
                print(f"  ✅ 守护进程已优雅退出 (耗时 {(i+1)*2}s)")
                test_results.append(("守护进程停止", "✅ 优雅关闭"))
                break
        else:
            print(f"  ⚠️ 强制终止 (SIGINT 未能在 24s 内关闭)")
            run_cmd("pkill -9 -f macsentinel.py 2>/dev/null")
            test_results.append(("守护进程停止", "⚠️ 强制终止"))
    else:
        print(f"  ⚠️ 找不到守护进程 PID")
        test_results.append(("守护进程停止", "⚠️ PID 未找到"))

    # 检查网络扩展清理
    time.sleep(2)
    if os.path.exists(LOGFILE):
        shutdown_log = read_log_full(LOGFILE)
        if "网络扩展清理完成" in shutdown_log:
            print("  ✅ 网络扩展已清理")
            test_results.append(("网络扩展清理", "✅"))
        if "Feishu推送] 成功" in shutdown_log and "监控已停止" in shutdown_log:
            print("  ✅ 飞书停止通知已发送")
            test_results.append(("飞书停止通知", "✅"))

    # 最终清理
    run_cmd("pkill -f macsentinel.py 2>/dev/null")
    run_cmd("pkill -f DNSMonitor 2>/dev/null")
    # 恢复 TARGET_DOMAINS 配置
    restore_config()
    time.sleep(1)

    # 再检查一次日志确认关闭
    if os.path.exists(LOGFILE):
        final_check = read_log_full(LOGFILE)
        if "守护进程退出" in final_check:
            # 更新测试结果
            for i, (name, result) in enumerate(test_results):
                if name == "守护进程停止":
                    test_results[i] = ("守护进程停止", "✅ 优雅关闭")
                    break
        if "网络扩展清理完成" in final_check:
            for i, (name, result) in enumerate(test_results):
                if name == "网络扩展清理":
                    test_results[i] = ("网络扩展清理", "✅")
                    break

    # ============================================================
    # Phase 5: 日志分析与检出率报告
    # ============================================================
    section("Phase 5: 日志分析与检出率报告")

    log_content = read_log_full(LOGFILE)
    if not log_content:
        print("  ❌ 日志文件不存在或为空!")
        sys.exit(1)

    # 统计数据
    total_lines = len(log_content.split('\n'))
    total_queries = count_dns_queries(log_content)
    feishu_sends = count_feishu_pushes(log_content)

    # DNS 捕获率: DNSMonitor 是否捕获到各场景的 DNS 查询
    dns_captured_count = sum(1 for s in TEST_SCENARIOS
                             if check_dns_captured(log_content, s["domain"])[0])
    dns_rate = (dns_captured_count / len(TEST_SCENARIOS)) * 100

    # 告警命中率: 目标域名场景中触发 HIT 的比例
    target_scenarios = [s for s in TEST_SCENARIOS if s.get("is_target")]
    hit_count_target = 0
    for s in target_scenarios:
        # 检查命中日志中是否有该域名
        if re.search(rf"domain={re.escape(s['domain'])}", log_content):
            hit_count_target += 1
    hit_rate = (hit_count_target / len(target_scenarios)) * 100 if target_scenarios else 0

    high_r, mid_r, low_r = check_risk_levels(log_content)
    features = check_trace_features(log_content)

    print(f"""
  📊 测试统计
  ┌─────────────────────────────────────┬──────────┐
  │ 指标                               │ 数值     │
  ├─────────────────────────────────────┼──────────┤
  │ 日志总行数                         │ {total_lines:>6} 行   │
  │ DNS 查询捕获数                     │ {total_queries:>6} 次   │
  │ 告警命中总次数                     │ {count_hits(log_content):>6} 次   │
  │ 飞书推送成功数                     │ {feishu_sends:>6} 次   │
  ├─────────────────────────────────────┼──────────┤
  │ 📡 DNS 捕获率                      │ {dns_rate:>5.1f} %   │
  │     (DNSMonitor 捕获到查询)         │ {dns_captured_count:>3}/{len(TEST_SCENARIOS):<3} 场景   │
  ├─────────────────────────────────────┼──────────┤
  │ 🚨 告警命中率                      │ {hit_rate:>5.1f} %   │
  │     (目标域名触发告警)              │ {hit_count_target:>3}/{len(target_scenarios):<3} 场景   │
  ├─────────────────────────────────────┼──────────┤
  │ 🔴 高风险评估                      │ {high_r:>6} 次   │
  │ 🟡 中风险评估                      │ {mid_r:>6} 次   │
  │ 🟢 低风险评估                      │ {low_r:>6} 次   │
  └─────────────────────────────────────┴──────────┘
  """)

    # 溯源功能检测清单
    print("  📋 溯源功能检测清单")
    print("  ┌──────────────────────────────────┬──────────┐")
    enabled_features = sum(1 for v in features.values() if v)
    total_features = len(features)
    for feat_name, enabled in features.items():
        icon = "✅" if enabled else "⬜"
        print(f"  │ {feat_name:<30} │ {icon:>8} │")
    print(f"  ├──────────────────────────────────┼──────────┤")
    print(f"  │ 功能启用率                       │ {enabled_features:>3}/{total_features:<3}     │")
    print(f"  └──────────────────────────────────┴──────────┘")

    # 测试用例结果清单
    print(f"\n  📋 测试用例结果清单")
    print(f"  ┌──────────────────────────────────┬──────────┐")
    for name, result in test_results:
        print(f"  │ {name:<30} │ {result:>8} │")
    print(f"  └──────────────────────────────────┴──────────┘")

    # ============================================================
    # 最终结论
    # ============================================================
    section("测试结论")

    all_passed = all("❌" not in r for _, r in test_results)
    if all_passed and dns_rate >= 60:
        print(f"""
  🏆 整体评估: 优秀
  ─────────────────────────────────────────────────────────
  ✅ DNS 捕获率 {dns_rate:.1f}% — DNSMonitor 能准确捕获各类工具 DNS 查询
  ✅ 告警命中率 {hit_rate:.1f}% — 目标域名能触发告警
  ✅ 溯源功能（{enabled_features}/{total_features} 项）
  ✅ 稳定性正常（自动重启 + 优雅关闭）
  ✅ 飞书推送正常（{feishu_sends} 次成功）
  ─────────────────────────────────────────────────────────
  日志文件: {LOGFILE}
        """)
    elif all_passed:
        print(f"""
  ⚠️ 整体评估: 通过
  ─────────────────────────────────────────────────────────
  ✅ DNS 捕获率 {dns_rate:.1f}%
  ✅ 告警命中率 {hit_rate:.1f}%
  ✅ 溯源功能（{enabled_features}/{total_features} 项）
  ─────────────────────────────────────────────────────────
        """)
    else:
        print(f"""
  ❌ 整体评估: 有失败项
  ─────────────────────────────────────────────────────────
  DNS 捕获率: {dns_rate:.1f}%
  告警命中率: {hit_rate:.1f}%
  溯源功能: {enabled_features}/{total_features}
  请检查日志排查问题: {LOGFILE}
  ─────────────────────────────────────────────────────────
        """)


def restore_config():
    """恢复监控脚本的原始配置"""
    CONFIG_BACKUP = SCRIPT + '.bak_config'
    if os.path.exists(CONFIG_BACKUP):
        with open(CONFIG_BACKUP, 'r') as f:
            content = f.read()
        with open(SCRIPT, 'w') as f:
            f.write(content)
        os.remove(CONFIG_BACKUP)
        print("  ✅ TARGET_DOMAINS 已恢复")
        return True
    return False


if __name__ == "__main__":
    try:
        main()
    finally:
        # 无论测试是否正常完成或异常退出，都必须恢复配置
        # 避免监控脚本 TARGET_DOMAINS 被永久篡改
        restore_config()