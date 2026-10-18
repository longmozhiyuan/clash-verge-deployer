#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
deploy_clash.py - Clash Verge Rev 订阅自动部署（本地执行，隐私脱敏）

流程：
  下载订阅（仅本地网络请求） -> 校验 YAML 结构 -> proxies 段去重 ->
  TCP 连通性抽测 -> 备份并写入 profile -> 确保本机 API 开启 ->
  重启 Clash Verge -> 经本机 API 选择低延迟节点 -> 验证代理连通。

隐私默认值：
  - 日志不显示完整订阅 URL（query/token 打码）、节点名、服务器地址；
  - 不硬编码任何 API secret，secret 仅从本机配置或环境变量读取；
  - 无遥测、无统计上报、无自动更新；
  - 修改配置前在同目录生成 .bak-<时间戳> 备份。

用法：
  python deploy_clash.py                         # 自动尝试内置公开订阅源
  python deploy_clash.py --url "<订阅URL>"        # 使用指定订阅（URL 不会被明文打印）
  python deploy_clash.py --dry-run               # 只下载、校验、抽测，不写入任何配置
  python deploy_clash.py --no-restart            # 写入后不重启，由用户手动重启
  python deploy_clash.py --verbose               # 排错模式：明文显示节点名/地址（勿外发输出）
"""

from __future__ import annotations

import os
import sys
import json
import time
import socket
import argparse
import platform
import urllib.request
import urllib.parse
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clash_common as cc
import safety_guard as sg

# 内置公开订阅源（jsDelivr CDN 镜像，规避 raw.githubusercontent.com 不可达）。
# 这些是公开仓库，与任何个人身份无关；自行 --url 指定的私人订阅不会被明文记录。
KNOWN_SUBSCRIPTIONS = [
    {
        "name": "zhuhaiuk/free-nodes",
        "url": "https://fastly.jsdelivr.net/gh/zhuhaiuk/free-nodes@main/clash_config.yaml",
    },
    {
        "name": "ermaozi/get_subscribe",
        "url": "https://fastly.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/clash.yml",
    },
    {
        "name": "zipvpn/FreeVPNNodes",
        "url": "https://fastly.jsdelivr.net/gh/zipvpn/FreeVPNNodes@main/free_clash_nodes.yaml",
    },
]

GENERIC_UA = "clash-verge-deployer/2.0 (local config tool)"


# ---------------------------------------------------------------------------
# 网络（全部为用户明确指定的目标，无第三方上报）
# ---------------------------------------------------------------------------

def download_subscription(url: str, args, timeout: int = 30) -> str:
    """经安全合规拦截层下载：URL 预检、重定向逐跳检查、大小与内容嗅探。"""
    return sg.download_safe(
        url, max_mb=args.max_download_mb, timeout=timeout,
        user_agent=GENERIC_UA,
        allow_suspicious=args.allow_suspicious,
        allow_http=args.allow_http,
        allow_local=args.allow_local_sources)


def validate_subscription(content: str):
    """返回 (is_valid, node_count, duplicates, has_proxies, has_groups, has_rules)。"""
    has_proxies = cc.locate_section(content, "proxies") is not None
    has_groups = cc.locate_section(content, "proxy-groups") is not None
    has_rules = cc.locate_section(content, "rules") is not None
    node_count, duplicates = cc.count_proxy_names(content)
    is_valid = has_proxies and node_count > 0 and not duplicates
    return is_valid, node_count, duplicates, has_proxies, has_groups, has_rules


def test_tcp_connectivity(content: str, max_nodes: int = 20, timeout: int = 3):
    """对前 N 个节点做 TCP 直连抽测；输出脱敏统计，不回显节点清单。"""
    nodes = cc.extract_proxy_nodes(content)[:max_nodes]
    alive = 0
    for _, server, port in nodes:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((server, int(port))) == 0:
                    alive += 1
        except Exception:
            pass
    return alive, len(nodes)


# ---------------------------------------------------------------------------
# Clash Verge 配置文件操作
# ---------------------------------------------------------------------------

def get_current_profile_uid(app_dir: Path):
    profiles_yaml = app_dir / "profiles.yaml"
    text = cc.read_text_safe(profiles_yaml)
    if text is None:
        return None
    m = __import__("re").search(r"(?m)^current\s*:\s*(\S+)", text)
    return m.group(1).strip().strip('"').strip("'") if m else None


def deploy_files(app_dir: Path, uid: str, content: str, new_url: str | None):
    """备份后写入 profile 与订阅 URL；返回备份清单（路径仅本机可见）。"""
    backups = []
    profiles_yaml = app_dir / "profiles.yaml"
    profile_file = app_dir / "profiles" / f"{uid}.yaml"

    if new_url:
        old = cc.read_text_safe(profiles_yaml)
        updated = cc.update_profile_url_text(old, uid, new_url) if old else None
        if updated is None:
            cc.log("警告: 未在 profiles.yaml 中定位到该 uid 条目，跳过 URL 更新")
        else:
            bak = cc.backup_file(profiles_yaml)
            if bak:
                backups.append(bak)
            profiles_yaml.write_text(updated, encoding="utf-8")
            cc.log("已更新该 profile 的订阅 URL（显示已脱敏）")

    if profile_file.is_file():
        bak = cc.backup_file(profile_file)
        if bak:
            backups.append(bak)
    profile_file.parent.mkdir(parents=True, exist_ok=True)
    profile_file.write_text(content, encoding="utf-8")
    cc.log(f"已写入 profile 缓存（{len(content)} 字节），旧文件已备份")
    return backups


def ensure_external_controller(app_dir: Path) -> bool:
    """确保 verge.yaml 启用 external-controller；返回是否发生修改。"""
    verge_yaml = app_dir / "verge.yaml"
    text = cc.read_text_safe(verge_yaml)
    if text is None:
        cc.log("警告: verge.yaml 不存在，跳过 API 开关设置")
        return False
    import re
    if re.search(r"(?m)^enable_external_controller\s*:\s*true\b", text):
        return False
    cc.backup_file(verge_yaml)
    new_text = cc.upsert_top_value(text, "enable_external_controller", "true")
    verge_yaml.write_text(new_text, encoding="utf-8")
    cc.log("已在 verge.yaml 中启用 external-controller（旧文件已备份）")
    return True


# ---------------------------------------------------------------------------
# 重启（跨平台）
# ---------------------------------------------------------------------------

def restart_clash_verge(exe: str | None, wait_seconds: int = 15):
    system = platform.system()
    cc.log("停止 Clash Verge...")
    if system == "Windows":
        subprocess.run(["taskkill", "/F", "/IM", "clash-verge.exe"],
                       capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "verge-mihomo.exe"],
                       capture_output=True)
    elif system == "Darwin":
        subprocess.run(["pkill", "-f", "Clash Verge"], capture_output=True)
    else:
        subprocess.run(["pkill", "-f", "clash-verge"], capture_output=True)
    time.sleep(3)

    cc.log("启动 Clash Verge...")
    if system == "Darwin":
        subprocess.Popen(["open", "-a", "Clash Verge"])
    elif exe:
        subprocess.Popen([exe], cwd=str(Path(exe).parent))
    else:
        cc.log("警告: 未探测到可执行文件路径，请手动启动 Clash Verge")
    time.sleep(wait_seconds)


# ---------------------------------------------------------------------------
# 本机 mihomo REST API（仅 127.0.0.1；secret 来自动态读取）
# ---------------------------------------------------------------------------

class ClashApi:
    def __init__(self, settings: dict):
        self.base = settings["api_base"]
        self.secret = settings["secret"]

    def request(self, method: str, path: str, body=None, timeout: int = 10):
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers["Authorization"] = f"Bearer {self.secret}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base + path, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw) if raw else {}

    def wait_ready(self, attempts: int = 12, interval: float = 2.0) -> bool:
        for i in range(attempts):
            try:
                self.request("GET", "/version", timeout=5)
                return True
            except Exception:
                time.sleep(interval)
        return False

    def global_nodes(self):
        result = self.request("GET", "/proxies/GLOBAL")
        return result.get("all", []), result.get("now", "")

    def switch(self, node_name: str):
        self.request("PUT", "/proxies/GLOBAL", {"name": node_name})

    def delay(self, node_name: str, timeout_ms: int = 5000):
        encoded = urllib.parse.quote(node_name, safe="")
        path = (f"/proxies/{encoded}/delay"
                f"?url=https://www.google.com/generate_204&timeout={timeout_ms}")
        return self.request("GET", path, timeout=8).get("delay", 9999)


def find_best_node(api: ClashApi, max_test: int = 10):
    """延迟测试；日志只显示脱敏序号。"""
    nodes, _ = api.global_nodes()
    proxy_nodes = [n for n in nodes if n not in ("DIRECT", "REJECT")][:max_test]
    best_name, best_delay = None, float("inf")
    for idx, node in enumerate(proxy_nodes, start=1):
        try:
            delay = api.delay(node)
            cc.log(f"  {cc.redact_node(node, idx)}: {delay}ms")
            if delay < best_delay:
                best_delay, best_name = delay, node
        except Exception:
            cc.log(f"  {cc.redact_node(node, idx)}: 超时")
    return best_name, best_delay


def test_proxy(mixed_port: int, url: str, timeout: int = 15):
    """通过本机混合端口验证连通性。"""
    handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{mixed_port}",
        "https": f"http://127.0.0.1:{mixed_port}",
    })
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(url, headers={"User-Agent": GENERIC_UA})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return resp.status
    except Exception as e:
        return f"{type(e).__name__}"


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------

def deploy(args) -> bool:
    cc._utf8_stdout()
    cc.set_verbose(args.verbose)
    if args.verbose:
        cc.log("注意: --verbose 会明文显示节点信息，输出内容请勿外发或粘贴到外部服务")

    cc.log("=== Clash Verge 自动部署开始（本地隐私模式）===")

    # 1. 解析订阅来源（--url-file / --url-stdin 可避免 URL 进入命令行参数与 shell 历史）
    subscription_url = args.url
    if not subscription_url and args.url_file:
        try:
            subscription_url = Path(args.url_file).read_text(
                encoding="utf-8").strip().splitlines()[0].strip()
        except Exception as e:
            cc.log(f"读取订阅 URL 文件失败: {type(e).__name__}")
            return False
    if not subscription_url and args.url_stdin:
        subscription_url = sys.stdin.readline().strip()

    content = None
    used_source = None
    if subscription_url:
        # 安全拦截（SafetyViolation）不属于网络故障，直接向上抛出终止
        content = download_subscription(subscription_url, args)
        used_source = subscription_url
    else:
        for sub in KNOWN_SUBSCRIPTIONS:
            try:
                cc.log(f"尝试公开订阅源: {sub['name']}")
                candidate = download_subscription(sub["url"], args)
                ok, n, dupes, *_ = validate_subscription(candidate)
                if ok:
                    cc.log(f"订阅源可用（{n} 个节点，无重名）")
                    content, used_source = candidate, sub["url"]
                    break
                cc.log(f"订阅源结构不合规（节点 {n} 个，重名 {len(dupes)} 个），尝试下一个")
            except sg.SafetyViolation:
                # 安全红线：立即停止，不尝试其他源
                raise
            except Exception as e:
                cc.log(f"订阅源下载失败: {type(e).__name__}，尝试下一个")
        if content is None:
            cc.log("所有内置公开源均不可用，可用 --url-file 指定自己的订阅")
            return False

    # 2. 校验
    ok, node_count, dupes, has_proxies, has_groups, has_rules = validate_subscription(content)
    cc.log(f"结构校验: 节点 {node_count} 个，重名 {len(dupes)} 个；"
           f"proxies={has_proxies}, proxy-groups={has_groups}, rules={has_rules}")

    # 2.5 防篡改哈希校验（--pin-hash 严格校验；否则与上次记录对比）
    sha = sg.compute_sha256(content)
    hash_key = cc.redact_url(used_source or subscription_url or "auto-source")
    if args.pin_hash:
        status, detail = sg.check_hash(hash_key, sha, args.pin_hash)
        if status == "pinned_mismatch":
            cc.log(f"⛔ 防篡改校验失败: 下载内容 SHA-256 与 --pin-hash 不匹配")
            cc.log("订阅可能被中间人篡改或 pin 值有误，已拒绝写入")
            return False
        cc.log(f"防篡改校验通过（pin 匹配 {sha[:12]}…）")
        sg.record_hash(hash_key, sha)
    else:
        status, detail = sg.check_hash(hash_key, sha, None)
        if status == "new":
            sg.record_hash(hash_key, sha)
            cc.log(f"首次记录订阅指纹: SHA-256 {sha[:16]}…（已存档）")
        elif status == "ok":
            cc.log(f"订阅指纹与上次一致: SHA-256 {sha[:16]}…")
        else:  # changed
            cc.log(f"⚠ 订阅内容与上次记录不同（SHA-256 {sha[:16]}…，"
                   f"上次 {detail[:16]}…）")
            cc.log("  可能是订阅方正常更新；若未预期，请检查订阅是否被篡改")
            sg.record_hash(hash_key, sha)

    # 3. 去重（只动 proxies 段，其余配置原样保留）
    if dupes:
        content, removed = cc.dedupe_proxy_text(content)
        ok, node_count, dupes, *_ = validate_subscription(content)
        cc.log(f"已去重 {removed} 个重名节点，剩余 {node_count} 个；其余配置段保持不变")
    if not ok:
        cc.log("订阅格式无效（缺少 proxies 或节点为空），终止部署")
        return False

    # 3.5 安全合规扫描：全部节点名/服务器（命中类别即永久拉黑并终止）
    try:
        scanned = sg.scan_nodes(content)
        cc.log(f"合规扫描: {scanned} 个节点全部通过（黑名单/违法类别/内网地址）")
    except sg.SafetyViolation as e:
        cc.log(f"⛔ 安全拦截[{e.category}] {e.reason}")
        cc.log("该订阅已拒绝部署，目标已写入永久黑名单，后续运行不再访问")
        return False

    # 3.6 路由劫持审计：政务/银行/支付域名不得被导向代理节点
    critical, warnings = sg.audit_routing(content)
    for w in warnings:
        cc.log(f"路由审计提示: {w}")
    if critical:
        for c in critical:
            cc.log(f"⛔ 路由劫持风险: {c}")
        if args.ignore_routing_audit:
            cc.log("已按 --ignore-routing-audit 忽略路由审计（用户显式授权）")
        else:
            cc.log("恶意订阅可能劫持敏感流量（网银/支付/政务），已拒绝部署；"
                   "如确认是误报，可加 --ignore-routing-audit 跳过")
            return False

    # 4. TCP 抽测
    alive, total = test_tcp_connectivity(content, max_nodes=args.max_tcp)
    cc.log(f"TCP 抽测: {alive}/{total} 个节点可达（地址已脱敏）")
    if alive == 0:
        cc.log("警告: 抽测节点均不可达，部署后代理可能无法使用")

    # 5. 定位本机配置
    app_dir = cc.find_app_dir()
    if not app_dir.is_dir():
        cc.log(f"未找到 Clash Verge 配置目录（期望位置: {app_dir}）")
        cc.log("请确认 Clash Verge Rev 已安装并至少运行过一次，或设置 CLASH_VERGE_DIR")
        return False
    settings = cc.controller_settings(app_dir)
    cc.log(f"配置目录: {app_dir}")
    cc.log(f"本机 API: {settings['api_base']} | "
          f"secret: {'已从本机配置读取' if settings['secret'] else '未设置（无认证）'} | "
          f"混合端口: {settings['mixed_port']}")

    if args.dry_run:
        cc.log("--dry-run: 不修改任何配置文件，流程结束")
        return True

    uid = get_current_profile_uid(app_dir)
    if not uid:
        cc.log("无法从 profiles.yaml 获取当前 profile UID，请先在 Clash Verge 中新建一个订阅")
        return False
    cc.log(f"当前 profile: {cc.redact_uid(uid)}")

    # 6. 备份并写入
    url_for_profile = subscription_url if args.update_url else None
    backups = deploy_files(app_dir, uid, content, url_for_profile)
    ensure_external_controller(app_dir)

    # 7. 重启
    if not args.no_restart:
        exe = cc.find_clash_verge_exe()
        if not exe and platform.system() == "Windows":
            cc.log("未探测到 clash-verge.exe，可设置环境变量 CLASH_VERGE_EXE 指定路径")
        restart_clash_verge(exe)
    else:
        cc.log("已跳过重启，请在 Clash Verge 中手动重载配置或重启应用")

    # 8. 等待 API 就绪并验证加载
    api = ClashApi(settings)
    if not api.wait_ready():
        cc.log("本机 API 未就绪；如刚修改过 API 端口/认证，请重启后重试")
        return False
    try:
        nodes, current = api.global_nodes()
        cc.log(f"内核已加载: GLOBAL 组 {len(nodes)} 个条目")
    except Exception as e:
        cc.log(f"API 查询失败: {type(e).__name__}（401 通常表示 secret 不匹配，"
               f"可设置 CLASH_VERGE_SECRET）")
        return False

    # 9. 切换低延迟节点
    if not args.no_switch:
        cc.log("开始延迟测试，选择最快节点...")
        best, best_delay = find_best_node(api, max_test=args.max_test)
        if best:
            api.switch(best)
            time.sleep(2)
            cc.log(f"已切换到最快节点（{best_delay}ms，名称已脱敏）")
        else:
            cc.log("未测得可用节点，保持当前选择")

    # 10. 验证代理
    if not args.no_verify:
        cc.log("验证代理连通性（Google generate_204）...")
        status = test_proxy(settings["mixed_port"],
                            "https://www.google.com/generate_204")
        cc.log("Google 连通: 成功(204)" if status == 204
               else f"Google 连通: 失败({status})")
        if args.with_youtube:
            yt = test_proxy(settings["mixed_port"], "https://www.youtube.com")
            cc.log("YouTube 连通: 成功(200)" if yt == 200
                   else f"YouTube 连通: 失败({yt})")

    if backups:
        cc.log("配置备份（含完整订阅，请勿外发）:")
        for b in backups:
            cc.log(f"  - {b}")
    cc.log("=== 部署完成 === 提示: 日志已脱敏；如需排错明文输出可加 --verbose")
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Clash Verge Rev 订阅自动部署（本地隐私模式）")
    parser.add_argument("--url", help="订阅 URL（私人链接含 token，日志中会自动脱敏；"
                                       "但会出现在命令行参数/Shell 历史中，更安全请用 --url-file）")
    parser.add_argument("--url-file", help="从本地文件读取订阅 URL（首行），"
                                            "避免 URL 进入命令行参数与 Shell 历史")
    parser.add_argument("--url-stdin", action="store_true",
                        help="从标准输入读取订阅 URL（首行）")
    parser.add_argument("--no-switch", action="store_true", help="不自动切换节点")
    parser.add_argument("--no-restart", action="store_true", help="写入后不重启 Clash Verge")
    parser.add_argument("--no-verify", action="store_true", help="跳过最终代理连通验证")
    parser.add_argument("--update-url", action="store_true",
                        help="同时把 profiles.yaml 中的订阅 URL 改为 --url 给定值")
    parser.add_argument("--with-youtube", action="store_true",
                        help="额外验证 YouTube（默认仅验证 generate_204）")
    parser.add_argument("--dry-run", action="store_true",
                        help="只下载/校验/抽测，不写入、不重启")
    parser.add_argument("--verbose", action="store_true",
                        help="明文显示节点名与地址（仅限本机排错，输出勿外发）")
    parser.add_argument("--max-tcp", type=int, default=20, help="TCP 抽测节点数")
    parser.add_argument("--max-test", type=int, default=10, help="延迟测试节点数")
    # 安全合规拦截层参数（核心拦截不可整体关闭，仅可按项显式放行）
    parser.add_argument("--allow-suspicious", action="store_true",
                        help="放行 punycode/凭证型 URL 等可疑特征（违法类别与黑名单仍拦截）")
    parser.add_argument("--allow-http", action="store_true",
                        help="允许明文 HTTP 订阅（不推荐，存在篡改风险）")
    parser.add_argument("--ignore-routing-audit", action="store_true",
                        help="忽略路由劫持审计的高风险结果（仅在确认误报时使用）")
    parser.add_argument("--max-download-mb", type=int,
                        default=sg.DEFAULT_MAX_DOWNLOAD_MB,
                        help="订阅下载体积上限（MB，默认 10）")
    parser.add_argument("--allow-local-sources", action="store_true",
                        help="放行本机(127.0.0.1)与 RFC1918 私网地址的订阅源"
                             "（自建内网订阅服务场景；元数据地址仍拦截）")
    parser.add_argument("--pin-hash", metavar="SHA256",
                        help="订阅内容 SHA-256 固定值，严格校验：不匹配即拒绝写入")
    parser.add_argument("--hash-status", action="store_true",
                        help="查看订阅指纹记录后退出")
    parser.add_argument("--list-blocked", action="store_true",
                        help="查看本机永久黑名单与拦截事件后退出")
    args = parser.parse_args()

    if args.list_blocked:
        cc._utf8_stdout()
        auto, url_rules, custom, n_events = sg.list_blocked()
        print(f"域名黑名单: {len(auto)} 条 | 链接黑名单: {len(url_rules)} 条 | "
              f"自定义: {len(custom)} 条 | 拦截事件: {n_events} 条")
        for item in auto:
            print(f"  [domain]      {item}")
        for h, p in url_rules:
            print(f"  [url]         {h}{p}")
        for item in custom:
            print(f"  [custom]      {item}")
        print(f"\n状态目录: {sg.state_dir()}")
        print("解除拉黑需手动编辑 blocklist.txt / blocked-urls.txt；"
              "custom-blocklist.txt 为你自定义的域名名单")
        sys.exit(0)

    if args.hash_status:
        cc._utf8_stdout()
        data = sg.load_hashes()
        if not data:
            print("尚无订阅指纹记录（首次部署时自动记录）")
        else:
            print(f"订阅指纹记录（{len(data)} 条，URL 已脱敏）:")
            for key, info in data.items():
                print(f"  {key}")
                print(f"    sha256: {info.get('sha256', '')[:24]}…"
                      f"  first: {info.get('first_seen', '')[:19]}"
                      f"  last: {info.get('last_seen', '')[:19]}")
        sys.exit(0)

    ok = False
    try:
        ok = deploy(args)
    except KeyboardInterrupt:
        cc.log("用户中断")
    except sg.SafetyViolation as e:
        cc._utf8_stdout()
        cc.log(f"⛔ 安全拦截 [{e.category}]：{e.reason}")
        cc.log("已立即停止访问（永久黑名单已记录）；部署终止")
        sys.exit(3)
    except Exception as e:
        cc.log(f"部署异常: {type(e).__name__}: {e}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
