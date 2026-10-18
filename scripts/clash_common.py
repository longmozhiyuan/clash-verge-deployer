#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
clash_common.py - Clash Verge 部署脚本共享工具（本地运行，无任何遥测）

职责：
  1. 跨平台探测 Clash Verge Rev 的配置目录与可执行文件；
  2. 隐私脱敏：订阅 URL（可能含 token）、节点名、服务器地址、profile UID；
  3. 从本机配置中动态读取 external-controller 地址 / secret / 混合端口（绝不硬编码）；
  4. 修改配置前自动备份；
  5. 纯文本行级解析 YAML 的 proxies 段，不重排、不丢弃其余配置。

隐私约定：
  - 本模块只连接 127.0.0.1 本机 API 与调用者明确指定的地址；
  - 默认 verbose=False，日志中不出现完整订阅链接、节点名、服务器地址；
  - 不写任何统计/上报/自动更新请求。
"""

from __future__ import annotations

import os
import re
import sys
import time
import shutil
import socket
import hashlib
import platform
import subprocess
from pathlib import Path

# ---------------------------------------------------------------------------
# 输出与脱敏
# ---------------------------------------------------------------------------

VERBOSE = False


def set_verbose(flag: bool) -> None:
    """开启后日志才显示明文节点名 / 服务器地址（本机排错用，默认关闭）。"""
    global VERBOSE
    VERBOSE = bool(flag)


def _utf8_stdout() -> None:
    """Windows 控制台默认 GBK，强制 UTF-8 输出，避免中文崩溃。"""
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# 疑似 token 的路径段：>=16 位的 hex / base64url 连续字符
_TOKENISH = re.compile(r"[A-Za-z0-9_\-]{16,}")


def redact_url(url: str) -> str:
    """
    脱敏订阅 URL：
      https://host/sub?token=SECRET      -> https://host/sub?***
      https://host/api/ab12...ef89/clash -> https://host/api/***/clash
    保留 scheme 与 host，便于判断来源；隐藏 query 与疑似 token 的路径段。
    """
    if not url:
        return "<empty>"
    s = url.strip()
    # 分离 query / fragment
    for sep in ("?", "#"):
        if sep in s:
            s = s.split(sep, 1)[0] + (sep + "***" if sep == "?" else "")
            break
    # 路径段打码
    parts = s.split("/")
    redacted = []
    for i, seg in enumerate(parts):
        if i >= 3 and _TOKENISH.fullmatch(seg):
            redacted.append("***")
        else:
            redacted.append(seg)
    return "/".join(redacted)


def redact_node(name: str, index: int) -> str:
    """节点名默认显示为 序号 + 短哈希；--verbose 时才显示明文。"""
    if VERBOSE:
        return name
    if name is None:
        return f"节点#{index:02d}"
    h = hashlib.sha1(name.encode("utf-8", errors="replace")).hexdigest()[:6]
    return f"节点#{index:02d}({h})"


def redact_endpoint(server: str, port) -> str:
    """服务器地址默认显示为 主机名后缀 + 端口的掩码形式。"""
    if VERBOSE:
        return f"{server}:{port}"
    if not server:
        return f"<未知主机>:{port}"
    # 域名保留最后两段（如 example.com），IP 保留 /24 前两段
    try:
        socket.inet_aton(server)
        octets = server.split(".")
        return f"{octets[0]}.{octets[1]}.x.x:{port}"
    except OSError:
        labels = server.rsplit(".", 2)
        tail = ".".join(labels[-2:]) if len(labels) >= 2 else server
        return f"*.{tail}:{port}"


def redact_uid(uid: str) -> str:
    """profile UID 是本地随机标识，仅显示前 6 位。"""
    if not uid:
        return "<none>"
    return uid[:6] + "***" if len(uid) > 6 else "***"


# ---------------------------------------------------------------------------
# 跨平台路径探测
# ---------------------------------------------------------------------------

def _home() -> Path:
    return Path.home()


def config_dir_candidates():
    """返回 Clash Verge Rev 配置目录候选列表（按优先级）。"""
    env = os.environ.get("CLASH_VERGE_DIR")
    candidates = []
    if env:
        candidates.append(Path(env))
    system = platform.system()
    appname = "io.github.clash-verge-rev.clash-verge-rev"
    if system == "Windows":
        appdata = os.environ.get("APPDATA", str(_home() / "AppData" / "Roaming"))
        candidates.append(Path(appdata) / appname)
    elif system == "Darwin":
        candidates.append(_home() / "Library" / "Application Support" / appname)
        candidates.append(_home() / ".config" / "clash-verge")
    else:
        candidates.append(_home() / ".config" / "clash-verge")
        candidates.append(_home() / ".config" / appname)
    return candidates


def find_app_dir() -> Path:
    """返回实际存在的配置目录；都不存在时返回首个候选（供报错提示）。"""
    candidates = config_dir_candidates()
    for c in candidates:
        if c.is_dir():
            return c
    return candidates[0]


def _windows_process_exe() -> str | None:
    """通过运行中的进程定位 clash-verge.exe（不读取任何其他进程信息）。"""
    ps = (
        "(Get-Process -Name 'clash-verge' -ErrorAction SilentlyContinue | "
        "Select-Object -First 1 -ExpandProperty Path)"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        ).stdout.strip()
        if out and Path(out).is_file():
            return out
    except Exception:
        return None
    return None


def _windows_registry_exe() -> str | None:
    """通过卸载注册表项定位安装目录。"""
    ps = (
        "$paths = @('HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "'HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'); "
        "Get-ItemProperty $paths -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayName -like '*Clash Verge*' } | "
        "Select-Object -First 1 -ExpandProperty InstallLocation"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=20,
        ).stdout.strip()
        if out:
            guess = Path(out) / "clash-verge.exe"
            if guess.is_file():
                return str(guess)
    except Exception:
        return None
    return None


def find_clash_verge_exe() -> str | None:
    """按 环境变量 → PATH → 常见安装位 → 运行进程 → 注册表 顺序探测可执行文件。"""
    env = os.environ.get("CLASH_VERGE_EXE")
    if env and Path(env).is_file():
        return env

    which = shutil.which("clash-verge") or shutil.which("clash-verge.exe")
    if which:
        return which

    system = platform.system()
    if system == "Windows":
        local = os.environ.get("LOCALAPPDATA", str(_home() / "AppData" / "Local"))
        candidates = [
            Path(local) / "Programs" / "clash-verge" / "clash-verge.exe",
            Path(r"C:\Program Files\Clash Verge\clash-verge.exe"),
            Path(r"C:\Program Files (x86)\Clash Verge\clash-verge.exe"),
            Path(r"C:\Clash Verge\clash-verge.exe"),
        ]
        for c in candidates:
            if c.is_file():
                return str(c)
        return _windows_process_exe() or _windows_registry_exe()

    if system == "Darwin":
        candidates = [
            "/Applications/Clash Verge.app/Contents/MacOS/Clash Verge",
            str(_home() / "Applications/Clash Verge.app/Contents/MacOS/Clash Verge"),
        ]
        for c in candidates:
            if Path(c).is_file():
                return c
        return None

    # Linux / 其他
    for c in ("/usr/bin/clash-verge", "/usr/local/bin/clash-verge",
              "/opt/clash-verge/clash-verge"):
        if Path(c).is_file():
            return c
    return None


# ---------------------------------------------------------------------------
# 本机配置读取（全部为本地文件 / 环境变量，不含任何默认密钥）
# ---------------------------------------------------------------------------

def read_text_safe(path: Path) -> str | None:
    try:
        # utf-8-sig 自动剥离可能存在的 BOM，无 BOM 时行为与 utf-8 一致
        return path.read_text(encoding="utf-8-sig")
    except Exception:
        return None


def read_top_value(text: str, key: str) -> str | None:
    """读取 YAML 顶层 `key: value`（仅用于少量本机标量字段，保留其余内容原样）。"""
    m = re.search(rf"(?m)^{re.escape(key)}\s*:\s*(.+?)\s*$", text)
    if not m:
        return None
    val = m.group(1).strip().strip('"').strip("'")
    return val or None


def controller_settings(app_dir: Path) -> dict:
    """
    解析本机 API 地址、secret、混合端口。
    优先级：环境变量 > verge.yaml > 运行时配置 clash-verge.yaml > 内置默认地址。
    注意：不存在 secret 时返回 None，绝不猜测或写入默认密钥。
    """
    api_base = os.environ.get("CLASH_VERGE_API")
    secret = os.environ.get("CLASH_VERGE_SECRET")
    mixed_port = os.environ.get("CLASH_VERGE_MIXED_PORT")

    verge_text = read_text_safe(app_dir / "verge.yaml")
    if verge_text:
        if not api_base:
            v = read_top_value(verge_text, "verge_external_controller")
            if v:
                api_base = v if v.startswith("http") else f"http://{v}"
        if not secret:
            secret = read_top_value(verge_text, "secret")
        if not mixed_port:
            mixed_port = read_top_value(verge_text, "verge_mixed_port")

    runtime_text = read_text_safe(app_dir / "clash-verge.yaml")
    if runtime_text:
        if not api_base:
            v = read_top_value(runtime_text, "external-controller")
            if v:
                api_base = v if v.startswith("http") else f"http://{v}"
        if not secret:
            secret = read_top_value(runtime_text, "secret")
        if not mixed_port:
            mixed_port = read_top_value(runtime_text, "mixed-port")

    return {
        "api_base": (api_base or "http://127.0.0.1:9097").rstrip("/"),
        "secret": secret,  # 可能为 None
        "mixed_port": int(mixed_port) if mixed_port and str(mixed_port).isdigit() else 7897,
    }


# ---------------------------------------------------------------------------
# 备份
# ---------------------------------------------------------------------------

def backup_file(path: Path) -> Path | None:
    """同目录时间戳备份，返回备份路径；备份内含完整订阅，提示用户勿外发。"""
    if not path.is_file():
        return None
    bak = path.with_name(path.name + f".bak-{time.strftime('%Y%m%d%H%M%S')}")
    shutil.copy2(path, bak)
    return bak


# ---------------------------------------------------------------------------
# 纯文本 proxies 段解析（不依赖 PyYAML，不重排文件）
# ---------------------------------------------------------------------------

_TOP_KEY = re.compile(r"^[A-Za-z0-9_.\-]+\s*:")


def locate_section(text: str, key: str):
    """定位顶层 `key:` 段的行范围 [key_line, end_line)，end 指向下一个顶层键。"""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(key)}\s*:", line):
            start = i
            break
    if start is None:
        return None
    end = len(lines)
    for j in range(start + 1, len(lines)):
        if _TOP_KEY.match(lines[j]):
            end = j
            break
    return start, end, lines


def split_proxy_items(body_lines):
    """把 proxies 段体按 `- name:` 切成节点块（保留块内原始行与空行）。"""
    items = []
    current = []
    for line in body_lines:
        if re.match(r"^\s*-\s+name\s*:", line):
            if current:
                items.append(current)
            current = [line]
        elif current:
            current.append(line)
    if current:
        items.append(current)
    return items


def item_name(block):
    m = re.match(r"^\s*-\s+name\s*:\s*(.+?)\s*$", block[0])
    if not m:
        return None
    return m.group(1).strip().strip('"').strip("'")


def extract_proxy_nodes(text: str):
    """仅从 proxies 段提取 (name, server, port)，忽略 proxy-groups 等其他段。"""
    loc = locate_section(text, "proxies")
    if not loc:
        return []
    start, end, lines = loc
    nodes = []
    for block in split_proxy_items(lines[start + 1:end]):
        blob = "\n".join(block)
        name = item_name(block)
        srv = re.search(r"(?m)^\s*server\s*:\s*(\S+)\s*$", blob)
        prt = re.search(r"(?m)^\s*port\s*:\s*(\d+)\s*$", blob)
        if name and srv and prt:
            nodes.append((name, srv.group(1).strip().strip("'\""), int(prt.group(1))))
    return nodes


def dedupe_proxy_text(text: str):
    """
    对 proxies 段按名称去重（保留首次出现的节点），
    其余所有段（全局配置、proxy-groups、rules 等）原样保留。
    返回 (新文本, 移除数量)。
    """
    loc = locate_section(text, "proxies")
    if not loc:
        return text, 0
    start, end, lines = loc
    items = split_proxy_items(lines[start + 1:end])
    seen = set()
    kept = []
    removed = 0
    for block in items:
        name = item_name(block)
        if name is not None:
            if name in seen:
                removed += 1
                continue
            seen.add(name)
        kept.append(block)

    new_lines = list(lines[:start + 1])
    for block in kept:
        new_lines.extend(block)
    new_lines.extend(lines[end:])
    result = "\n".join(new_lines)
    if text.endswith("\n") and not result.endswith("\n"):
        result += "\n"
    return result, removed


def count_proxy_names(text: str):
    """统计 proxies 段节点数与重名集合（不扫 proxy-groups）。"""
    names = [n for n, _, _ in extract_proxy_nodes(text)]
    counts = {}
    for n in names:
        counts[n] = counts.get(n, 0) + 1
    dupes = {k: v for k, v in counts.items() if v > 1}
    return len(names), dupes


def update_profile_url_text(text: str, uid: str, new_url: str):
    """
    替换 profiles.yaml 中指定 uid 条目内的 url 字段（行级处理，保留其余内容）。
    找不到对应条目时返回 None。
    """
    lines = text.splitlines()
    # items 列表条目以 "- uid:" 或 "  - uid:" 起始
    item_start = None
    for i, line in enumerate(lines):
        m = re.match(r"^(\s*)-\s+uid\s*:\s*(\S+)\s*$", line)
        if m and m.group(2).strip() == uid:
            item_start = i
            break
    if item_start is None:
        # 兼容 uid 独占一行之后跟值的写法
        return None
    item_end = len(lines)
    for j in range(item_start + 1, len(lines)):
        if re.match(r"^\s*-\s+uid\s*:", lines[j]) or _TOP_KEY.match(lines[j]):
            item_end = j
            break
    replaced = False
    for j in range(item_start, item_end):
        if re.match(r"^\s*url\s*:", lines[j]):
            indent = re.match(r"^(\s*)", lines[j]).group(1)
            lines[j] = f"{indent}url: {new_url}"
            replaced = True
            break
    if not replaced:
        return None
    return "\n".join(lines) + ("\n" if text.endswith("\n") else "")


def upsert_top_value(text: str, key: str, value: str) -> str:
    """顶层键存在则替换，不存在则在文件末尾追加。"""
    if re.search(rf"(?m)^{re.escape(key)}\s*:", text):
        return re.sub(
            rf"(?m)^{re.escape(key)}\s*:.*$",
            f"{key}: {value}", text, count=1,
        )
    base = text.rstrip("\n")
    return base + f"\n{key}: {value}\n"
