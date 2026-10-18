#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
safety_guard.py - 本地安全合规拦截层（纯本地、零联网、零上报）

在任何网络访问前依次执行：

  1. 永久黑名单：状态目录 blocklist.txt 中的域名精确/后缀命中即永久阻断；
     类别词命中的域名会自动写入该名单，所有后续运行不再访问。
  2. 违法类别词库：博彩、诈骗、色情、毒品、枪支、非法金融、黑客攻击、
     公民信息贩卖等法律明令禁止类别（中英文，域名 label 匹配 + 中文子串匹配）。
  3. 钓鱼 / 可疑 URL 结构：凭证型 URL（userinfo）、punycode 同形异义域名、
     内网与保留地址（SSRF 防护）、明文 HTTP 订阅（强制 HTTPS）。
  4. 安全下载：重定向逐跳检查（最多 3 跳、禁止 HTTPS→HTTP 降级）、
     体积上限、拒绝二进制与伪装成订阅的钓鱼 HTML 页面。
  5. 订阅路由劫持审计：政务 / 银行 / 支付域名被导向代理节点时阻断，
     教育域名导向代理时告警；内网网段走代理时告警。

所有规则、黑名单与事件仅保存在本机状态目录，不向任何第三方查询、
不发送任何 URL 或域名；可逐行审计。
"""

from __future__ import annotations

import os
import re
import sys
import time
import json
import socket
import hashlib
import ipaddress
import urllib.request
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clash_common as cc

# ---------------------------------------------------------------------------
# 违规类别词库（安全防护特征，仅用于拦截）
# ---------------------------------------------------------------------------

# 英文词：以 host 拆分后的 label（按 . - _ 切割）精确匹配，避免短词误伤
# （例如 bet 不收录，避免误伤 better；bet365 等明确词收录）
EXACT_LABEL_KEYWORDS = {
    "gambling": {
        "casino", "casinos", "gambling", "gamble", "baccarat", "slots",
        "poker", "blackjack", "roulette", "lottery", "lotteries", "bet365",
        "188bet", "12bet", "22bet", "sbobet", "sportsbet", "sportsbetting",
        "bookmaker", "sweepstakes", "pachinko", "888casino", "m88", "w88",
        "ibc9", "bobet", "hg08", "agcasino", "macauslot", "mgmcasino",
        "live-casino", "online-casino",
    },
    "fraud": {
        "phishing", "scam", "scams", "fraud", "fraudsters", "fakebank",
        "bankverify", "bank-verify", "verify-account", "secure-login",
        "account-verification", "moneylaundering", "money-mule", "carding",
        "carders", "cvvshop", "dumpshop", "fullz", "bruteforce",
        "brute-force", "fakepay", "stolen-account", "account-factory",
    },
    "porn": {
        "porn", "porno", "pornhub", "xvideos", "xnxx", "xxx", "onlyfans",
        "hentai", "escorts", "webcamsex", "adultdating", "redtube",
        "xhamster", "brazzers", "adult-video", "sex-chat",
    },
    "drugs": {
        "cocaine", "heroin", "methamphetamine", "fentanyl", "oxycodone",
        "drugmarket", "weedshop", "cannabis-shop", "psychedelics-shop",
        "buy-drugs", "darknet-market",
    },
    "weapons": {
        "guns-for-sale", "rifles-for-sale", "ammoshop", "glockforsale",
        "silencer-shop", "explosives-shop", "buy-weapons",
    },
    "cybercrime": {
        "malware", "ransomware", "stealer", "keylogger", "rootkit",
        "exploit-kit", "cracked-software", "keygen", "warez", "nulled",
        "webshell", "ddos-service", "stolen-database",
    },
}

# 中文词：在 host（含解码后的路径）与节点名中做子串匹配。
# 刻意保守：多义、易误伤的短词（如“成人”“外围”“菠菜”）不收录。
SUBSTRING_KEYWORDS = {
    "gambling": [
        "博彩", "赌场", "赌博", "网赌", "网络售彩", "时时彩", "六合彩",
        "北京赛车", "百家乐", "老虎机", "赌球", "赌马", "真人视讯",
        "现金网", "棋牌在线", "威尼斯人", "金沙赌场", "皇冠体育",
        "飞艇计划", "在线娱乐城", "娱乐城", "网络赌场",
    ],
    "fraud": [
        "诈骗", "刷单", "跑分平台", "洗钱", "资金盘", "杀猪盘", "传销",
        "非法集资", "钓鱼网站", "接码平台", "公民信息", "身份证贩卖",
        "银行卡四件套", "储蓄卡收购", "信用卡套现", "贷款套现", "套现",
    ],
    "porn": [
        "色情", "成人视频", "成人电影", "成人用品", "裸聊", "约炮", "援交",
        "卖淫", "嫖娼", "偷拍在线", "同城约炮", "在线av", "成人av",
    ],
    "drugs": [
        "毒品", "海洛因", "冰毒", "麻古", "摇头丸", "大麻出售", "迷奸药",
        "三唑仑", "k粉出售",
    ],
    "weapons": [
        "枪支", "猎枪", "气枪", "仿真枪", "炸药", "雷管", "子弹出售",
        "军火爆卖",
    ],
    "cybercrime": [
        "黑客教程", "木马免杀", "webshell出售", "攻击接单", "ddos平台",
        "撞库", "脱库", "社工库", "钓鱼源码",
    ],
    "stolen_data": [
        "开房记录", "身份证查询", "户籍查询", "征信修复", "个人信息出售",
        "银行卡余额查询",
    ],
}

CATEGORY_LABEL = {
    "gambling": "博彩",
    "fraud": "诈骗/非法金融",
    "porn": "色情",
    "drugs": "毒品",
    "weapons": "枪支武器",
    "cybercrime": "黑客攻击/恶意软件",
    "stolen_data": "公民信息贩卖",
}

# 官方域名豁免：政府与教育域名由域名体系保障，不做类别词误伤
# （显式黑名单仍优先于豁免）
OFFICIAL_SUFFIXES = (".gov.cn", ".edu.cn")

# 高风险路由劫持审计：敏感域名被导向代理时阻断
PROTECTED_SUFFIXES_BLOCK = [
    "gov.cn",            # 各级政府
    "pbc.gov.cn",        # 人民银行（含于 gov.cn，显式列出便于审计）
    "alipay.com", "alipayobjects.com",
    "tenpay.com", "weixinpay.com",
    "unionpay.com", "unionpaysecure.com", "95516.com",
    "icbc.com.cn", "ccb.com", "abchina.com", "boc.cn", "bankcomm.com",
    "psbc.com", "cmbchina.com", "spdb.com.cn", "citicbank.com.cn",
    "cebbank.com", "cib.com.cn", "hxb.com", "cgbchina.com.cn",
    "cmbc.com.cn", "pingan.com", "bankofbeijing.com.cn",
]
# 教育域名被导向代理时仅告警
PROTECTED_SUFFIXES_WARN = ["edu.cn"]

# 注入路由的内网网段（恶意订阅可能将内网流量导向节点）
INTERNAL_CIDRS = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    )
]

# allow_local 显式放行的来源网段：仅环回与 RFC1918 私网。
# 刻意不含 169.254.0.0/16（云元数据地址）与 100.64.0.0/10 等保留网段。
_LOCAL_ALLOW_NETS = [
    ipaddress.ip_network(n) for n in (
        "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    )
]


def _is_allowable_local(ip) -> bool:
    return any(ip in net for net in _LOCAL_ALLOW_NETS)

MAX_REDIRECTS = 3
DEFAULT_MAX_DOWNLOAD_MB = 10


class SafetyViolation(Exception):
    """安全拦截异常。permanent=True 时会写入永久黑名单。"""

    def __init__(self, category: str, reason: str, target: str,
                 permanent: bool = False):
        self.category = category
        self.reason = reason
        self.target = target
        self.permanent = permanent
        super().__init__(f"[{category}] {reason}: {target}")


# ---------------------------------------------------------------------------
# 状态目录（黑名单 / 事件日志）
# ---------------------------------------------------------------------------

def state_dir() -> Path:
    env = os.environ.get("CLASH_DEPLOYER_STATE_DIR")
    if env:
        d = Path(env)
    else:
        system = sys.platform
        home = Path.home()
        if system.startswith("win"):
            base = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
            d = Path(base) / "clash-verge-deployer"
        elif system == "darwin":
            d = home / "Library" / "Application Support" / "clash-verge-deployer"
        else:
            d = home / ".config" / "clash-verge-deployer"
    d.mkdir(parents=True, exist_ok=True)
    return d


def blocklist_file() -> Path:
    """域名级永久黑名单（命中的主机及其子域）。"""
    return state_dir() / "blocklist.txt"


def blocked_urls_file() -> Path:
    """链接级永久黑名单：host + 路径前缀（仅路径命中类别时使用）。"""
    return state_dir() / "blocked-urls.txt"


def events_file() -> Path:
    return state_dir() / "blocked-events.log"


def hashes_file() -> Path:
    """订阅内容哈希记录（防篡改基线）。"""
    return state_dir() / "subscription-hashes.json"


def compute_sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def load_hashes():
    try:
        return json.loads(hashes_file().read_text(encoding="utf-8"))
    except Exception:
        return {}


def record_hash(key: str, sha256: str):
    data = load_hashes()
    entry = data.get(key, {})
    data[key] = {
        "sha256": sha256,
        "first_seen": entry.get("first_seen",
                                datetime.now(timezone.utc).isoformat()),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    hashes_file().write_text(
        json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def check_hash(key: str, sha256: str, pin: str | None):
    """
    防篡改校验。返回 (status, detail)：
      'ok'              与上次记录一致
      'changed'         与上次记录不同（可能是正常更新，也可能是异常）
      'pinned_ok'       匹配用户提供的 pin
      'pinned_mismatch' 不匹配 pin（调用方应抛 SafetyViolation 终止）
      'new'             首次记录
    """
    if pin:
        if sha256 == pin.lower():
            return "pinned_ok", sha256
        return "pinned_mismatch", pin
    record = load_hashes().get(key)
    if not record:
        return "new", sha256
    if record.get("sha256") == sha256:
        return "ok", record["sha256"]
    return "changed", record["sha256"]


def _read_lines(path: Path):
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        # 同时剥离行尾内联注释（如 "evil.com  # auto gambling ..."）
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.lower())
    return out


def _append_line(path: Path, line: str):
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def load_blocklist() -> set:
    """域名级永久黑名单 + 用户自定义黑名单（custom-blocklist.txt）。"""
    rules = set(_read_lines(blocklist_file()))
    custom = state_dir() / "custom-blocklist.txt"
    rules.update(_read_lines(custom))
    return rules


def load_blocked_urls():
    """链接级黑名单，返回 [(host, path_prefix), ...]。"""
    out = []
    for raw in _read_lines(blocked_urls_file()):
        if "\t" in raw:
            h, p = raw.split("\t", 1)
            out.append((h.strip(), p.strip()))
    return out


def block_host(host: str, category: str, reason: str):
    """写入域名级永久黑名单与事件日志（本地记录，不进入任何输出外发）。"""
    host = host.lower().strip()
    if host not in _read_lines(blocklist_file()):
        _append_line(blocklist_file(),
                     f"{host}    # auto {category} "
                     f"{datetime.now(timezone.utc).isoformat()}")
    _append_line(events_file(),
                 f"{datetime.now(timezone.utc).isoformat()}\tBLOCK\t"
                 f"{category}\t{host}\t{reason}")


def block_url(host: str, path_prefix: str, category: str, reason: str):
    """写入链接级永久黑名单（仅路径命中时，避免牵连整域）。"""
    path_blocked = blocked_urls_file()
    existing = load_blocked_urls()
    key = (host.lower(), path_prefix)
    if key not in existing:
        _append_line(path_blocked,
                     f"{host.lower()}\t{path_prefix}    # auto {category} "
                     f"{datetime.now(timezone.utc).isoformat()}")
    _append_line(events_file(),
                 f"{datetime.now(timezone.utc).isoformat()}\tBLOCK-URL\t"
                 f"{category}\t{host}{path_prefix}\t{reason}")


def list_blocked():
    """返回 (域名黑名单, 链接黑名单, 自定义条目, 事件行数)，供本机管理。"""
    auto = _read_lines(blocklist_file())
    url_rules = load_blocked_urls()
    custom = _read_lines(state_dir() / "custom-blocklist.txt")
    events = events_file()
    n_events = len(events.read_text(encoding="utf-8").splitlines()) \
        if events.is_file() else 0
    return auto, url_rules, custom, n_events


# ---------------------------------------------------------------------------
# 匹配原语
# ---------------------------------------------------------------------------

def _domain_matches(host: str, rule: str) -> bool:
    host = host.lower().rstrip(".")
    rule = rule.lower().strip()
    return host == rule or host.endswith("." + rule)


def _is_official(host: str) -> bool:
    h = host.lower()
    return any(h.endswith(s) for s in OFFICIAL_SUFFIXES)


def _keyword_hit(text: str):
    """返回命中的 (category, 词)。
    中文按子串匹配；英文两级匹配：
      段集合（保留连字符，命中 guns-for-sale 等完整词）
      + token 集合（按连字符切开，命中 casino-bet365 中的 casino）。"""
    # 中文子串
    for category, words in SUBSTRING_KEYWORDS.items():
        for w in words:
            if w in text:
                return category, w
    lowered = text.lower()
    segments = set(re.split(r"[^a-z0-9-]+", lowered))
    tokens = set()
    for seg in segments:
        tokens.update(x for x in seg.split("-") if x)
    labels = (segments | tokens) - {""}
    for category, words in EXACT_LABEL_KEYWORDS.items():
        hit = labels & words
        if hit:
            return category, sorted(hit)[0]
    return None


def _is_internal_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local or
            ip.is_reserved or ip.is_multicast or ip.is_unspecified)


# ---------------------------------------------------------------------------
# URL 检查
# ---------------------------------------------------------------------------

def check_url(url: str, *, allow_suspicious: bool = False,
              allow_http: bool = False,
              allow_loopback: bool = False,
              allow_local: bool = False):
    """
    访问前检查。
    allow_loopback：仅供本机 127.0.0.1 API 调用内部使用；
    allow_local：显式放行环回与 RFC1918 私网地址（用户自建本机/内网订阅源场景，
                 元数据地址 169.254.169.254 等仍拦截）。
    命中类别/黑名单直接抛 SafetyViolation(permanent=True)；
    可疑结构默认抛非永久违规，allow_suspicious 放行。
    """
    if not url or not isinstance(url, str):
        raise SafetyViolation("invalid_url", "URL 为空", str(url))

    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise SafetyViolation("invalid_scheme",
                              f"仅允许 http/https，收到 {scheme or '空'}", url)

    host = (parsed.hostname or "").lower()
    if not host:
        raise SafetyViolation("invalid_url", "无法解析主机名", url)

    # 1. 永久黑名单优先（域名级 + 链接级）
    for rule in load_blocklist():
        if _domain_matches(host, rule):
            raise SafetyViolation("blocked",
                                  f"命中永久黑名单规则 {rule}",
                                  cc.redact_url(url), permanent=False)
    decoded_path = urllib.parse.unquote(parsed.path or "")
    for rule_host, prefix in load_blocked_urls():
        if _domain_matches(host, rule_host) and decoded_path.startswith(prefix):
            raise SafetyViolation("blocked",
                                  f"命中永久链接黑名单 {rule_host}{prefix}",
                                  cc.redact_url(url), permanent=False)

    # 2. 内网/保留地址（SSRF 防护）；本机 API 豁免；显式放行本机/私网源
    is_ip = True
    try:
        _ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        is_ip = False
        _ip = None
    if is_ip and _is_internal_ip(host):
        local_ok = allow_loopback or (
            allow_local and _ip is not None and _is_allowable_local(_ip))
        if not local_ok:
            raise SafetyViolation("internal_address",
                                  "目标为内网/保留地址，禁止访问（SSRF 防护）",
                                  host)

    # 3. 强制 HTTPS（非本机）
    if scheme == "http" and not allow_http and not (allow_loopback or allow_local):
        raise SafetyViolation("plain_http",
                              "明文 HTTP 订阅已拒绝，请改用 HTTPS",
                              cc.redact_url(url))

    # 4. 可疑结构：凭证型 URL、punycode 同形异义域名
    if parsed.username or parsed.password:
        if not allow_suspicious:
            raise SafetyViolation("suspicious_url",
                                  "URL 含用户名/密码字段（钓鱼特征）",
                                  cc.redact_url(url))
    if "xn--" in host:
        if not allow_suspicious:
            raise SafetyViolation("suspicious_url",
                                  "punycode 同形异义域名（钓鱼特征）",
                                  host)

    # 5. 违法类别词：主机命中 → 域名级拉黑；仅路径命中 → 链接级拉黑（不牵连整域）
    if not _is_official(host):
        host_hit = _keyword_hit(host)
        if host_hit:
            category, word = host_hit
            block_host(host, category, f"host-keyword:{word}")
            raise SafetyViolation(
                category,
                f"域名命中{ CATEGORY_LABEL.get(category, category) }类规则"
                f"（{word}），该主机已永久拉黑",
                host, permanent=True)
        if decoded_path:
            path_hit = _keyword_hit(decoded_path)
            if path_hit:
                category, word = path_hit
                prefix = decoded_path[:decoded_path.find(word) + len(word)]
                block_url(host, prefix, category, f"path-keyword:{word}")
                raise SafetyViolation(
                    category,
                    f"链接路径命中{ CATEGORY_LABEL.get(category, category) }"
                    f"类规则（{word}），该链接已永久拉黑",
                    cc.redact_url(url), permanent=True)


def check_node(name: str, server: str, port):
    """
    检查订阅中的单个节点（名称与服务器地址）。
    命中类别即永久拉黑服务器域名并抛异常。
    """
    server = (server or "").strip().lower()
    if server:
        for rule in load_blocklist():
            if _domain_matches(server, rule):
                raise SafetyViolation("blocked",
                                      f"节点服务器命中黑名单规则 {rule}",
                                      server)
        if _is_internal_ip(server):
            raise SafetyViolation("internal_address",
                                  "节点服务器指向内网地址（恶意订阅特征）",
                                  server)
        hit = _keyword_hit(server + " " + str(name or ""))
        if hit:
            category, word = hit
            block_host(server, category, f"node-keyword:{word}")
            raise SafetyViolation(
                category,
                f"节点信息命中{ CATEGORY_LABEL.get(category, category) }类"
                f"规则（{word}），订阅已拒绝并永久拉黑该服务器",
                server, permanent=True)


# ---------------------------------------------------------------------------
# 安全下载（重定向逐跳检查 + 大小限制 + 内容嗅探）
# ---------------------------------------------------------------------------

class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allow_suspicious, allow_http, allow_loopback=False,
                 allow_local=False):
        self.hops = 0
        self.allow_suspicious = allow_suspicious
        self.allow_http = allow_http
        self.allow_loopback = allow_loopback
        self.allow_local = allow_local

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.hops += 1
        if self.hops > MAX_REDIRECTS:
            raise SafetyViolation("too_many_redirects",
                                  f"重定向超过 {MAX_REDIRECTS} 次", newurl)
        target = urllib.parse.urljoin(req.full_url, newurl)
        if req.full_url.startswith("https://") and target.startswith("http://"):
            raise SafetyViolation("tls_downgrade",
                                  "重定向将 HTTPS 降级为 HTTP，已拒绝", target)
        check_url(target, allow_suspicious=self.allow_suspicious,
                  allow_http=self.allow_http,
                  allow_loopback=self.allow_loopback,
                  allow_local=self.allow_local)
        cc.log(f"  重定向 {self.hops}/{MAX_REDIRECTS}: "
               f"{cc.redact_url(target)}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download_safe(url: str, *, max_mb: int = DEFAULT_MAX_DOWNLOAD_MB,
                  timeout: int = 30, user_agent: str = "",
                  allow_suspicious: bool = False, allow_http: bool = False,
                  allow_loopback: bool = False, allow_local: bool = False):
    """先检查 URL，再安全下载；返回 UTF-8 文本。
    allow_loopback 仅供本机测试/API；allow_local 供自建本机/内网订阅源。"""
    check_url(url, allow_suspicious=allow_suspicious, allow_http=allow_http,
              allow_loopback=allow_loopback, allow_local=allow_local)
    cc.log(f"下载订阅: {cc.redact_url(url)}")

    handler = _SafeRedirectHandler(allow_suspicious, allow_http,
                                   allow_loopback=allow_loopback,
                                   allow_local=allow_local)
    opener = urllib.request.build_opener(handler)
    req = urllib.request.Request(
        url, headers={"User-Agent": user_agent or "clash-verge-deployer/2.0"})

    with opener.open(req, timeout=timeout) as resp:
        # 仅允许 200/204；最终落地再次检查（重定向处理器已覆盖，此处双保险）
        chunks, total = [], 0
        limit = max_mb * 1024 * 1024
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise SafetyViolation(
                    "oversize_download",
                    f"下载内容超过 {max_mb} MB 上限，已中止",
                    cc.redact_url(url))
            chunks.append(chunk)
    raw = b"".join(chunks)
    cc.log(f"下载完成: {len(raw)} 字节")

    # 内容嗅探
    if b"\x00" in raw[:2048]:
        raise SafetyViolation("binary_content",
                              "下载内容为二进制文件（非 YAML 订阅），已拒绝",
                              cc.redact_url(url))
    head = raw[:4096].decode("utf-8", errors="replace").lstrip().lower()
    if head.startswith("<!doctype html") or head.startswith("<html") or \
            head.startswith("<head"):
        raise SafetyViolation("phishing_page",
                              "订阅地址返回 HTML 页面（钓鱼/登录页伪装），已拒绝",
                              cc.redact_url(url))
    text = raw.decode("utf-8", errors="replace").lstrip("\ufeff")
    if "proxies" not in text:
        raise SafetyViolation("not_a_subscription",
                              "下载内容不含 proxies 段，不是有效 Clash 订阅",
                              cc.redact_url(url))
    return text


# ---------------------------------------------------------------------------
# 订阅内容安全扫描
# ---------------------------------------------------------------------------

def scan_nodes(content: str):
    """对订阅全部节点做合规检查；命中即返回首个违规。"""
    nodes = cc.extract_proxy_nodes(content)
    for idx, (name, server, port) in enumerate(nodes, start=1):
        check_node(name, server, port)
    return len(nodes)


_RULE_LINE = re.compile(
    r"^\s*-\s*(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD)\s*,([^,]+),([^,]+)")
_CIDR_LINE = re.compile(r"^\s*-\s*IP-CIDR(?:6)?\s*,([^,]+),([^,]+)")


def audit_routing(content: str):
    """
    路由劫持审计，返回 (critical, warnings)：
      critical：政务/银行/支付域名被导向非 DIRECT/REJECT 策略；
      warnings：教育域名导向代理、内网网段导向代理。
    """
    loc = cc.locate_section(content, "rules")
    if not loc:
        return [], []
    start, end, lines = loc
    critical, warnings = [], []
    for line in lines[start:end]:
        m = _RULE_LINE.match(line)
        if m:
            kind, domain, policy = m.group(1), m.group(2).strip().lower(), \
                m.group(3).strip().upper()
            if policy in ("DIRECT", "REJECT", "PASS"):
                continue
            for suffix in PROTECTED_SUFFIXES_BLOCK:
                if (kind == "DOMAIN-SUFFIX" and
                        (domain == suffix or domain.endswith("." + suffix))) \
                        or (kind == "DOMAIN" and domain == suffix) \
                        or (kind == "DOMAIN-KEYWORD" and suffix in domain):
                    critical.append(f"敏感域名({suffix}) 被导向代理策略 {policy}")
                    break
            else:
                for suffix in PROTECTED_SUFFIXES_WARN:
                    if (kind == "DOMAIN-SUFFIX" and
                        (domain == suffix or domain.endswith("." + suffix))) \
                            or (kind == "DOMAIN" and domain == suffix):
                        warnings.append(
                            f"教育域名({suffix}) 被导向代理策略 {policy}")
                        break
            continue
        m2 = _CIDR_LINE.match(line)
        if m2:
            cidr, policy = m2.group(1).strip(), m2.group(2).strip().upper()
            if policy in ("DIRECT", "REJECT", "PASS"):
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if any(net.subnet_of(internal) or net == internal
                       for internal in INTERNAL_CIDRS):
                    warnings.append(f"内网网段 {cidr} 被导向代理策略 {policy}")
            except ValueError:
                continue
    return critical, warnings
