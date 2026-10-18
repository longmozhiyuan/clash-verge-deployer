#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_direct_rules.py - 生成/合并"正规站点直连"规则（浏览器侧配套）

用途：
  让政务、教育、银行、支付、运营商与主流正规站点始终走 DIRECT，
  不经过代理节点，避免敏感流量被节点运营方观测（与 SKILL.md 路由劫持审计呼应）。

用法：
  python make_direct_rules.py --out direct-rules.yaml
      生成独立规则文件（含域名与内网网段 DIRECT 规则）
  python make_direct_rules.py --merge <订阅文件> [--out <输出>|--in-place]
      把直连规则插入订阅 rules 段最前（优先匹配），
      并将订阅中原有的敏感域名非 DIRECT 规则改写为 DIRECT（自动备份）

隐私：
  纯本地操作；域名清单为公开正规站点，不含任何个人信息；
  输出可安全分享（仍建议按需精简）。
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clash_common as cc
import safety_guard as sg

ASSETS_DIR = Path(__file__).resolve().parent.parent / "assets"
DOMAINS_FILE = ASSETS_DIR / "direct-domains.txt"

INTERNAL_DIRECT_RULES = [
    "IP-CIDR,127.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve",
    "IP-CIDR,172.16.0.0/12,DIRECT,no-resolve",
    "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,169.254.0.0/16,DIRECT,no-resolve",
    "IP-CIDR,100.64.0.0/10,DIRECT,no-resolve",
]

# 需要强制 DIRECT 的敏感域名后缀（与 safety_guard 的审计清单一致）
SENSITIVE_SUFFIXES = set(sg.PROTECTED_SUFFIXES_BLOCK) | \
    set(sg.PROTECTED_SUFFIXES_WARN)


def load_direct_domains() -> list:
    if not DOMAINS_FILE.is_file():
        print(f"缺少域名清单: {DOMAINS_FILE}")
        sys.exit(2)
    out = []
    for line in DOMAINS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.lower().rstrip(".")
        if domain and domain not in out:
            out.append(domain)
    return out


def build_direct_rules(domains=None) -> list:
    """返回 ['DOMAIN-SUFFIX,xxx,DIRECT', ...]（含内网网段）。"""
    domains = domains if domains is not None else load_direct_domains()
    rules = [f"DOMAIN-SUFFIX,{d},DIRECT" for d in domains]
    rules.extend(INTERNAL_DIRECT_RULES)
    return rules


def write_rules_file(rules: list, out: Path):
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# 正规站点直连规则（clash-verge-deployer 生成，可安全分享）",
             "# 作用：政务/教育/银行/支付/运营商/主流站点走 DIRECT，不经过代理节点",
             "# 可编辑本文件或 assets/direct-domains.txt 后重新生成",
             "rules:"]
    for r in rules:
        lines.append(f"  - {r}")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"已生成 {len(rules)} 条直连规则: {out}")


def merge_into_subscription(sub_path: Path, rules: list,
                            out_path: Path | None = None,
                            in_place: bool = False):
    """插入直连规则到 rules 段最前；敏感域名非 DIRECT 规则改写为 DIRECT。"""
    content = sub_path.read_text(encoding="utf-8-sig", errors="replace")
    loc = cc.locate_section(content, "rules")
    if not loc:
        print("订阅缺少 rules 段，无法合并")
        sys.exit(1)
    start, end, lines = loc

    # 已存在的敏感域名 DIRECT 规则（避免重复插入）
    direct_seen = set()
    # 1) 先改写订阅中原敏感域名的非 DIRECT 规则为 DIRECT
    rewritten = 0
    for i in range(start, end):
        m = sg._RULE_LINE.match(lines[i])
        if not m:
            continue
        kind, domain, policy = m.group(1), m.group(2).strip().lower(), \
            m.group(3).strip().upper()
        if policy in ("DIRECT", "REJECT", "PASS"):
            if kind == "DOMAIN-SUFFIX" and domain in SENSITIVE_SUFFIXES:
                direct_seen.add(domain)
            continue
        hit = None
        for suffix in SENSITIVE_SUFFIXES:
            if (kind == "DOMAIN-SUFFIX" and
                    (domain == suffix or domain.endswith("." + suffix))) \
                    or (kind == "DOMAIN-KEYWORD" and suffix in domain) \
                    or (kind == "DOMAIN" and domain == suffix):
                hit = suffix
                break
        if hit:
            indent = re_indent(lines[i])
            lines[i] = f"{indent}- {kind},{domain},{'DIRECT'}"
            direct_seen.add(hit)
            rewritten += 1

    # 2) 构造待插入规则（跳过已 DIRECT 的敏感后缀，其余全部插入）
    insert_rules = []
    seen_insert = set()
    for r in rules:
        if r.startswith("DOMAIN-SUFFIX,"):
            d = r.split(",", 2)[1]
            if d in direct_seen:
                continue
        if r not in seen_insert:
            seen_insert.add(r)
            insert_rules.append(f"  - {r}")

    # 3) 在 rules 段头部插入
    new_lines = lines[:start + 1] + insert_rules + \
        ([""] if start + 1 < len(lines) else []) + lines[start + 1:]

    new_content = "\n".join(new_lines)
    if content.endswith("\n") and not new_content.endswith("\n"):
        new_content += "\n"

    if in_place:
        bak = cc.backup_file(sub_path)
        sub_path.write_text(new_content, encoding="utf-8")
        print(f"已合并到原文件（备份: {bak}）")
    else:
        if out_path is None:
            print("请指定 --out 或 --in-place")
            sys.exit(2)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(new_content, encoding="utf-8")
        print(f"已输出合并订阅: {out_path}")

    print(f"重写敏感域名规则: {rewritten} 条 | 插入直连规则: {len(insert_rules)} 条")
    # 4) 合并后审计：不应再存在敏感域名走代理
    critical, warnings = sg.audit_routing(new_content)
    if critical:
        print(f"⚠ 审计异常（仍有 {len(critical)} 条敏感域名走代理），请检查订阅 rules 段")
    elif warnings:
        print(f"审计提示: {warnings}")
    else:
        print("审计通过: 合并后敏感域名均未走代理")


def re_indent(line: str) -> str:
    import re
    return re.match(r"^(\s*)", line).group(1)


def main():
    cc._utf8_stdout()
    parser = argparse.ArgumentParser(
        description="生成/合并正规站点直连规则（浏览器侧配套）")
    parser.add_argument("--out", help="输出规则文件路径（生成模式）")
    parser.add_argument("--merge", metavar="订阅文件", help="合并到订阅文件的 rules 段")
    parser.add_argument("--out-sub", metavar="输出订阅", help="合并模式输出路径")
    parser.add_argument("--in-place", action="store_true", help="合并模式原地修改（自动备份）")
    args = parser.parse_args()

    rules = build_direct_rules()
    if args.merge:
        sub = Path(args.merge)
        if not sub.is_file():
            print(f"订阅文件不存在: {sub}")
            sys.exit(2)
        out = Path(args.out_sub) if args.out_sub else None
        merge_into_subscription(sub, rules, out_path=out,
                                in_place=args.in_place)
    elif args.out:
        write_rules_file(rules, Path(args.out))
    else:
        print("请提供 --out <文件> 或 --merge <订阅文件>")
        sys.exit(2)


if __name__ == "__main__":
    main()
