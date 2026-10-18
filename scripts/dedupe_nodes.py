#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dedupe_nodes.py - 对 Clash 订阅 proxies 段按名称去重

用法:
  python dedupe_nodes.py <输入文件> <输出文件>
  python dedupe_nodes.py <输入文件> <输出文件> --in-place   # 原地修改（自动备份）

说明:
  - 只处理 proxies 段内的重名节点，保留首个出现的节点；
  - global 配置、dns、proxy-groups、rules 等其余所有段原样保留；
  - 不依赖 PyYAML，不重排文件、不改写注释。
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clash_common as cc
import safety_guard as sg


def main():
    cc._utf8_stdout()
    parser = argparse.ArgumentParser(description="Clash 订阅 proxies 段去重")
    parser.add_argument("input", help="输入 YAML 文件")
    parser.add_argument("output", nargs="?", help="输出 YAML 文件（--in-place 时可省略）")
    parser.add_argument("--in-place", action="store_true",
                        help="原地修改输入文件（自动生成 .bak-时间戳 备份）")
    parser.add_argument("--no-safety-scan", action="store_true",
                        help="跳过节点合规扫描（仅做去重，不建议）")
    args = parser.parse_args()

    src = Path(args.input)
    if not src.is_file():
        print(f"文件不存在: {src}")
        sys.exit(2)

    content = src.read_text(encoding="utf-8-sig", errors="replace")
    before, before_dupes = cc.count_proxy_names(content)
    result, removed = cc.dedupe_proxy_text(content)
    after, after_dupes = cc.count_proxy_names(result)

    # 合规扫描：去重结果写入前检查节点名/服务器，命中类别即拉黑并拒绝输出
    if not args.no_safety_scan:
        try:
            n = sg.scan_nodes(result)
            print(f"安全扫描: {n} 个节点通过合规检查")
        except sg.SafetyViolation as e:
            print(f"⛔ 安全拦截 [{e.category}]：{e.reason}")
            print("已停止输出，相关服务器已写入永久黑名单；"
                  "如仅需去重可加 --no-safety-scan（不建议）")
            sys.exit(3)

    if args.in_place:
        bak = cc.backup_file(src)
        src.write_text(result, encoding="utf-8")
        dst = src
        print(f"已原地修改: {dst}")
        if bak:
            print(f"备份文件（含完整订阅，请勿外发）: {bak}")
    else:
        if not args.output:
            print("请提供输出文件路径，或使用 --in-place")
            sys.exit(2)
        dst = Path(args.output)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(result, encoding="utf-8")
        print(f"已输出: {dst}")

    print(f"原始节点数: {before}（重名 {len(before_dupes)} 组）")
    print(f"移除重复: {removed}")
    print(f"剩余节点: {after}（重名 {len(after_dupes)} 组）")
    if removed == 0:
        print("没有需要去重的节点")


if __name__ == "__main__":
    main()
