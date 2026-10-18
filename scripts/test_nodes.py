#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_nodes.py - 测试 Clash 订阅中节点的 TCP 连通性（默认脱敏输出）

用法:
  python test_nodes.py <订阅文件路径> [最大测试节点数]
  python test_nodes.py <订阅文件路径> 50 --verbose   # 明文排错，输出勿外发

隐私:
  - 默认仅显示序号、短哈希与通断结果，不输出节点名/服务器地址；
  - 仅向订阅文件中已有的节点地址发起 TCP 连接，不做任何额外请求。
"""

from __future__ import annotations

import sys
import socket
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clash_common as cc
import safety_guard as sg


def test_node(server: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((server, int(port))) == 0
    except Exception:
        return False


def main():
    cc._utf8_stdout()
    parser = argparse.ArgumentParser(description="Clash 节点 TCP 连通性测试（脱敏）")
    parser.add_argument("file", help="订阅 YAML 文件路径")
    parser.add_argument("max_nodes", nargs="?", type=int, default=50,
                        help="最多测试节点数（默认 50）")
    parser.add_argument("--timeout", type=float, default=3.0, help="单节点超时秒数")
    parser.add_argument("--verbose", action="store_true",
                        help="明文显示节点名与地址（仅限本机排错，输出勿外发）")
    parser.add_argument("--allow-suspicious", action="store_true",
                        help="放行可疑结构特征（违法类别与黑名单仍拦截）")
    args = parser.parse_args()

    cc.set_verbose(args.verbose)
    path = Path(args.file)
    if not path.is_file():
        print(f"文件不存在: {path}")
        sys.exit(2)

    content = path.read_text(encoding="utf-8-sig", errors="replace")
    nodes = cc.extract_proxy_nodes(content)
    if not nodes:
        print("未在 proxies 段解析到任何节点（检查 YAML 格式）")
        sys.exit(1)

    total = min(args.max_nodes, len(nodes))
    print(f"共 {len(nodes)} 个节点，测试前 {total} 个（结果默认脱敏）...\n")

    alive = 0
    tested = 0
    blocked = 0
    for idx, (name, server, port) in enumerate(nodes[:total], start=1):
        # 安全合规拦截：命中类别/黑名单/内网地址的节点不发起任何连接
        try:
            sg.check_node(name, server, port)
        except sg.SafetyViolation as e:
            blocked += 1
            print(f"  [{idx:2d}] ⛔ 拦截 {cc.redact_node(name, idx)} "
                  f"[{e.category}] {e.reason}")
            continue
        ok = test_node(server, port, args.timeout)
        tested += 1
        label = cc.redact_node(name, idx)
        endpoint = cc.redact_endpoint(server, port)
        if cc.VERBOSE:
            print(f"  [{idx:2d}] {'✓ 通  ' if ok else '✗ 不通'} {label} ({endpoint})")
        else:
            print(f"  [{idx:2d}] {'✓ 通  ' if ok else '✗ 不通'} {label}")
        alive += int(ok)

    print(f"\n结果: {alive}/{tested} 个节点可达；安全拦截 {blocked} 个（不测试）")
    if blocked:
        print("被拦截节点已写入永久黑名单，后续不再连接")
        sys.exit(3)


if __name__ == "__main__":
    main()
