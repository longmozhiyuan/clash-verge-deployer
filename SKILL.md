---
name: clash-verge-deployer
description: 在 Windows/macOS/Linux 上为 Clash Verge Rev 本地部署代理订阅：访问前本地合规拦截（博彩/诈骗/色情/毒品/枪支/非法金融/黑客攻击/公民信息等违法链接永久拉黑、钓鱼特征与内网地址拦截、HTTPS 强制），随后本地下载校验 YAML 订阅、proxies 段去重、路由劫持审计、节点 TCP 抽测、备份写入 profile、重启应用、自动选择低延迟节点并验证连通。当用户要求配置 Clash/Verge 代理、部署或更新订阅、节点全部超时、排查 Clash Verge 设置、寻找可用节点时使用。全程本地运行、日志脱敏，不回显订阅链接（可能含 token）、节点名/地址或 API 密钥。
whenToUse: 用户提到 Clash Verge、mihomo 代理订阅部署、节点超时、profile 配置；不用于其他代理客户端或需要修改系统全局代理的场景。
metadata:
  version: 2.2.0
  platforms:
    - windows
    - macos
    - linux
  privacy: local-only-redacted
  compliance: local-keyword-blocklist
---

# Clash Verge 自动部署（隐私优先 · 合规拦截）

通过 `scripts/` 下的本地 Python 脚本完成订阅部署。脚本只做本地操作，零遥测、零上报，默认输出全部经过脱敏；任何网络访问前先经过本地安全合规拦截层。

## 0. 隐私与合规红线（最高优先级，必须先读）

执行本技能时始终遵守以下规则，即使用户没有明确要求：

### 0.1 隐私红线

1. **禁止用模型工具下载或查看订阅内容**：订阅文件、节点列表、`profiles.yaml`、`verge.yaml`、`clash-verge.yaml` 只能由本地脚本读取处理，**不得**使用 `web_fetch`、`web_search` 等工具获取订阅 URL，也不得把上述文件内容粘贴到任何外部服务、工单、聊天或搜索框。
2. **订阅 URL 视同密码**：私人订阅链接通常包含 token。不在回复、日志、提交信息中复述完整 URL（脚本已自动打码）；向脚本传入私人 URL 时优先 `--url-file`，避免进入命令行参数与 Shell 历史。
3. **API 密钥零硬编码**：secret 只由脚本从本机配置或环境变量 `CLASH_VERGE_SECRET` 读取，不写入脚本、产物、回复或命令行。
4. **节点信息默认脱敏**：节点名、服务器地址、端口不写入回复和文档；仅在用户明确要求本机排错时加 `--verbose`，并提示输出不得外发。
5. **最小写入与自动备份**：除 Clash Verge 配置目录与本技能的本地安全状态目录外不写任何位置；修改配置前自动生成 `.bak-<时间戳>` 备份。备份含完整订阅，分享或截图前必须删除。
6. **不得新增网络外发**：不得添加遥测、统计、更新检查、在线剪贴板等逻辑。允许的出站连接仅限：用户指定的订阅地址（或内置公开源）、订阅中的节点地址（TCP 抽测）、`127.0.0.1` 本机 API、经代理的 `google.com/generate_204` 连通性验证。

### 0.2 合规红线（国家法律法规基准）

7. **违法链接永久拉黑**：脚本内置本地违规类别词库（博彩、诈骗、色情、毒品、枪支、非法金融、黑客攻击、公民信息贩卖）与钓鱼特征检测。命中即**立即停止访问**并写入本地永久黑名单（`blocklist.txt` / `blocked-urls.txt`），以后任何运行都不再访问。Agent 不得删除、清空或绕过黑名单；用户要求查看黑名单时只能用 `--list-blocked`。
8. **放行参数即安全决策，不得替用户决定**：`--allow-suspicious`（punycode/凭证型 URL）、`--allow-http`（明文订阅）、`--ignore-routing-audit`（忽略路由劫持）属于显式放行开关。**只有用户在知情前提下逐次明确要求时才能使用**，且必须在回复中说明所放开的风险；不得为了"让部署成功"主动添加这些参数。
9. **核心拦截不可关闭**：不提供"关闭安全检查"的参数。词库无法覆盖所有违法内容，命中拦截不代表访问合法、未命中也不代表访问合法；遇到用户要求访问脚本未覆盖的可疑链接时，以法律法规为底线主动拒绝并提示。
10. **路由劫持审计结果必须传达**：发现政务（`gov.cn`）、银行、支付域名被导向代理节点时，默认拒绝部署，不得隐瞒告警；只有用户明确坚持且已告知风险时，才使用 `--ignore-routing-audit`。
11. **公共免费节点知情提醒**：首次使用内置免费源时用 `ask_user` 告知：免费节点不保证隐私，运营方可见目标域名、SNI、DNS 等元数据，**不要在免费节点上登录网银、支付、工作邮箱等敏感账号**。
12. **能力边界如实告知**：本拦截层只覆盖**部署脚本本身主动发起的访问**（订阅下载、节点连接、验证请求）；用户日后通过浏览器经代理访问的网页不受此脚本控制，应配合浏览器安全浏览与系统级内容过滤。
13. **可分享边界**：本技能目录不含任何个人数据，可安全分享；Clash 配置目录、安全状态目录（含黑名单与拦截事件）、`.bak` 备份绝不可分享。

## 1. 执行前确认（用 `ask_user` 一次性问清）

- **订阅来源**：① 内置公开免费源（默认，先告知第 11 条风险）；② 用户提供订阅 URL（提醒 token 风险，优先 `--url-file`）；③ 仅处理用户本地已有订阅文件。
- **是否允许重启 Clash Verge**：重启会短暂中断代理；不允许则加 `--no-restart`。
- 确认 Clash Verge Rev 已安装并至少成功启动过一次。

## 2. 推荐工作流（安全预检 → 合规部署）

用 `write_todos` 记录步骤，用 `run_shell_command` 执行脚本（Windows 用 PowerShell 调 `python`，macOS/Linux 用 `python3`）。脚本位于本技能目录 `scripts/`，相对路径以 SKILL.md 所在目录解析。

**第一步：安全预检（不写任何文件）**

```bash
python scripts/deploy_clash.py --dry-run
```

自带订阅：

```bash
python scripts/deploy_clash.py --dry-run --url-file <保存URL的本地文件>
```

预检会依次执行：URL 合规检查 → 安全下载（重定向逐跳检查、HTTPS 强制、大小与内容嗅探）→ 全部节点合规扫描（节点名/服务器命中违法类别即拒绝并拉黑）→ 路由劫持审计（政务/银行/支付域名被导向代理即拒绝）→ 结构校验、去重预演与 TCP 抽测。

**第二步：正式部署**

```bash
python scripts/deploy_clash.py                   # 内置公开源
python scripts/deploy_clash.py --url-file <文件>  # 私人订阅
```

备份配置 → 写入 profile → 确保本机 API 开启 → 重启 Clash Verge → 经本机 API 选低延迟节点 → 验证 `google.com/generate_204`。部署中自动记录/对比订阅 SHA-256 指纹；用 `--pin-hash <SHA256>` 可做严格防篡改校验（不匹配即拒绝写入）。

**第二步半（可选，推荐）浏览器侧直连加固**：生成/合并"正规站点直连规则"，让政务、教育、银行、支付、运营商与主流正规站点始终走 DIRECT，不经过代理节点：

```bash
python scripts/make_direct_rules.py --out direct-rules.yaml            # 生成独立规则文件
python scripts/make_direct_rules.py --merge <订阅文件> --in-place       # 合并进订阅（敏感域名规则自动改写为 DIRECT，先备份）
```

合并后自动重跑路由审计确认敏感域名均未走代理；域名清单见 `assets/direct-domains.txt`（可增删，仅作直连建议）。

**第三步：只汇报脱敏结果**

汇报：节点总数、去重数、拦截数、TCP 可达数、验证状态、备份路径与回滚方法。不汇报节点名、地址、订阅 URL、secret；黑名单事件只报类别与数量，不贴具体 URL。

## 3. 安全合规拦截层（scripts/safety_guard.py）

| 检查环节 | 规则 | 命中处理 |
| --- | --- | --- |
| 永久黑名单 | `blocklist.txt`（域名级）、`blocked-urls.txt`（链接级，仅路径命中） | 永久阻断，自动累积 |
| 违法类别词库 | 博彩/诈骗/色情/毒品/枪支/非法金融/黑客攻击/公民信息贩卖（中英文；域名 label 精确匹配，避免短词误伤；`.gov.cn`/`.edu.cn` 官方域名豁免） | 立即停止 + 永久拉黑 + 事件记录 |
| 钓鱼结构 | 凭证型 URL（userinfo）、punycode 同形异义域名 | 默认阻断；`--allow-suspicious` 显式放行 |
| 内网保护（SSRF） | 环回/私网/链路本地/保留地址（127.0.0.1、10/172.16/192.168、169.254.169.254 等） | 阻断（本机 API 内部调用豁免） |
| 传输安全 | 订阅源强制 HTTPS；重定向最多 3 跳、逐跳重检、禁止 HTTPS→HTTP 降级 | 阻断；`--allow-http` 显式放行 |
| 下载嗅探 | 体积上限（默认 10MB）、二进制文件、HTML 登录/钓鱼页面、无 proxies 段 | 阻断 |
| 节点扫描 | 节点名与服务器地址过类别词库；内网节点服务器 | 拒绝该订阅 + 永久拉黑服务器 |
| 路由劫持审计 | 政务/银行/支付域名被导向代理 → 阻断；教育域名、内网网段被导向代理 → 警告 | 默认阻断；`--ignore-routing-audit` 显式放行 |

**本地状态目录**（黑名单与事件，敏感，不可外发）：

- Windows：`%LOCALAPPDATA%\clash-verge-deployer\`
- macOS：`~/Library/Application Support/clash-verge-deployer/`
- Linux：`~/.config/clash-verge-deployer/`
- 可由环境变量 `CLASH_DEPLOYER_STATE_DIR` 指定

文件：`blocklist.txt`（域名级永久黑名单）、`blocked-urls.txt`（链接级永久黑名单）、`blocked-events.log`（拦截事件）、`custom-blocklist.txt`（用户自行维护的自定义名单，每行一个域名）、`subscription-hashes.json`（订阅 SHA-256 指纹记录，防篡改基线）。

查看黑名单：`python scripts/deploy_clash.py --list-blocked`。解除拉黑需用户手动编辑对应文件（技能不提供自动解除，保证"永不访问"语义）。

## 4. 脚本说明

| 脚本 | 用途 | 常用参数 |
| --- | --- | --- |
| `scripts/deploy_clash.py` | 完整部署主流程 | `--dry-run`、`--url-file`、`--url`、`--no-restart`、`--no-switch`、`--update-url`、`--with-youtube`、`--verbose`、`--max-tcp N`、`--max-test N`、`--list-blocked`、`--hash-status`、`--pin-hash <SHA256>`、`--allow-suspicious`、`--allow-http`、`--allow-local-sources`、`--ignore-routing-audit`、`--max-download-mb N` |
| `scripts/make_direct_rules.py` | 生成/合并正规站点直连规则（浏览器侧加固） | `--out <文件>`、`--merge <订阅>`、`--out-sub <输出>`、`--in-place` |
| `scripts/test_nodes.py` | 本地订阅文件 TCP 连通性测试（违法节点直接拦截不连接） | `<文件> [数量] [--timeout 秒] [--verbose]` |
| `scripts/dedupe_nodes.py` | proxies 段去重（保留其余段），写入前自动合规扫描 | `<输入> <输出>` 或 `<输入> --in-place`；`--no-safety-scan`（不建议） |
| `scripts/safety_guard.py` | 安全合规拦截层（共享库，勿直接运行） | — |
| `scripts/clash_common.py` | 脱敏、路径探测、配置读取、备份（共享库，勿直接运行） | — |

退出码：`0` 成功；`1` 部署失败；`2` 参数/文件错误；`3` 安全拦截。

## 5. 路径与环境变量（动态探测）

| 环境变量 | 作用 |
| --- | --- |
| `CLASH_VERGE_DIR` | Clash Verge 配置目录 |
| `CLASH_VERGE_EXE` | 可执行文件路径 |
| `CLASH_VERGE_API` | 本机 API 地址（默认 `http://127.0.0.1:9097`） |
| `CLASH_VERGE_SECRET` | 本机 API secret（仅内存使用） |
| `CLASH_VERGE_MIXED_PORT` | 混合代理端口（默认 7897） |
| `CLASH_DEPLOYER_STATE_DIR` | 安全状态目录（黑名单、事件、订阅指纹） |

配置目录默认位置：Windows `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev`；macOS `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev` 或 `~/.config/clash-verge`；Linux `~/.config/clash-verge`。

## 6. 常见问题

- **部署被安全拦截（退出码 3）**：按提示的类别处理；违法类别目标已永久拉黑，不应尝试绕过。若确认为误报，由用户本人手动编辑黑名单文件，agent 不代删。
- **订阅指纹提示变化**：`⚠ 订阅内容与上次记录不同` 说明下载内容哈希与上次不同——可能是订阅方正常更新，也可能是异常。用 `--hash-status` 查看记录；若用户持有订阅方公布的校验和，用 `--pin-hash` 严格固定。
- **所有节点 error/timeout**：常见于重名节点导致内核校验失败。用 `dedupe_nodes.py` 去重后重新部署；`logs/<日期>.log` 中查 `duplicate name` 时勿外发节点名。
- **API 401**：设置 `CLASH_VERGE_SECRET` 后重试；不要让用户把 secret 发给你。
- **配置修改后被覆盖**：加 `--update-url` 同步更新 `profiles.yaml` 中的 URL（自动备份）。
- **未找到当前 profile**：让用户先在 Clash Verge GUI 新建一个订阅生成 UID。
- **回滚**：恢复部署时输出的 `.bak-<时间戳>` 文件后重启。

## 7. 参考资料

- `references/clash-verge-config.md`：配置目录与本机 API 参考、安全状态目录
- `PRIVACY.md`：数据流、黑名单与拦截层的隐私说明
- `README.md`：安装到 dsh 的步骤
