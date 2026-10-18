# 隐私与数据流说明

本技能为本地配置工具，所有脚本均为纯 Python 标准库实现，可逐行审查。
**不包含任何遥测、统计、崩溃上报、自动更新或云端配置拉取逻辑。**
安全合规拦截层（`safety_guard.py`）同样**完全离线运行**：规则词库内置在本地，
不向任何"安全检测 API"或第三方查询 URL，不做任何在线信誉查询。

## 一、出站连接清单（白名单）

脚本只可能发起以下网络连接，且全部是完成部署所必需的：

| 目标 | 发起者 | 目的 | 携带的数据 |
| --- | --- | --- | --- |
| 用户指定的订阅 URL，或 3 个内置 jsDelivr 公开源 | `deploy_clash.py` | 下载订阅 YAML（访问前先过本地合规拦截） | 通用 User-Agent，无个人标识、无 Cookie |
| 订阅中的节点服务器地址 | 节点扫描 + TCP 抽测 | 合规检查后判断端口是否可达 | 仅一次 TCP 握手，不发送应用数据 |
| `127.0.0.1` 本机 API（默认 9097） | 节点查询/切换/延迟测试 | 与本机 mihomo 内核通信 | 不出本机 |
| `www.google.com/generate_204`（经本地代理） | 连通性验证 | 确认代理可用 | 单次 HTTPS 请求 |
| `www.youtube.com`（仅加 `--with-youtube` 时） | 可选连通性验证 | 同上 | 单次 HTTPS 请求 |

除以上地址外不连接任何服务器；命中黑名单/违法类别/钓鱼特征的目标**根本不会发起连接**。
你可以在脚本中搜索 `urlopen` / `socket` / `subprocess` 自行核对。

## 二、日志脱敏规则

默认模式下，终端输出**不包含**：完整订阅链接、节点名、服务器地址、API secret。

| 原始内容 | 默认显示 | 明文模式（`--verbose`） |
| --- | --- | --- |
| `https://sub.airport.io/api/sub?token=abc123...` | `https://sub.airport.io/api/sub?***` | 原样显示 |
| 路径中的 `dl/AAAA1111BBBB2222/clash.yml` | `dl/***/clash.yml` | 原样显示 |
| 节点名 `香港-专线-01` | `节点#01(6cffb1)`（序号+短哈希） | 原样显示 |
| 节点地址 `1.2.3.4:443` | `1.2.x.x:443` | 原样显示 |
| 节点域名 `node.tokyo.example.com:8443` | `*.example.com:8443` | 原样显示 |
| profile UID | `abcdef***` | 原样显示 |

`--verbose` 仅用于本机排错，输出请勿截图、粘贴到外部网站或发给他人。

## 三、订阅 URL（含 token）的保护

私人订阅链接等同于密码：任何拿到链接的人都能下载你的全部节点。

- 脚本日志对 URL 自动打码；
- 推荐用 `--url-file <本地文件>` 传入 URL，避免链接出现在命令行参数、PowerShell 历史（`ConsoleHost_history.txt`）和进程列表中；
- 脚本不会把 URL 写入除 `profiles.yaml`（Clash Verge 自身需要）之外的任何位置。

## 四、API secret 的处理

- 旧版技能硬编码了占位密钥，**新版已彻底移除**；
- secret 只在运行时从本机 `verge.yaml`、运行时配置或环境变量 `CLASH_VERGE_SECRET` 读取，仅保存在内存中，不打印、不落盘、不写入任何产物；
- 若本机未设置 secret（仅监听 127.0.0.1，风险可控），脚本以无认证方式调用本机 API。

## 五、文件修改与备份

脚本仅修改 Clash Verge 配置目录内的 3 类文件，且修改前在同目录生成
`<文件名>.bak-<时间戳>` 备份：

1. `profiles/<uid>.yaml`（profile 缓存）；
2. `profiles.yaml`（仅 `--update-url` 时）；
3. `verge.yaml`（仅在本机 API 未启用时开启开关）。

**备份文件包含完整订阅内容，请勿外发；**确认新配置可用后可自行删除 `.bak-*` 文件。

下载的订阅内容只在内存中处理，落地位置仅限 Clash Verge 自己的 profile 缓存目录，不会写入技能目录，因此**分享整个技能文件夹不会泄露任何订阅信息**。

## 六、安全状态目录与黑名单（本地、敏感）

合规拦截层在本机状态目录维护以下文件：

| 文件 | 内容 |
| --- | --- |
| `blocklist.txt` | 域名级永久黑名单（主机名命中违法类别时自动写入，含其子域） |
| `blocked-urls.txt` | 链接级永久黑名单（仅路径命中类别时写入，不牵连整域） |
| `blocked-events.log` | 每次拦截的时间、类别、目标、命中规则（仅本机留存） |
| `custom-blocklist.txt` | 用户自行维护的自定义域名名单（每行一个域名） |
| `subscription-hashes.json` | 订阅内容 SHA-256 指纹记录（防篡改基线；URL 键已脱敏，哈希仅显示前 24 位） |

位置：Windows `%LOCALAPPDATA%\clash-verge-deployer\`；
macOS `~/Library/Application Support/clash-verge-deployer/`；
Linux `~/.config/clash-verge-deployer/`；可用 `CLASH_DEPLOYER_STATE_DIR` 覆盖。

要点：

- 这些文件是"接触过哪些可疑链接"的记录，属于敏感数据，与订阅内容同等保护，**禁止外发、截图或上传**；
- 黑名单只在本机参与匹配，永不上传；拦截层**不联网**、不调用任何在线信誉/预警接口，规则词库随技能分发、可逐行审计；
- `subscription-hashes.json` 记录的是订阅内容哈希（不可逆）与脱敏后的 URL 键，用于检测订阅被替换/篡改；`--hash-status` 只显示哈希前 24 位；
- 不提供自动解除或清空功能（保证"永不访问"语义）；用户可手动编辑文件；
- 拦截规则不覆盖用户日后浏览器的上网行为，能力边界以 SKILL.md 第 0.2 节为准。

## 七、公共免费节点的风险

内置订阅源来自公开 GitHub 仓库，节点由不相关的第三方运营：

- 节点运营方可见你访问的目标域名、TLS SNI、DNS 查询等元数据（HTTPS 下看不到具体内容）；
- 节点质量参差不齐，可能记录、篡改或劫持明文流量；
- **不要**在免费公共节点上登录网银、支付、工作邮箱、公司内网等敏感账号；
- 敏感用途请使用你自己付费、可信的订阅服务，并通过 `--url-file` 部署。

## 八、安全检查清单（分享/上传本技能前）

- [x] 技能目录中无任何本机用户名、绝对用户路径（统一使用环境变量与 `~` 探测）；
- [x] 无任何 secret、token、订阅 URL 个人参数（内置源为公开仓库地址）；
- [x] 无 `.bak` 备份、日志、下载的订阅文件、黑名单与拦截事件（这些只写入用户级状态目录）；
- [x] `subscription-hashes.json` 只存在于用户级状态目录，不在技能包内；
- [x] 可安全分享：`SKILL.md`、`scripts/`、`assets/direct-domains.txt`（公开站点清单）、`references/`、`README.md`、`PRIVACY.md`；
- [ ] 绝不可分享：Clash Verge 配置目录、`profiles/`、`*.bak-*`、`logs/`、安全状态目录（`blocklist.txt`、`blocked-urls.txt`、`blocked-events.log`、`subscription-hashes.json`）。

## 九、依赖与权限

- 仅依赖 Python 3.8+ 标准库，无需安装第三方包；
- 重启 Clash Verge 时会调用系统进程管理命令（Windows `taskkill`、macOS/Linux `pkill`），作用对象仅限 Clash Verge / mihomo 自身进程；
- 不请求管理员/root 权限；不修改系统注册表、系统代理设置或防火墙规则。
