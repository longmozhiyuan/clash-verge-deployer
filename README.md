# clash-verge-deployer（DeepSeek Harness 版）

为 [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) 自动部署代理订阅的 DeepSeek Harness（dsh）技能：
访问前本地合规拦截（违法链接永久拉黑）→ 安全下载校验订阅 → 路由劫持审计 → proxies 段去重 → TCP 抽测 → 备份写入 → 重启应用 → 自动选择低延迟节点 → 验证连通。

**隐私优先 · 合规底线**：零遥测、零上报、离线规则库、默认日志脱敏（订阅链接/节点名/地址/secret 均不回显）。详见 [PRIVACY.md](PRIVACY.md)。

## 安全合规拦截层

任何网络访问前在本地执行（`scripts/safety_guard.py`，全程离线，不调用任何第三方查询）：

- **永久黑名单**：博彩、诈骗、色情、毒品、枪支、非法金融、黑客攻击、公民信息贩卖等违法类别（中英文规则库）命中即立即停止并永久拉黑，区分域名级与链接级（不牵连整域）；
- **钓鱼特征**：凭证型 URL、punycode 同形异义域名、内网/保留地址（SSRF）一律拦截；
- **传输安全**：订阅源强制 HTTPS；重定向逐跳检查、最多 3 跳、禁止 HTTPS→HTTP 降级；
- **下载嗅探**：体积上限（默认 10MB）、拒绝二进制与伪装成订阅的钓鱼 HTML 页面；
- **节点与路由审计**：节点名/服务器违法特征拦截、内网节点拒绝；政务（gov.cn）/银行/支付域名被导向代理时拒绝部署，教育域名/内网网段告警。

> 边界：拦截层只覆盖部署脚本主动发起的访问，不控制日后浏览器上网内容。

## 目录结构

```
clash-verge-deployer/
├── SKILL.md                          # dsh 技能入口（frontmatter + 隐私与合规红线 + 操作指引）
├── README.md                         # 本文件
├── PRIVACY.md                        # 数据流与隐私说明
├── scripts/
│   ├── clash_common.py               # 共享库：脱敏 / 跨平台探测 / 配置读取 / 备份
│   ├── safety_guard.py               # 安全合规拦截层：黑名单 / 词库 / 安全下载 / 路由审计 / 订阅指纹
│   ├── deploy_clash.py               # 主部署流程
│   ├── make_direct_rules.py          # 浏览器侧直连规则生成 / 合并（v2.2）
│   ├── test_nodes.py                 # 节点 TCP 连通性测试（违法节点不连接）
│   └── dedupe_nodes.py               # proxies 段去重（写入前合规扫描）
├── assets/
│   └── direct-domains.txt            # 直连域名清单（gov/edu/银行/支付/运营商等，可增删）
└── references/
    └── clash-verge-config.md         # 配置目录、本机 API 与安全状态目录参考
```

## 前置条件

- Python 3.8+（仅标准库，无需 pip 安装依赖）；
- 已安装 Clash Verge Rev 并至少成功启动过一次；
- Windows / macOS / Linux 均可。

## 安装到 DeepSeek Harness

dsh 按固定技能根扫描，目录 bundle 必须是 `<技能根>/<技能名>/SKILL.md`，只扫描一层，技能名必须为 kebab-case。

### 方式 A：用户级（所有项目可用，推荐）

| 平台 | 目标目录 |
| --- | --- |
| Windows | `%USERPROFILE%\.dsh\skills\` |
| macOS / Linux | `~/.dsh/skills/` |

PowerShell（Windows）：

```powershell
$dst = "$env:USERPROFILE\.dsh\skills\clash-verge-deployer"
New-Item -ItemType Directory -Force $dst | Out-Null
Copy-Item -Recurse -Force .\clash-verge-deployer\* $dst
```

bash（macOS / Linux）：

```bash
mkdir -p ~/.dsh/skills
cp -r clash-verge-deployer ~/.dsh/skills/
```

### 方式 B：项目级（仅当前项目）

把 `clash-verge-deployer/` 整个目录复制到项目根的 `.dsh/skills/` 下：

```
<项目根>/.dsh/skills/clash-verge-deployer/SKILL.md
```

### 验证安装

新开会话后直接问 dsh："列出当前会话可用的技能"。目录中应出现
`clash-verge-deployer`，随后说"帮我部署 Clash Verge 订阅"即可触发。

## 快速开始

```bash
# 1) 预检（不写任何配置，推荐先跑）
python scripts/deploy_clash.py --dry-run

# 2) 正式部署（内置公开源；首次使用会提示公共节点隐私风险）
python scripts/deploy_clash.py

# 3) 私人订阅：把订阅链接保存到本地文件后部署（链接不进命令行历史）
python scripts/deploy_clash.py --url-file $HOME/.config/clash-sub-url.txt

# 4) 仅去重 / 仅测连通性（对本地订阅文件操作，自动过合规扫描）
python scripts/dedupe_nodes.py subscription.yaml fixed.yaml
python scripts/test_nodes.py fixed.yaml 30

# 5) 查看永久黑名单与拦截事件 / 查看订阅指纹记录
python scripts/deploy_clash.py --list-blocked
python scripts/deploy_clash.py --hash-status

# 6) 浏览器侧直连加固（可选，推荐）：让政务/教育/银行/支付等正规站点始终直连
python scripts/make_direct_rules.py --out direct-rules.yaml             # 生成独立规则
python scripts/make_direct_rules.py --merge subscription.yaml --in-place  # 合并进订阅并自动审计

# 7) 订阅内容严格防篡改（可选）：持有订阅方公布的 SHA-256 校验和时固定
python scripts/deploy_clash.py --url-file $HOME/.config/clash-sub-url.txt --pin-hash <SHA256>
```

退出码：`0` 成功；`1` 部署失败；`2` 参数/文件错误；`3` 安全拦截（命中黑名单或违法类别）。

## 可选环境变量

| 变量 | 作用 |
| --- | --- |
| `CLASH_VERGE_DIR` | 显式指定配置目录 |
| `CLASH_VERGE_EXE` | 显式指定可执行文件路径 |
| `CLASH_VERGE_API` | 本机 API 地址（默认 `http://127.0.0.1:9097`） |
| `CLASH_VERGE_SECRET` | 本机 API secret（仅内存使用，不记录） |
| `CLASH_VERGE_MIXED_PORT` | 混合代理端口（默认 7897） |
| `CLASH_DEPLOYER_STATE_DIR` | 安全状态目录（黑名单、拦截事件、订阅指纹） |

## 安全放行参数（谨慎使用）

以下开关仅在确认误报、且用户知情时使用，核心违法类别拦截与黑名单**不可关闭**：

| 参数 | 放开的检查 |
| --- | --- |
| `--allow-suspicious` | punycode 域名、凭证型 URL 等结构特征 |
| `--allow-http` | 明文 HTTP 订阅源（有篡改风险） |
| `--allow-local-sources` | 本机(127.0.0.1)与 RFC1918 私网订阅源（自建内网源；元数据地址仍拦截） |
| `--ignore-routing-audit` | 政务/银行/支付域名路由劫持阻断 |
| `--max-download-mb N` | 调整订阅下载体积上限（默认 10MB） |

## 订阅指纹防篡改（v2.2）

每次部署都会计算订阅内容的 SHA-256 并记录到 `<安全状态目录>/subscription-hashes.json`（URL 已脱敏）：

- 首次部署 → 记录指纹；
- 内容与上次一致 → 静默通过；
- 内容变化 → 打印 `⚠ 订阅内容与上次记录不同`，可能是订阅方正常更新，也可能被篡改；
- `--pin-hash <SHA256>` → 严格校验，不匹配即拒绝写入（防止中间人替换订阅）。

`--hash-status` 查看全部记录（SHA-256 只显示前 24 位）。

## 维护黑名单

- 黑名单位置：`<安全状态目录>/blocklist.txt`（域名级）、`blocked-urls.txt`（链接级）；
- 用户可在 `custom-blocklist.txt` 每行一个域名加入自定义永久拉黑；
- 技能不提供自动解除拉黑（保证"永不访问"），确认误报时由用户手动编辑。

## 相比旧版的隐私、合规与可靠性修复

- **新增本地安全合规拦截层**：违法类别（博彩/诈骗/色情/毒品/枪支/非法金融/黑客/公民信息）链接命中即永久拉黑、访问前拦截；钓鱼特征、SSRF 内网地址、HTTPS 强制、重定向逐跳检查、下载内容嗅探、订阅路由劫持审计；
- **新增浏览器侧直连规则（v2.2）**：一键生成/合并"正规站点直连"规则，政务、教育、银行、支付、运营商与主流正规站点不经过代理节点，降低敏感流量被节点窥探与路由劫持风险；
- **新增订阅指纹防篡改（v2.2）**：自动记录订阅 SHA-256 指纹、内容变化即告警，支持 `--pin-hash` 严格校验；
- **移除硬编码 API secret**，改为运行时从本机配置/环境变量动态读取，不打印、不落盘；
- **日志默认脱敏**：订阅 URL（query 与路径 token）、节点名、服务器地址、UID 全部掩码；
- **订阅 URL 支持 `--url-file` / `--url-stdin`**，避免进入命令行参数与 Shell 历史；
- **移除硬编码安装路径**，跨平台自动探测配置目录与可执行文件（含运行进程/注册表）；
- **修复去重损坏配置的缺陷**：旧版去重会丢掉 proxies 段以外的全部配置（groups/rules 等），新版只处理 proxies 段；
- **修复节点提取漏匹配**：type 等字段不再阻断 name/server/port 解析；
- **兼容带 BOM 的订阅文件**，避免顶层段解析失败；
- **修改前自动备份** `profiles.yaml` / profile 缓存 / `verge.yaml`，并提示回滚；
- 连通性验证默认只发轻量 `generate_204` 请求，YouTube 验证改为显式 `--with-youtube`；
- 无任何遥测/统计/自动更新网络请求，安全拦截层亦完全离线运行。

## 卸载

删除技能目录即可（例如 `~/.dsh/skills/clash-verge-deployer`），不会留下任何系统改动。
Clash Verge 配置目录中的 `.bak-*` 备份确认无用后可手动删除。
