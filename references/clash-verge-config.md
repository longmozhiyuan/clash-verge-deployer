# Clash Verge Rev 配置参考

> 本参考只描述本机配置结构与本地 API。所有字段均应由脚本动态读取，
> 不要把其中任何敏感值（secret、订阅 URL、节点信息）写入对话、提交或外发。

## 配置目录（跨平台）

| 平台 | 配置目录 |
| --- | --- |
| Windows | `%APPDATA%\io.github.clash-verge-rev.clash-verge-rev\` |
| macOS | `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/` 或 `~/.config/clash-verge/` |
| Linux | `~/.config/clash-verge/` |

可通过环境变量 `CLASH_VERGE_DIR` 显式指定。

## 目录结构

```
<配置目录>/
├── profiles.yaml          # profile 索引文件
├── verge.yaml             # Clash Verge 主设置
├── clash-verge.yaml       # mihomo 运行时配置（自动生成，勿手改）
├── profiles/              # 订阅缓存目录
│   └── <uid>.yaml         # 每个订阅的本地缓存
└── logs/                  # 日志目录
```

## 安全状态目录（部署脚本独立维护，不在 Clash 配置目录内）

位置：Windows `%LOCALAPPDATA%\clash-verge-deployer\`；
macOS `~/Library/Application Support/clash-verge-deployer/`；
Linux `~/.config/clash-verge-deployer/`；可由 `CLASH_DEPLOYER_STATE_DIR` 覆盖。

```
<安全状态目录>/
├── blocklist.txt          # 域名级永久黑名单（自动写入，可查看）
├── blocked-urls.txt       # 链接级永久黑名单（仅路径命中违法类别时）
├── blocked-events.log     # 拦截事件（时间/类别/目标/规则）
├── custom-blocklist.txt   # 用户自定义域名名单（每行一个域名，可选）
└── subscription-hashes.json  # 订阅 SHA-256 指纹（防篡改基线，URL 键脱敏）
```

这些文件记录"接触过哪些可疑链接"，属敏感数据，禁止外发或上传；
拦截规则全部离线生效，不向任何第三方查询。

## 浏览器侧直连规则（assets/direct-domains.txt）

`scripts/make_direct_rules.py` 依据该清单生成 `- DOMAIN-SUFFIX,<域名>,DIRECT` 规则，
覆盖政务、教育、银行、支付、运营商与主流正规站点；用户可自行增删清单行。
`--merge` 合并进订阅时会把同一域名的非 DIRECT 规则改写为 DIRECT，
并自动重跑路由审计确认敏感域名均未走代理。

## 关键配置项

### profiles.yaml

```yaml
current: <uid>              # 当前激活的 profile UID
items:
- uid: <uid>
  type: remote              # remote = 远程订阅
  name: <显示名称>
  file: <uid>.yaml          # 本地缓存文件名
  url: <订阅URL>            # 可能含 token，禁止外发
  updated: <时间戳>
  option:
    allow_auto_update: true
```

### verge.yaml

```yaml
enable_external_controller: true   # 启用本机 REST API（默认端口 9097）
verge_external_controller: 127.0.0.1:9097   # 本机 API 地址（可被用户改）
verge_mixed_port: 7897             # 混合代理端口
secret: <用户配置或为空>            # 本机 API 密钥，可能不存在
```

## 本机 mihomo REST API

- 地址：默认 `http://127.0.0.1:9097`，从 `verge_external_controller` / 运行时配置的 `external-controller` 动态读取，仅监听本机。
- 认证：若配置了 secret，请求头带 `Authorization: Bearer <secret>`；secret 只能从本机配置或环境变量 `CLASH_VERGE_SECRET` 获取，**不存在通用默认值，禁止猜测或硬编码**。

### 常用端点

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/version` | 探活 |
| GET | `/configs` | 获取当前配置 |
| PUT | `/configs?force=true` | 重载配置 |
| GET | `/proxies/GLOBAL` | 获取 GLOBAL 组节点 |
| PUT | `/proxies/GLOBAL` | 切换节点（body: `{"name": "节点名"}`） |
| GET | `/proxies/{name}/delay?url=...&timeout=5000` | 节点延迟测试 |

## 常见问题

### 1. 所有节点显示 error/timeout

**根因**：订阅存在重名节点，mihomo 配置校验失败，Clash Verge 回退到最小配置（仅 DIRECT/REJECT）。

**解决**：运行 `scripts/dedupe_nodes.py` 去重（只动 proxies 段，保留其余配置），再重新部署；或在 `logs/<日期>.log` 中搜索 `duplicate name`（日志可能含节点名，排错时勿外发）。

### 2. 配置修改后被覆盖

**根因**：Clash Verge 重启时会按 `profiles.yaml` 的 `url` 重新下载订阅。

**解决**：使用 `deploy_clash.py --update-url` 同步更新索引中的 URL（脚本会先备份）；或替换 profile 缓存后保持应用不重启、直接在 GUI 中重载。

### 3. API 连接失败 / 401

- 连不上：`enable_external_controller` 为 false，脚本会自动开启（备份后生效，需重启）。
- 401：本机配置了 secret，设置环境变量 `CLASH_VERGE_SECRET` 后重试；不要把 secret 发给任何人。

### 4. raw.githubusercontent.com 无法访问

使用 jsDelivr CDN 镜像：

- 原地址：`https://raw.githubusercontent.com/<user>/<repo>/<branch>/<path>`
- 镜像：`https://fastly.jsdelivr.net/gh/<user>/<repo>@<branch>/<path>`

## 内置公开订阅源（公开仓库，无身份关联）

| 仓库 | CDN URL | 特点 |
| --- | --- | --- |
| zhuhaiuk/free-nodes | `https://fastly.jsdelivr.net/gh/zhuhaiuk/free-nodes@main/clash_config.yaml` | 更新频繁 |
| ermaozi/get_subscribe | `https://fastly.jsdelivr.net/gh/ermaozi/get_subscribe@main/subscribe/clash.yml` | 节点数量多 |
| zipvpn/FreeVPNNodes | `https://fastly.jsdelivr.net/gh/zipvpn/FreeVPNNodes@main/free_clash_nodes.yaml` | 免费节点 |

> 免费公共节点不保证隐私：节点运营方可见目标域名、SNI、DNS 查询等元数据。
> 不要在这类节点上登录网银、支付或敏感工作账号；敏感场景请使用可信私人订阅。
