**中文** | [English](./README.en.md)

# Bitwarden Workers

> Bitwarden Server API 的 Cloudflare Workers 实现，完全兼容官方 Bitwarden 客户端（Web、桌面、浏览器扩展、移动端）。
>
> 零服务器、零运维。当前默认配置使用 Workers Paid（最低 $5 USD/月），并可在各产品包含额度内运行个人/家庭密码管理器。
>
> 所有密码库数据由客户端端到端加密后存储于 [Cloudflare D1](https://developers.cloudflare.com/d1/)——服务端只保存密文，即使数据库泄露也无法还原明文。D1 自身还提供 AES-256-GCM 静态加密（encryption at rest）和 TLS 传输加密，密钥由 Cloudflare 基础设施托管，无需额外配置。D1 每小时自动创建备份，支持还原到 30 天内的任意时间点——即使误操作清空了全部数据，也可以通过 Cloudflare Dashboard 或 `wrangler d1 time-travel` 一键回滚恢复。

## 功能概览

| 模块 | 端点 | 说明 |
|------|------|------|
| Identity | `/identity/*` | 注册、登录、Token 颁发、WebAuthn/FIDO2 认证 |
| Accounts | `/api/accounts/*` | 用户资料、密钥管理、主密码修改 |
| Sync | `/api/sync` | 全量数据同步 |
| Ciphers | `/api/ciphers/*` | 密码条目 CRUD、批量操作、附件、分享 |
| Folders | `/api/folders/*` | 文件夹管理 |
| Organizations | `/api/organizations/*` | 组织/成员/集合/群组/策略管理 |
| Collections | `/api/collections/*` | 集合管理 |
| Two-Factor | `/api/two-factor/*` | 2FA 设置（TOTP、WebAuthn 等） |
| WebAuthn | `/api/webauthn/*` | 通行密钥注册与认证 |
| Auth Requests | `/api/auth-requests/*` | 免密码登录审批 |
| Sends | `/api/sends/*` | Bitwarden Send（加密文本/文件分享） |
| Devices | `/api/devices/*` | 登录设备管理 |
| Events | `/api/events/*` | 审计日志 |
| Emergency Access | `/api/emergency-access/*` | 紧急访问 |
| Settings | `/api/settings/*` | 等价域名等用户设置 |
| Reports | `/api/reports/*` | 组织安全报告 |
| Icons | `/{hostname}/icon.png` | 网站图标抓取与缓存（跨用户复用） |
| Notifications | `/notifications/hub` | 实时推送（WebSocket / Durable Objects） |
| Config | `/api/config` | 服务端配置 |
| Tasks | `/api/tasks/*` | 定时任务管理 |
| Org Licenses | `/api/organizations/licenses/*` | 自建组织许可证 |
| Attachments | `/attachments/:cipherId/:attachmentId` | 附件下载 |

## 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | [Cloudflare Workers](https://workers.cloudflare.com/) |
| Web 框架 | [Hono](https://hono.dev/) |
| 数据库 | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) |
| ORM | [Drizzle ORM](https://orm.drizzle.team/) |
| 对象存储 | [Cloudflare R2](https://developers.cloudflare.com/r2/)（附件） |
| 缓存 | [Cloudflare KV](https://developers.cloudflare.com/kv/)（Icons） + Edge Cache |
| 实时通知 | [Durable Objects](https://developers.cloudflare.com/durable-objects/)（WebSocket） |
| 定时任务 | [Cron Triggers](https://developers.cloudflare.com/workers/configuration/cron-triggers/) |
| 认证 | JWT (HMAC-SHA256) |
| 加密 | Web Crypto API / PBKDF2-SHA256 |

---

## Cloudflare 使用与费用

本项目使用多个 Cloudflare Developer Platform 产品。以下内容按 **2026-07-10** 的官方价格说明整理；Cloudflare 可能调整套餐、额度和价格，部署前请以链接中的官方文档为准。

### 当前默认配置

当前仓库的生产部署应使用 **Workers Paid**：

- `wrangler.toml` 中的 `NotificationHub` 使用 `new_classes`，即 KV 存储后端的 Durable Object。该后端仅支持 Workers Paid；Workers Free 只支持 SQLite 存储后端的 Durable Objects。
- GitHub Actions 在未设置 `EMAIL_MODE` 时默认使用 `cloudflare`。通过 Cloudflare Email Service 向任意收件人发送邮件要求 Workers Paid。
- Workers Paid 当前最低账户费用为 **$5 USD/月**。D1、KV、Durable Objects、Queues、日志等产品包含一定用量，超出后可能按量收费。

如果是**从未部署过 Durable Object 的全新环境**，可以把首次迁移设计为 `new_sqlite_classes` 并禁用 Cloudflare Email Sending，从而尝试在 Workers Free 的限额内运行。已经部署的 `new_classes` 不能通过修改历史迁移直接切换存储后端，应新建类并迁移，或在确认可以丢失通知状态后重建。

### 使用的产品

| Cloudflare 产品 | 本项目用途 | 当前套餐与费用说明 |
|-----------------|------------|--------------------|
| Workers + Static Assets | API、Web Vault、Cron 入口 | 当前使用 Paid；静态资源请求免费且不限量，动态 Worker 请求和 CPU 使用量计入 Workers 套餐 |
| D1 | 用户、密码库密文、组织及认证数据 | Paid 每月包含 250 亿行读取、5,000 万行写入和 5 GB 存储；超额按量收费，无数据传出费用 |
| R2 Standard | 附件和 Send 文件 | 每月免费额度为 10 GB-month、100 万次 Class A、1,000 万次 Class B；超额按量收费，公网传出免费 |
| Workers KV | 网站图标缓存 | Paid 每月包含 1,000 万次读取、100 万次写入/删除、1 GB 存储；超额按量收费 |
| Durable Objects | SignalR 兼容 WebSocket 通知 Hub | 当前 KV 后端要求 Paid；Paid 每月包含 100 万请求和 400,000 GB-s，超额按量收费 |
| Queues | Web Push 持久化重试和死信队列 | 需要主队列和 DLQ；Paid 每月包含 100 万次操作，超额 $0.40/百万次操作 |
| Cron Triggers | 清理过期 Send、Cipher 和 Refresh Token | 调用计入 Workers 请求与 CPU 用量，不需要单独服务器 |
| Workers Logs / Traces | 请求日志、错误和链路追踪 | Paid 包含日志/追踪事件额度；当前日志采样率为 100%，Trace 采样率为 10%，高流量部署应按需降低 |
| Email Service | 邀请、验证码和安全通知邮件 | 任意收件人发送要求 Paid；每月包含 3,000 封，之后 $0.35/1,000 封。设置 `EMAIL_MODE=disabled` 可完全禁用 |

官方价格文档：[Workers](https://developers.cloudflare.com/workers/platform/pricing/)、[D1](https://developers.cloudflare.com/d1/platform/pricing/)、[R2](https://developers.cloudflare.com/r2/pricing/)、[Email Service](https://developers.cloudflare.com/email-service/platform/pricing/)。

建议在 Cloudflare Dashboard 中为 Workers、D1、R2、KV、Queues 和 Email 设置用量监控。Workers Paid 超出包含额度后可能产生额外费用；Workers Free 则通常在达到产品限额后拒绝后续操作。

---

## 快速开始

### 前置条件

- Node.js >= 22（Wrangler 4.x 要求）
- npm
- [Cloudflare 账户](https://dash.cloudflare.com/sign-up)；当前默认配置需要 Workers Paid

### 本地开发

```bash
npm install
npm run db:generate
npm run db:migrate:local
npm run dev
```

本地服务默认运行在 `http://localhost:8787`。

---

## 部署

提供两种方式：**手动部署** 和 **GitHub Actions 自动部署**。推荐长期使用 GitHub Actions，因为它会同时构建 `clients` Web Vault 静态文件、运行 Workers 检查、执行 D1 迁移并部署到 Cloudflare Workers。

### 配置安全原则

`wrangler.toml` 是可提交的公开模板，不应写入任何真实生产资源信息。以下内容都不要提交到仓库：

- Cloudflare Account ID、API Token、D1 database ID、KV namespace ID。
- 真实 Worker 名称、D1 数据库名、R2 bucket 名。
- 真实发件域名、发件邮箱、Reply-To。
- `JWT_SECRET`、邮件 provider token、通知投递 token 等密钥。

部署时使用 `scripts/render-wrangler-config.mjs` 从环境变量或 GitHub Secrets 生成临时配置：

```bash
npm run render:wrangler -- --strict
```

生成文件默认位于：

```text
workers/wrangler.deploy.toml
```

该文件已被 `.gitignore` 忽略。部署和迁移都应使用这个临时文件：

```bash
npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --remote --config wrangler.deploy.toml
npx wrangler deploy --config wrangler.deploy.toml
```

### Cloudflare 资源

首次部署前需要创建这些资源：

```bash
npx wrangler login

# D1 数据库
npx wrangler d1 create <your-d1-database-name>

# R2 存储桶，用于附件
npx wrangler r2 bucket create <your-attachments-bucket-name>

# KV namespace，用于 Icons 缓存
npx wrangler kv namespace create ICONS_CACHE
npx wrangler kv namespace create ICONS_CACHE --preview

# Web Push 主队列和死信队列（名称必须与 wrangler.toml 一致）
npx wrangler queues create bitwarden-web-push-dlq-dev
npx wrangler queues create bitwarden-web-push-dev
```

记录以下值，但不要写入 `wrangler.toml`：

| 值 | 用途 |
|----|------|
| Worker 名称 | `WORKER_NAME` |
| D1 数据库名 | `D1_DATABASE_NAME` |
| D1 database ID | `D1_DATABASE_ID` |
| R2 bucket 名 | `ATTACHMENTS_BUCKET_NAME` |
| KV production ID | `ICONS_CACHE_ID` |
| KV preview ID | `ICONS_CACHE_PREVIEW_ID` |
| Web Push 主队列 | `bitwarden-web-push-dev` |
| Web Push 死信队列 | `bitwarden-web-push-dlq-dev` |

### 生产密钥

`JWT_SECRET` 是 Worker secret，不进入 `wrangler.toml`，也不进入 `wrangler.deploy.toml`：

```bash
npx wrangler secret put JWT_SECRET --config wrangler.deploy.toml
```

如使用 webhook 邮件 provider，`EMAIL_PROVIDER_TOKEN` 也应使用 secret：

```bash
npx wrangler secret put EMAIL_PROVIDER_TOKEN --config wrangler.deploy.toml
```

### 手动部署

在 `workers` 目录中导出生产配置环境变量：

```bash
export WORKER_NAME="<your-worker-name>"
export D1_DATABASE_NAME="<your-d1-database-name>"
export D1_DATABASE_ID="<your-d1-database-id>"
export ATTACHMENTS_BUCKET_NAME="<your-r2-bucket-name>"
export ICONS_CACHE_ID="<your-kv-production-id>"
export ICONS_CACHE_PREVIEW_ID="<your-kv-preview-id>"

# 注册策略：auto / true / false
export SIGNUPS_ALLOWED="auto"

# 用于组织邀请链接，建议设置为正式访问地址
export VAULT_BASE_URL="https://<your-worker-domain>"
```

如果使用 Cloudflare Email Service 发信，需要先在 Cloudflare Dashboard 完成 Email Sending 发件域名 onboarding，然后导出：

```bash
export EMAIL_MODE="cloudflare"
export EMAIL_FROM="Bitwarden <no-reply@example.com>"
export EMAIL_SENDER_ADDRESS="no-reply@example.com"
# 可选
export EMAIL_REPLY_TO="support@example.com"
```

如果暂时不发邮件：

```bash
export EMAIL_MODE="disabled"
```

构建 Web Vault、检查 Workers、渲染临时配置并部署：

```bash
cd ..
./scripts/deploy-workers.sh
```

该脚本会执行：

1. `workers` TypeScript 类型检查。
2. `workers` 测试。
3. 构建 `clients/apps/web` 的 self-hosted production 静态文件。
4. 删除 sourcemap，避免 Cloudflare assets 超限。
5. 生成 `workers/wrangler.deploy.toml`。
6. 使用临时配置执行 `wrangler deploy`。

如果只想手动执行核心步骤：

```bash
cd workers
npm ci
npm run typecheck
npm run test
npm run render:wrangler -- --strict
npx wrangler d1 migrations apply "$D1_DATABASE_NAME" --remote --config wrangler.deploy.toml
npx wrangler deploy --config wrangler.deploy.toml
```

### GitHub Actions 自动部署

`workers/.github/workflows/deploy.yml` 会在 `workers` 仓库 `main` 分支推送时自动运行，也支持手动触发并指定 `clients_ref`。

工作流会：

1. Checkout `deluxebear/bitwarden_cf_workers` 到 `workers/`。
2. Checkout `deluxebear/bitwarden_clients` 到 `clients/`。
3. 安装两个仓库的 npm 依赖。
4. 执行 Workers `typecheck` 和 `test`。
5. 在 `clients/apps/web` 执行 `npm run dist:bit:selfhost`。
6. 校验 `clients/apps/web/build/index.html` 存在并删除 `.map` 文件。
7. 从 GitHub Secrets 生成 `workers/wrangler.deploy.toml`。
8. 使用临时配置执行 D1 迁移。
9. 使用临时配置部署 Workers + Web Vault assets。

如果你修改了 `clients`，需要先把对应提交 push 到 `deluxebear/bitwarden_clients`。自动部署默认构建 `main`，手动运行 workflow 时可以在 `clients_ref` 填入 branch、tag 或 commit SHA。

#### GitHub Secrets

在 `bitwarden_cf_workers` 仓库的 **Settings > Secrets and variables > Actions** 中添加：

| Secret 名称 | 是否必需 | 说明 |
|-------------|----------|------|
| `CLOUDFLARE_API_TOKEN` | 必需 | Cloudflare API Token |
| `CLOUDFLARE_ACCOUNT_ID` | 必需 | Cloudflare Account ID |
| `WORKER_NAME` | 必需 | 生产 Worker 名称 |
| `D1_DATABASE_NAME` | 必需 | 生产 D1 数据库名 |
| `D1_DATABASE_ID` | 必需 | 生产 D1 database ID |
| `ATTACHMENTS_BUCKET_NAME` | 必需 | 生产 R2 bucket 名 |
| `ICONS_CACHE_ID` | 必需 | KV production namespace ID |
| `ICONS_CACHE_PREVIEW_ID` | 必需 | KV preview namespace ID |
| `EMAIL_MODE` | 建议 | `cloudflare`、`provider`、`disabled` 或 `log`；未设置时按 `cloudflare` 校验 |
| `EMAIL_FROM` | `EMAIL_MODE=cloudflare` 时必需 | 例如 `Bitwarden <no-reply@example.com>` |
| `EMAIL_SENDER_ADDRESS` | `EMAIL_MODE=cloudflare` 时必需 | Cloudflare Email Sending 已验证的发件地址 |
| `EMAIL_FROM_NAME` | 可选 | Cloudflare Email Service 显示名称 |
| `EMAIL_REPLY_TO` | 可选 | 回复地址 |
| `EMAIL_PROVIDER_ENDPOINT` | `EMAIL_MODE=provider` 时使用 | webhook 邮件服务地址 |
| `SIGNUPS_ALLOWED` | 可选 | `auto`、`true` 或 `false` |
| `VAULT_BASE_URL` | 建议 | Web Vault 正式访问地址，用于邀请链接 |
| `SSO_BASE_URL` | 使用 OIDC 时必需 | Worker 的公网 HTTPS origin，用于 OIDC 回调 |
| `FORCE_INVITE_REGISTER` | 可选 | `true` 时邀请链接强制进入注册流程 |
| `CLIENTS_REPO_TOKEN` | 私有 clients 仓库时必需 | 读取 `deluxebear/bitwarden_clients` 的 token |

Cloudflare API Token 至少需要这些权限：

| 范围 | 资源 | 级别 |
|------|------|------|
| 帐户 | D1 | 编辑 |
| 帐户 | Workers KV 存储 | 编辑 |
| 帐户 | Workers R2 存储 | 编辑 |
| 帐户 | Workers Queues | 编辑 |
| 帐户 | Workers 脚本 | 编辑 |
| 帐户 | 帐户设置 | 读取 |
| 用户 | 成员资格 | 读取 |
| 用户 | 用户详细信息 | 读取 |

### 部署验证

```bash
curl https://<your-worker-domain>/alive
curl -I https://<your-worker-domain>/github.com/icon.png
```

Web Vault 和 API 由同一个 Worker 提供。自托管 Web Vault 构建由 `ENV=selfhosted` 生成，因此 Admin Console 的订阅和许可证上传界面会走 self-hosted 版本。

---

## 配置 Bitwarden 客户端

在 Bitwarden 客户端的"自托管"设置中填入你的 Worker 地址：

```
服务端 URL: https://<your-worker-domain>
```

所有客户端（Web Vault、桌面、浏览器扩展、移动端）均使用同一个地址。

---

## 环境变量

公开默认值保存在 `wrangler.toml` 的 `[vars]` 中；生产私有值通过 GitHub Secrets 或本地 shell 环境变量渲染到 `wrangler.deploy.toml`。真正的密钥仍然使用 `npx wrangler secret put` 设置，不能进入任何 TOML 文件。

### 核心配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `JWT_SECRET` | — | **必须修改**。JWT 签名密钥，使用 `wrangler secret put` 配置 |
| `JWT_EXPIRATION` | `3600` | Access Token 有效期（秒） |
| `JWT_REFRESH_EXPIRATION` | `2592000` | Refresh Token 有效期（秒），默认 30 天 |
| `GLOBAL_PREMIUM` | `true` | 全局启用 Premium 功能 |

### 高级二步验证与 SSO

以下值必须通过 `wrangler secret put` 配置，不能写入 TOML 或提交到仓库：

| Secret | 用途 |
|--------|------|
| `DUO_CONFIG_ENCRYPTION_KEY` | 加密 D1 中的 Duo Client Secret；必须是 Base64/Base64URL 编码的 32 字节随机密钥 |
| `YUBICO_CLIENT_ID` / `YUBICO_SECRET` | Yubico OTP Validation 凭据 |
| `WEB_PUSH_VAPID_PRIVATE_KEY` | Web Push VAPID P-256 私钥，Base64URL 编码的 32 字节标量 |
| `HEALTH_CHECK_TOKEN` | `/healthz/extended` 的高熵服务令牌；未配置时深度探针返回 404 |
| OIDC 配置指定的 secret binding | 组织 OIDC Client Secret；binding 名由组织配置保存 |

生成 Duo 加密密钥并写入 Worker：

```bash
openssl rand -base64 32 | npx wrangler secret put DUO_CONFIG_ENCRYPTION_KEY
```

启用 Duo 前还必须设置 `VAULT_BASE_URL` 为 Web Vault 的公网 HTTPS 地址；Duo 回调会使用其中的 `duo-redirect-connector.html`。

Web Push 还需在公开变量中配置 `WEB_PUSH_VAPID_PUBLIC_KEY` 和 `WEB_PUSH_VAPID_SUBJECT`。只有公钥、私钥和 subject 三项齐全时，`/api/config` 才会向客户端声明 `pushTechnology=WebPush`；否则继续使用 SignalR。

生产启用 Web Push 前需先创建重试队列和死信队列，并将名称通过 `WEB_PUSH_QUEUE_NAME`、`WEB_PUSH_DLQ_NAME` 传给部署配置渲染器：

```bash
npx wrangler queues create bitwarden-web-push
npx wrangler queues create bitwarden-web-push-dlq
```

### 注册与邀请

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `SIGNUPS_ALLOWED` | `auto` | 注册控制，见下方说明 |
| `VAULT_BASE_URL` | — | Web Vault 前端地址（如 `https://vault.example.com`），用于生成邀请链接 |
| `FORCE_INVITE_REGISTER` | — | 设为 `true` 时邀请链接一律走注册流程 |
| `INSTALLATION_ID` | — | 自建许可证校验用 Installation ID |

#### 注册控制 (`SIGNUPS_ALLOWED`)

| 值 | 行为 |
|------|------|
| `auto` | **默认**。无用户时允许注册，有用户后自动关闭 |
| `true` | 始终允许注册 |
| `false` | 始终禁止注册（仅邀请有效） |

> 无论哪种模式，通过组织邀请的注册始终有效。  
> 典型用法：保持默认 `auto`，第一个人注册后即自动关闭开放注册。

### Icons 缓存

网站图标服务采用"域名维度缓存"，同一网站的 icon 在所有用户间共享，无需重复抓取。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ICONS_CACHE_SUCCESS_TTL_SECONDS` | `1209600` | 成功缓存 TTL（14 天） |
| `ICONS_CACHE_NEGATIVE_TTL_SECONDS` | `43200` | 负缓存 TTL（12 小时），对无 icon 站点避免反复请求 |
| `ICONS_MAX_IMAGE_BYTES` | `51200` | 可缓存 icon 最大字节数（50KB） |

成本优化建议：
- 访问量大时可将成功缓存提高到 30 天（`2592000`）。
- 负缓存保持 6-24 小时区间，避免长期错误锁死。

---

## Cloudflare 资源绑定

| 绑定名 | 类型 | 用途 |
|--------|------|------|
| `DB` | D1 | 主数据库 |
| `ATTACHMENTS` | R2 | 附件文件存储 |
| `ICONS_CACHE` | KV | Icons 缓存（跨用户复用） |
| `NOTIFICATION_HUB` | Durable Object | 实时 WebSocket 推送 |
| `WEB_PUSH_QUEUE` | Queue | Web Push 429/5xx/网络故障的持久化延迟重试；消费者最终失败进入 DLQ |

---

## 可观测性与健康检查

- 所有 HTTP 响应包含 `X-Request-Id`。调用方可传入 8–64 位字母、数字、`_`、`-` 组成的请求 ID；无效或缺失时由 Worker 生成 UUID。
- 每个请求输出一条结构化 JSON 完成日志，字段为 `requestId`、`method`、`route`、`status`、`duration`、`errorCode`。日志不包含查询参数、请求体、认证头、邮箱、OTP 或密钥。
- `GET /healthz` 是不访问绑定的轻量存活探针。
- `GET /healthz/extended` 仅在配置 secret `HEALTH_CHECK_TOKEN` 后启用，并要求 `Authorization: Bearer <token>`；它会并行验证 D1、KV、R2 与 Durable Object，全部可用返回 `200`，否则返回不含底层错误和资源 ID 的 `503 degraded`。未配置或鉴权失败返回 `404`，避免被公开请求放大资源消耗。
- `GET /version` 优先读取可选 `WORKER_VERSION`，其次读取 Cloudflare Version Metadata binding（建议绑定名 `CF_VERSION_METADATA`），均未配置时安全返回 `unknown`。

生产环境建议在 Wrangler 中启用 Workers Observability，并为高流量服务配置合适的 head sampling rate。`WORKER_VERSION` 和 Version Metadata binding 需由部署配置注入；它们都不是 secret。

## 定时任务

通过 Cron Triggers 自动执行，无需额外基础设施：

| Cron | 任务 | 说明 |
|------|------|------|
| `*/5 * * * *` | DeleteSendsJob | 每 5 分钟清理到期 Send |
| `0 0 * * *` | DeleteCiphersJob | 每日午夜永久删除 30 天前软删除的 Cipher |
| `0 22 * * 5` | DatabaseExpiredGrantsJob | 每周五 22:00 UTC 清理过期 Refresh Token |

---

## 项目结构

```
workers/
├── src/
│   ├── index.ts                  # Worker 入口与路由挂载
│   ├── routes/                   # API 路由
│   │   ├── identity.ts           # 认证与 Token
│   │   ├── accounts.ts           # 用户账户
│   │   ├── sync.ts               # 数据同步
│   │   ├── ciphers.ts            # 密码条目
│   │   ├── folders.ts            # 文件夹
│   │   ├── organizations.ts      # 组织管理
│   │   ├── collections.ts        # 集合
│   │   ├── two-factor.ts         # 双因素验证
│   │   ├── webauthn.ts           # 通行密钥
│   │   ├── auth-requests.ts      # 免密登录
│   │   ├── sends.ts              # 安全分享
│   │   ├── devices.ts            # 设备管理
│   │   ├── events.ts             # 审计日志
│   │   ├── settings.ts           # 用户设置
│   │   ├── reports.ts            # 安全报告
│   │   ├── icons.ts              # 网站图标
│   │   ├── config.ts             # 服务端配置
│   │   └── tasks.ts              # 定时任务
│   ├── services/                 # 业务逻辑
│   │   ├── icons/                # Icons 抓取、缓存、安全校验
│   │   ├── crypto.ts             # 加密工具
│   │   ├── totp.ts               # TOTP 验证
│   │   ├── scheduled.ts          # Cron 任务处理
│   │   ├── events.ts             # 事件记录
│   │   ├── policy-validators.ts  # 策略校验
│   │   └── signup-guard.ts       # 注册控制
│   ├── middleware/               # 中间件
│   │   ├── auth.ts               # JWT 认证
│   │   ├── error.ts              # 错误处理
│   │   └── debug.ts              # 调试日志
│   ├── durable-objects/          # Durable Objects
│   ├── db/                       # Drizzle 数据库 schema
│   ├── models/                   # 响应模型
│   └── types/                    # TypeScript 类型定义
├── drizzle/                      # SQL 迁移文件
├── .github/workflows/deploy.yml  # CI/CD 自动部署
├── wrangler.toml                 # 可提交的公开 Workers 配置模板
├── tsconfig.json
└── package.json
```

---

## 安全

- **端到端加密**：所有密码库数据在客户端加密，服务端只存储密文。
- **密码哈希**：PBKDF2-SHA256，与 Bitwarden 官方一致。
- **JWT 签名**：HMAC-SHA256，`JWT_SECRET` 必须使用 `wrangler secret put` 设置强随机值。
- **Token 轮换**：Refresh Token 每次使用后自动更换。
- **防枚举**：Prelogin 端点对不存在的用户也返回默认 KDF 参数。
- **注册保护**：默认 `auto` 模式，首个用户注册后自动关闭开放注册。
- **SSRF 防护**：Icons 服务拒绝 IP 直连、内网地址、非标准端口。

---

## License

AGPL-3.0
