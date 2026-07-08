**中文** | [English](./README.en.md)

# Bitwarden Workers

> Bitwarden Server API 的 Cloudflare Workers 实现，完全兼容官方 Bitwarden 客户端（Web、桌面、浏览器扩展、移动端）。
>
> 零服务器、零运维，基于 Cloudflare 免费套餐即可运行个人/家庭密码管理器。
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

## 快速开始

### 前置条件

- Node.js >= 22（Wrangler 4.x 要求）
- npm
- [Cloudflare 账户](https://dash.cloudflare.com/sign-up)（免费即可）

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
| `FORCE_INVITE_REGISTER` | 可选 | `true` 时邀请链接强制进入注册流程 |
| `CLIENTS_REPO_TOKEN` | 私有 clients 仓库时必需 | 读取 `deluxebear/bitwarden_clients` 的 token |

Cloudflare API Token 至少需要这些权限：

| 范围 | 资源 | 级别 |
|------|------|------|
| 帐户 | D1 | 编辑 |
| 帐户 | Workers KV 存储 | 编辑 |
| 帐户 | Workers R2 存储 | 编辑 |
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

---

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
