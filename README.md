# Bitwarden Workers

> Bitwarden Server API 的 Cloudflare Workers 实现，与官方 Bitwarden 客户端兼容。

## 技术栈

- **运行时**: [Cloudflare Workers](https://workers.cloudflare.com/)
- **框架**: [Hono](https://hono.dev/) - 轻量高性能 Web 框架
- **数据库**: [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite)
- **ORM**: [Drizzle ORM](https://orm.drizzle.team/)
- **认证**: JWT (HMAC-SHA256)
- **加密**: Web Crypto API

## 已实现的 API

| 模块 | 端点 | 方法 | 描述 |
|------|------|------|------|
| Identity | `/identity/accounts/prelogin` | POST | 获取 KDF 参数 |
| Identity | `/identity/accounts/register` | POST | 用户注册 |
| Identity | `/identity/connect/token` | POST | 登录 (password/refresh_token grant) |
| Accounts | `/api/accounts/profile` | GET/PUT/POST | 用户资料管理 |
| Accounts | `/api/accounts/revision-date` | GET | 账户修订日期 |
| Accounts | `/api/accounts/keys` | GET/POST | 密钥管理 |
| Accounts | `/api/accounts/password` | POST | 修改密码 |
| Sync | `/api/sync` | GET | 全量同步 |
| Ciphers | `/api/ciphers` | GET/POST | 密码条目列表/创建 |
| Ciphers | `/api/ciphers/:id` | GET/PUT/DELETE | 单条目操作 |
| Ciphers | `/api/ciphers/:id/delete` | PUT | 软删除 |
| Ciphers | `/api/ciphers/:id/restore` | PUT | 恢复 |
| Ciphers | `/api/ciphers/delete` | POST | 批量删除 |
| Ciphers | `/api/ciphers/move` | PUT | 批量移动 |
| Ciphers | `/api/ciphers/purge` | POST | 清空 |
| Folders | `/api/folders` | GET/POST | 文件夹列表/创建 |
| Folders | `/api/folders/:id` | GET/PUT/DELETE | 文件夹操作 |
| Config | `/api/config` | GET | 服务端配置 |

## 快速开始

### 前置条件

- Node.js >= 18
- npm / pnpm
- Cloudflare 账户（用于部署）

### 本地开发

```bash
# 安装依赖
npm install

# 生成数据库迁移
npm run db:generate

# 应用迁移（本地 D1）
npm run db:migrate:local

# 启动开发服务器
npm run dev
```

### 部署到 Cloudflare

```bash
# 1. 创建 D1 数据库
npx wrangler d1 create bitwarden-db

# 2. 更新 wrangler.toml 中的 database_id

# 3. 应用迁移
npm run db:migrate:remote

# 4. 配置生产 JWT_SECRET
npx wrangler secret put JWT_SECRET

# 5. 部署
npm run deploy
```

### 配置 Bitwarden 客户端

在 Bitwarden 客户端中设置自托管服务器地址：
- **服务端 URL**: `https://your-worker.your-subdomain.workers.dev`

## 项目结构

```
workers/
├── src/
│   ├── index.ts              # Worker 入口，路由挂载
│   ├── routes/
│   │   ├── identity.ts       # 认证（Prelogin/Register/Token）
│   │   ├── accounts.ts       # 账户管理
│   │   ├── sync.ts           # 全量同步
│   │   ├── ciphers.ts        # 密码条目 CRUD
│   │   ├── folders.ts        # 文件夹 CRUD
│   │   └── config.ts         # 服务端配置
│   ├── middleware/
│   │   ├── auth.ts           # JWT 认证中间件
│   │   └── error.ts          # 错误处理
│   ├── db/
│   │   └── schema.ts         # Drizzle ORM 表定义
│   ├── services/
│   │   └── crypto.ts         # 加密/哈希服务
│   └── types/
│       └── index.ts          # TypeScript 类型定义
├── drizzle/                  # 生成的 SQL 迁移文件
├── wrangler.toml             # Workers 配置
├── drizzle.config.ts         # Drizzle Kit 配置
├── tsconfig.json
└── package.json
```

## 安全说明

- **JWT_SECRET** 必须在生产环境中使用 `wrangler secret put` 配置为强随机值
- 密码使用 PBKDF2-SHA256 哈希，与 Bitwarden 官方实现一致
- 所有密码库数据在客户端加密，服务端只存储密文
- Refresh token 使用 rotation 策略，每次使用后自动更换
- 防用户枚举：prelogin 端点对不存在的用户也返回默认 KDF 参数

## License

AGPL-3.0
