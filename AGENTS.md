# AGENTS.md

本目录是用 Cloudflare Workers 复刻/兼容上游 Bitwarden Server API 的实现。后续开发必须把“官方客户端兼容”和“上游 server 行为对齐”放在第一位。

## 开发目标

- 目标不是重新设计 Bitwarden，而是在 Workers 运行时中实现上游 `bitwarden/server` 的可用等价行为。
- 新增或修改接口前，先在上游仓库确认对应 Controller、Request/Response Model、Service、Repository、SQL 迁移和测试的真实语义。
- 对外响应字段、状态码、错误结构、路由路径、认证要求和客户端可见行为必须尽量匹配官方 Bitwarden 客户端期望。
- 若 Cloudflare 平台限制导致无法完全一致，需要在代码附近留下简短说明，并优先选择客户端无感知的兼容方案。

## 项目结构

- `src/index.ts`：Workers 入口，挂载 Hono 路由、Cron handler 和 Durable Object。
- `src/routes/`：按 Bitwarden API 模块拆分的 HTTP 路由。
- `src/services/`：认证、加密、事件、策略校验、推送、计划任务等业务逻辑。
- `src/db/schema.ts`：Drizzle/D1 数据模型。
- `drizzle/`：Drizzle 生成的数据库迁移。
- `migrations/`：历史/手写 D1 迁移；改动前确认当前项目实际使用路径。
- `src/durable-objects/`：通知 Hub 等 Durable Objects。

## 技术约束

- 运行时是 Cloudflare Workers，不是 Node.js 服务端。不要引入依赖长连接、本地文件系统、进程、线程或原生模块的实现。
- Web 框架使用 Hono；保持现有路由拆分方式，不要把大型模块塞回 `src/index.ts`。
- 数据库使用 Cloudflare D1 + Drizzle。涉及 schema 变更时必须同步更新 schema、迁移文件和相关读写逻辑。
- 附件使用 R2，图标缓存使用 KV/Edge Cache，实时通知使用 Durable Objects。
- 敏感值必须通过 Wrangler secrets 配置；不要把真实密钥、token、许可证私钥或生产资源 ID 写入源码。

## Cloudflare Workers 规则

- 不要在模块级变量里保存请求级状态、用户身份、数据库结果或可变业务状态。
- 所有 Promise 必须 `await`、`return`、显式 `void`，或交给 `ctx.waitUntil()`；后台任务使用 `ctx.waitUntil()`。
- 不要解构 `ctx.waitUntil`，保持 `ctx.waitUntil(...)` 调用。
- 大文件和未知大小响应要流式处理，避免对不受控内容直接 `text()`、`json()` 或 `arrayBuffer()`。
- 安全随机值使用 Web Crypto，例如 `crypto.randomUUID()` 或 `crypto.getRandomValues()`；不要用 `Math.random()` 生成 token、密钥或安全 ID。
- 优先使用绑定访问 D1/R2/KV/DO，不要在 Worker 内通过 Cloudflare REST API 调自己的资源。

## 与上游 Bitwarden 对齐

开发某个端点时，至少确认以下内容：

- 上游路由路径、HTTP 方法、鉴权策略和 feature flag 行为。
- Request/Response model 的字段名、大小写、可空性、默认值和 `object` 字段。
- 错误响应格式、状态码和客户端依赖的错误消息。
- 数据库字段、索引、唯一约束、软删除/修订时间/同步时间语义。
- 事件日志、推送通知、`/api/sync` 返回内容是否需要同步更新。

如果实现的是某个上游 Controller 的子集，要保持未实现部分有明确、客户端可接受的返回，不要静默成功。

## 数据和加密

- Bitwarden vault 数据是端到端加密密文。服务端不得尝试解密、重加密或解析客户端密文字段。
- 认证、KDF、WebAuthn、TOTP、Send、组织密钥、集合授权等逻辑必须保持与官方客户端协议兼容。
- 修改 ciphers、folders、collections、organizations、sends 等数据时，注意同步 `revisionDate`、软删除字段、事件记录和推送通知。
- 不要为了迁就本地测试写入明文密码库数据。

## 数据库迁移

- 修改 `src/db/schema.ts` 后运行：

```bash
npm run db:generate
npm run db:migrate:local
```

- 迁移文件需要可重复应用、向前兼容已有数据，并尽量避免破坏用户现有 D1 数据库。
- 生产迁移使用：

```bash
npm run db:migrate:remote
```

- 不要手动编辑已发布迁移来改变历史；需要修正时新增迁移。

## 常用命令

```bash
npm install
npm run dev
npm run typecheck
npm run test
npm run db:generate
npm run db:migrate:local
```

部署前至少运行：

```bash
npm run typecheck
npm run test
```

## 验证重点

- 官方 Bitwarden Web、浏览器扩展、桌面端和移动端能正常登录、同步、创建/编辑/删除密码条目。
- `/identity/connect/token`、`/api/sync`、`/api/ciphers/*`、附件、Send、组织/集合/成员相关接口是高风险区域，改动后要做端到端验证。
- 涉及通知时，确认 Durable Object WebSocket Hub 和 push payload 不破坏客户端实时刷新。
- 涉及定时任务时，确认 `scheduled()` 中的 cron 分支不会阻塞请求路径。

## 代码风格

- 保持 TypeScript 类型清晰，避免 `any` 和双重断言 `as unknown as T`。
- 复用现有 service/helper，不要复制大段业务逻辑到多个 route。
- 错误处理使用现有 middleware 和 Bitwarden 风格 JSON 响应。
- 注释只写必要的协议差异、平台限制或非显然兼容逻辑。

## 禁止事项

- 不要提交真实 secret、生产数据库 ID、Cloudflare API token、用户数据或导出的 vault 数据。
- 不要用破坏性迁移删除用户数据，除非有明确数据迁移方案。
- 不要引入需要常驻 TCP 连接、Node 原生模块或服务器文件系统的依赖。
- 不要为了让测试通过改变公开 API 形状。
- 不要在未理解上游行为时凭直觉新增 Bitwarden 协议字段。
