# DEBUG REPORT

- **Symptom:** Bitwarden iOS 2026.6.1 登录成功，但密码库页面无法加载并显示通用请求失败。
- **Root cause:** `/api/sync` 返回 200，但 `policies[0].revisionDate` 使用旧 SQLite 时间格式 `2026-07-09 03:38:19Z`；iOS 的严格日期解码要求 ISO 8601 `T` 分隔符。
- **Fix:** `src/routes/sync.ts` 在同步 policy 响应中通过 `toApiDate` 将旧格式规范为 ISO 8601。
- **Evidence:** iOS 导出日志报告 `DecodingError.dataCorrupted`，路径为 `policies[0].revisionDate`；Cloudflare tail 确认对应 `/api/sync` 请求返回 200。
- **Regression test:** `src/routes/sync.test.ts`。
- **Verification:** `npm run typecheck` 通过；`npm test` 通过（33 个单元测试文件、144 个测试；12 个集成测试文件、72 个测试）；已部署版本 `d23e433c-eff5-41f9-b831-4b50a99ad001`，iOS 真机命中新版本 `/api/sync` 并返回 200。
- **Related:** 历史 policy 数据可能来自 SQLite 风格时间戳；新写入路径已使用 `new Date().toISOString()`。
- **Status:** DONE_WITH_CONCERNS（代码、部署和真机请求已验证，尚缺用户确认密码库界面已正常显示）。
