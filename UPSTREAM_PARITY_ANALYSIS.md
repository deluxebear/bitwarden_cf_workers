# Workers 复刻版 vs 官方 Server:业务逻辑完整性分析

> 生成日期:2026-07-10
> 对比对象:官方 Bitwarden Server(.NET,`/src/`、`/bitwarden_license/src/`)vs Cloudflare Workers 复刻版(`/workers/src/`)
> 方法:按 10 个领域并行深度对比业务语义(权限校验、副作用如 revisionDate/事件/推送、错误结构、密钥语义),而非仅比对端点是否存在。
> 说明:file:line 为分析当时的行号,后续改动后可能漂移,定位时以符号/上下文为准。

---

## 总体结论

该复刻对「官方客户端 + 个人/小团队自托管」场景覆盖度高:登录、双因素、密码库 CRUD、附件、Send、组织/成员/群组/集合/策略、紧急访问端点面、实时通知(SignalR 兼容)、图标、事件日志的主干链路都能与官方 web/扩展/桌面/移动客户端互操作,响应字段与零知识密钥交付语义还原度高,部分实现(Duo secret 加密存储、Web Push、图标 SSRF 防护)甚至严于官方。

但**不是完全实现**,缺口分三层:
1. 一批安全语义偏差,其中约 10 处是可利用的越权 / 认证绕过路径;
2. 若干官方客户端会实际撞到的功能缺口(CLI 登录、改 KDF、强制改密、2FA 记住我、TDE 管理员审批、HIBP 等);
3. 企业商业闭环整体缺失(SSO/SCIM/Secrets Manager/Provider/公共 API/Key Connector/真实计费),对个人用户无影响。

## 模块完成度总览

| 领域 | 主干实现 | 主要问题性质 |
|---|---|---|
| Identity 登录/注册 | 高 | API key 登录缺失、2FA remember 缺失、新设备验证过严 |
| 账户/密钥管理 | 中高 | refresh 层会话吊销漏洞、验证可绕过、KDF/强制改密缺失 |
| Vault 密码库 | 中 | 组织 cipher 写权限绕过、跨成员 revision 不同步、冲突检测缺失 |
| Send | 高 | 编辑时清除密码保护、匿名访问缺副作用 |
| 组织核心 | 中高 | 4-5 处越权、细粒度授权缺失、事件类型错乱 |
| 组织扩展(域名/审批/链接/license/2FA) | 高 | license 更新无鉴权、域名反验证、副作用邮件缺失 |
| 2FA / WebAuthn | 中高 | 可伪造 token 禁用 2FA、无密码读恢复码、无防重放、Duo/YubiKey 缺失 |
| 设备 / AuthRequest / 紧急访问 | 中 | TDE 审批被 cron 误删、update-trust 无验证、紧急访问是假成功占位 |
| 平台(通知/推送/事件/config/icons/reports) | 高 | HIBP 缺失、等价域名排除失效、auth request cron bug |
| 顶层缺失模块 | ❌ | SSO/SCIM/SM/Provider/公共 API/计费 |

---

## 一、必须优先修复:安全级偏差(P0)

「实现了但语义错误、能被利用」,比未实现更危险。

| # | 问题 | 位置 | 官方对应 | 后果 |
|---|---|---|---|---|
| 1 | 组织 license 更新端点无 Owner 校验 | `organization-licenses.ts:438` | `SelfHostedOrganizationLicensesController.cs:80` 要求 OrganizationOwner | 任意登录用户可向任意组织上传 license,改席位/关功能位/`enabled=false` 使组织瘫痪 |
| 2 | reset-password-enrollment 完全无鉴权 | `organizations.ts:3180` | `UpdateUserResetPasswordEnrollmentCommand.cs:32` | 任意用户给任意成员写/清 `resetPasswordKey`,使管理员无法再恢复其账户;不记 1506/1507 |
| 3 | 组织 cipher 写权限绕过 | `ciphers.ts:2433`;`delete-admin`/`restore-admin`/`delete('/admin')` :1659,1766,2359 | `CiphersController.cs:243`、`CanDeleteOrRestoreCipherAsAdminAsync:399` | readOnly/未分配集合的普通成员可改写、软删、硬删、恢复全组织条目 |
| 4 | authenticator 验证 token 可伪造 | `two-factor.ts:383,403,459` | `TwoFactorAuthenticatorUserVerificationTokenable`(DataProtector 签名,30min) | 仅凭 access token 即可在不知主密码下禁用/篡改 2FA |
| 5 | GET /two-factor/recover 无密码返回恢复码 | `two-factor.ts:562` | 官方无此端点,仅 `POST /get-recover` 经 `CheckAsync` 密码验证 | 会话劫持者直接读恢复码 → 配合登录清空全部 2FA,完整绕过链 |
| 6 | DELETE /accounts、security-stamp 验证可跳过 | `accounts.ts:685,580` | `AccountsController.cs:575` 必须 `VerifySecretAsync`;`UserService.cs:681` | body 不带 hash 就不验证 → 仅凭 token 直接销毁账户 |
| 7 | POST /:id/keys 任意成员覆盖组织密钥对 | `organizations.ts:1582` | `OrganizationUpdateKeysCommand` 要求 ManageResetPassword 且禁止覆盖已有 | 破坏账户恢复信任链 |
| 8 | accept 携带 token 跳过邮箱匹配 | `organizations.ts:2542` | `AcceptOrgUserCommand.AcceptOrgUserByEmailTokenAsync:79` 强制 `user.Email==orgUser.Email` | 转发邀请链接的任意账号占用席位,confirm 时组织密钥交给非预期账户 |
| 9 | POST update-trust 不强制验证 | `devices.ts:109` | `DevicesController.cs:175` 必须 `VerifySecretAsync` + 2s 延迟 | 被盗 token 可改写设备信任密钥,无防爆破 |
| 10 | recover-account 缺角色层级 / remove 别名缺保护 | `organizations.ts:1955,3143` | `RecoverAccountAuthorizationHandler`;`RemoveOrganizationUserCommand` | Custom 用户可重置 Owner 密码;Admin 可通过老 POST remove 别名移除 Owner |
| 11 | 事件 collect 无成员身份校验 | `events.ts:229` | `CollectController.cs:135` 要求 `currentContext.GetOrganization` | 任意用户可向他组织事件日志注入条目(审计污染) |

**系统性会话吊销漏洞**:`identity.ts:1760` 的 refresh_token grant 不校验 securityStamp,只查 token 存在/过期/设备 active,并用当前 stamp 签发新 access token。凡是「只轮换 stamp、未删 refreshTokens」的操作(密钥轮换 `accounts.ts:743`、管理员重置 `organizations.ts:2030`、紧急接管 `emergency-access.ts:459`),其他设备靠 refresh token 静默续命,继续用旧用户密钥解密/加密回写。
修复:refresh 时比对 securityStamp(不匹配即 invalid_grant)+ 在上述三处补 `delete(refreshTokens)`。

---

## 二、官方客户端会实际撞到的功能缺口(P1)

| 缺口 | 位置 | 影响 |
|---|---|---|
| TDE 审批被 cron 误删 | `scheduled.ts:247`(另标于 :178) | `deleteExpiredAuthRequests` 无类型区分,15min 删掉所有 auth request(含 7 天期 AdminApproval)→ 信任设备加密的管理员审批流程被摧毁。**本次分析最高优先级之一** |
| Send 编辑清除密码保护 | `sends.ts:755` | 官方客户端编辑不改密码时提交 `password:null`,workers 直接移除密码 → 任何人可匿名打开 |
| 紧急访问是假成功占位 | `emergency-access.ts` 全文 | invite/accept/confirm/takeover 全返回假成功,用户以为配置了紧急联系人实际什么都没存(schema 无 emergency_access 数据落地流程) |
| client_credentials / API key 缺失 | `identity.ts:675`;无 `accounts/api-key` | CLI `bw login --apikey` 不可用;web「查看 API 密钥」失败 |
| POST /accounts/kdf 缺失 | 官方 `AccountsController.cs:350` | 「更改 KDF 算法/迭代次数」404,无法升级 Argon2id |
| update-temp-password 缺失 | 官方 `AccountsController.cs:712` | 管理员账户恢复后,用户强制改密流程最后一步 404,被卡死 |
| POST /accounts/email 方法错(注册为 PUT) | `accounts.ts:632` | 官方客户端 POST 换邮箱 → 404,换邮箱整体不可用;且不置 emailVerified、email-token 阶段抛错可枚举 |
| 2FA「记住我」(provider 5)缺失 | `identity.ts`(无 TwoFactorRemember) | 勾选「30 天记住此设备」无效,每次登录强制 2FA;带过期 remember token 登录直接报错 |
| 新设备验证过严 | `identity.ts:1061` | 无全局开关、无「首次登录/24h 内/无设备」豁免 → 邮件未配置的部署上新用户首登被 OTP 锁死(官方自托管默认关闭) |
| HIBP 泄露报告缺失 | 无 `/api/hibp/breach` | web「工具→数据泄露报告」404 |
| 等价域名排除失效 + 仅 5 组 | `settings.ts:22`、`sync.ts:101,472` | 自动填充等价域名少 86 组;用户排除某组后 sync 不生效;Type 编号也错 |
| 密钥轮换缺完整性校验 + 漏紧急访问重加密 | `accounts.ts:743,831` | 部分数据仍旧 key、user key 已换 → 永久不可解密混合态;紧急联系人 keyEncrypted 不更新 → 紧急访问永久失效 |
| 组织 cipher 写不 bump 其他成员 revision | `ciphers.ts` 各 handler | 多成员组织,推送不可达时其他人长期同步不到变更(官方每个 cipher 写 sproc 都 bump 所有可访问用户) |
| lastKnownRevisionDate 冲突检测缺失 | `ciphers.ts` save/share/attachment | 官方 `CipherService.cs:900` 超 1s 差报「out of date」,workers 直接覆盖 → 多设备并发编辑静默丢数据 |
| Security Task 全部 stub | `tasks.ts`(49 行) | 安全任务/Risk Insights 闭环不可用(complete/bulk-create/metrics 均缺) |
| 2FA / WebAuthn 无防重放 | `totp.ts`;`identity.ts:981` | TOTP 码 ~90s 内可复用;WebAuthn 2FA 断言不校验 challenge、不更新 counter,可无限重放 |

---

## 三、各领域详细清单

### 1. Identity 登录/注册

**已实现**:prelogin(新旧双端点)、password grant 主干(失败计数、设备 upsert、事件 1000、`UserDecryptionOptions.MasterPasswordUnlock`/`AccountKeys`/`kdfSettings` 对齐)、auth request 设备批准登录(7 项校验)、webauthn grant、send_access grant、三步注册 + 组织邀请注册、2FA 挑战基本结构(`TwoFactorProviders`/`TwoFactorProviders2`)、recovery code(provider 8)、access token claims(1h、sstamp 中间件校验 `auth.ts:113`)。

**偏差**:
- 2FA remember token 缺失(见 P1)。
- 2FA provider 覆盖:仅 0/1/7/8;Email 挑战缺打码邮箱与顶层 `Email` 字段(`identity.ts:773`);组织强制 2FA(`Use2fa`)未在登录端生效;2FA 挑战响应缺 `MasterPasswordPolicy`。
- 新设备验证语义偏差(见 P1);官方 OTP 通过会置 `EmailVerified=true`,workers 不会;新设备登录通知邮件缺失;auth request 流对未知设备比官方更宽松。
- refresh_token:workers 每次轮换 + 固定 30d,忽略 client_id;官方 ReUse + 滑动过期 + per-client(mobile 60d/web 7d/其余 30d)。并发刷新可能偶发登出。
- 防枚举弱化:send-verification-email 对已存在邮箱抛 400(`identity.ts:330`,官方静默 200);登录失败无 2s 延迟、无失败事件 1005/1006;auth request accessCode 用 `===`(`identity.ts:868`,官方 FixedTimeEquals)。
- master password 服务端存明文提交 hash(`crypto.ts:64`),官方再经 PBKDF2 加盐(深度防御,非零知识问题)。
- KDF 参数无范围校验(`registration.ts:41`)。

**未实现**:client_credentials grant(API key 登录,高)、SSO/OIDC authorization_code(仅简化 OIDC)、register/finish 的 EmergencyAccessInvite/ProviderInvite/OrgSponsoredFreeFamily token 类型、legacy 用户迁移拦截、ClientVersionValidator、Duo/YubiKey/组织 Duo 2FA、Key Connector。

### 2. 账户 / 密钥管理

**已实现**:profile 读写/avatar、revision-date、password(legacy 格式:验旧 hash、轮换 stamp、删 refresh、push logout)、security-stamp 主体、邮箱两步流程主体、password-hint(匿名防枚举)、resend-new-device-otp、keys 读写(禁止覆盖已有)、`users/{id}/public-key`、账户删除数据清理、sstamp access-token 层失效。

**偏差**:
- refresh 层 securityStamp 漏洞(见 P0);密钥轮换/管理员重置/紧急接管三处不删 refreshTokens(`accounts.ts:743`、`organizations.ts:2030`、`emergency-access.ts:459`)。
- POST /accounts/password 不支持新版 `authenticationData`/`unlockData`(`accounts.ts:493`):新格式下密码/key 都没改但 stamp 已轮换 → 「新密码登不上、旧密码能登」。
- DELETE /accounts、security-stamp 验证可绕过(见 P0)。
- 密钥轮换缺完整性校验(官方要求提交集覆盖全部现存 ciphers/folders/sends;公钥不可变、KDF/salt 不可变);漏 `emergencyAccessUnlockData`(`accounts.ts:831`)。
- 邮箱修改 HTTP 方法为 PUT(应 POST)、不置 emailVerified、email-token 阶段可枚举(见 P1)。
- 账户删除缺「唯一 Owner」防护(`claimed-accounts.ts:206`)→ 孤儿组织。
- verify-password 响应多包一层(`accounts.ts:565`)→ 客户端读到的策略字段全 undefined;profile 组织未按 Confirmed 过滤(`accounts.ts:221`)。
- PUT /profile 可改 hint/culture(官方只允许改 Name);失败路径无 2s 延迟、无 User_ChangedPassword 事件;sso/user-identifier token 无消费方。

**未实现(404)**:kdf、verify-email/verify-email-token、delete-recover/delete-recover-token、api-key/rotate-api-key、update-temp-password、set-password、request-otp/verify-otp、verify-devices、GET /accounts/organizations、DELETE /accounts/sso/{orgId}、key-management/regenerate-keys、新版 rotate-user-keys/key-rotation-data、Key Connector 系列、GET /users/{id}/keys(V2)、Obsolete 别名、license/cancel(计费类)。

### 3. Vault 密码库(Ciphers/附件/Folders/Sync/导入/SecurityTask)

**已实现**:Folders CRUD(缺 `DELETE /all`)、附件签名下载(HMAC 5min token + 匿名入口)、partial 更新、archive/unarchive(500 上限、仅个人)、attachment v2 两步骨架、个人导入(OrganizationDataOwnership 拦截)、sync 基础结构(excludeDomains、profile/folders/collections/policies/ciphers/sends/domains/userDecryption)、purge 本人验证 + claimed 拦截、事件码 1100-1116。

**偏差**(权限类最严重):
- 组织 cipher 写权限绕过 / admin 批量端点仅验成员资格 / canAccessAllOrgItems 双向偏差 / collections 变更端点权限缺失(见 P0 第 3 项;`ciphers.ts:2433,1659,102,1150`)。
- 组织 cipher 写不 bump 其他成员 revision(见 P1);已有 `bumpAccountRevisionDateByOrganizationId`(`organizations.ts:150`)但 ciphers.ts 从不调用。
- sync 中 owner/admin 拿到全组织 cipher(`sync.ts:291`,官方 admin 全库视图走专用端点);权限标志硬编码 edit/viewPassword/permissions 恒 true(`ciphers.ts:348`、`sync.ts:384`);collection 响应缺 manage/externalId/type。
- purge 语义错误(`ciphers.ts:1901`:只删已软删,忽略 orgId;官方无 orgId 清空整个个人库);单条/批量软删/恢复/移动仅限个人条目(组织条目 404);组织 cipher 创建保留 userId、/create 丢 collection(`ciphers.ts:937,1020`)。
- lastKnownRevisionDate 冲突检测缺失(见 P1)。
- share 语义缺口:`/attachment/:id/share` 是 no-op 丢弃重加密文件(`ciphers.ts:879`);批量 share 静默跳过非自有;缺存储校验;事件记 1101 应为 1105。
- 附件配额/大小限制缺失(官方 500MB + 配额);v1 上传/删除不 bump revision;renew 无校验(`ciphers.ts:744`);admin 附件/单删端点缺路由。
- 组织导出含成员个人条目(无 includeMemberItems);组织导入忽略 folders、per-collection 授权近似、残留 4 条 console.log(`ciphers.ts:1411`)、无事务。
- 文件夹删除不清理 cipher 引用(悬空 folderId);sync 杂项:未过滤禁用组织、globalEquivalentDomains 仅 5 组、未按客户端版本过滤新 cipher 类型。
- attachment-token 签名非常量时间比较(`attachment-token.ts:34`)。

**未实现**:SecurityTask 全部业务逻辑(`tasks.ts` stub:complete/bulk-create/metrics/软删联动)、`DELETE /folders/all`、EncryptedFor 校验、FIDO2 最低客户端版本校验、emergency access 附件下载、批量 500 上限的分批保护。

### 4. Send

**已实现**:CRUD 全套 + remove-password/remove-auth、text/file 两类型、accessId 编码(.NET Guid 小端序)、匿名访问判定顺序、accessCount 递增语义、send_access token 流、文件 v2 上传流、Send 策略强制(DisableSend/SendOptions/SendControls)、定时清理、推送 + accountRevision、响应 object 字段。

**偏差**:
- 编辑清除密码保护(见 P1,`sends.ts:755`)+ 忽略 `authType` 字段。
- 匿名访问不推送、不 bump 账户修订(`sends.ts:355`);token 化访问反而篡改 revisionDate(`sends.ts:443`)。
- `creatorIdentifier` 缺失(`sends.ts:281`)→ hideEmail 开关形同虚设(等效永远隐藏)。
- 密码错误无 2s 防爆破延迟;固定盐密码哈希(`crypto.ts:75`);access token 失效返回 404 而非 401;上传大小要求精确匹配(官方 ±1MB 容差);日期校验缺失(可造永久 Send、expiration>deletion);模型级验证缺失(maxAccessCount≥1、emails 规范化/2500 上限)。

**未实现**:premium/存储配额门槛(免费账户可无限文件 Send)、Send 事件日志(企业审计无 Send 活动)、组织 Send 分支(官方也未启用)。

### 5. 组织核心(Organizations/成员/Groups/Collections/Policies)

**已实现**:组织 CRUD、初始集合、API Key、事件分页;成员生命周期部分(revoke-self 最后 Owner 保护 + 1518、auto-confirm 单/批量 + 复检、restore 策略复检、账户恢复重置密码 + 1508/1519);claimed domain/accounts 语义;Policies 框架(PolicyType 0-21、依赖图、MasterPassword/SendOptions/ResetPassword 数据校验、聚合需求);同步副作用(AccountRevisionDate + SyncOrgKeys/SyncOrganizations/SyncVault)。

**偏差**(安全类):reset-password-enrollment 无鉴权、remove 别名缺保护、POST keys 任意覆盖、accept 跳过邮箱匹配、recover-account 缺角色层级(均见 P0);invite 角色提权 + 不校验被邀角色 + 丢 permissions/groups + 无席位校验(`organizations.ts:2419`);成员更新缺最后 Owner 保护 + groups 不处理 + Custom 校验缺失(`organizations.ts:2990`);confirm 不做策略复检(`organizations.ts:2589`);restore 缺自我/Owner 层级校验;组织删除不验证主密码(`organizations.ts:1461`)。

**偏差**(权限门/信息暴露):GET /:id/users 对所有成员开放(泄露全员邮箱/角色/2FA,`organizations.ts:1715`,includeCollections 被忽略);集合列表泄露(`organizations.ts:4058`、`collections.ts:21`);policies GET/PUT 仅 Owner/Admin 不含 Custom;`GET /:id/policies/token` 语义反转(`organizations.ts:4696`:应匿名 + 校验邀请 token,实为登录 + 不校验 token)。

**偏差**(集合授权 V1):create 强制 Owner/Admin 且丢 users/groups 授权(`organizations.ts:3243`);update/delete 缺按集合 Manage 路径;DefaultUserCollection 类型语义缺失。

**偏差**(策略副作用):TwoFactor 启用只撤 Confirmed 不含 Accepted、用字符串非空判定 2FA、缺无主密码保护、不发邮件/不记 1520(`organizations.ts:4582`);SingleOrg 副作用漏 Accepted/Revoked(`organizations.ts:4541`);OrganizationDataOwnership 被错加 SingleOrg 依赖(`policy-validators.ts:85`);策略推送用 SyncVault 而非 PolicyChanged。

**偏差**(事件码错位,管理端审计误导):策略更新记 1300(应 1700)、revoke 记 1503(应 1511)、restore 记 1505(应 1512)、claimed 删除记 1503(应 1515)、leave 记 1504(应 1516)、accept 记 1501(官方 accept 不记)。

**未实现**:席位管理与校验、批量移除成员端点、InitPendingOrganization(accept-init)、OrganizationDataOwnership 默认集合副作用(`policy-requirements.ts:519` 空壳)、策略撤销通知邮件 + 1520/1521、delete-recover-token、Provider 全部、免费版 admin 数限制。

### 6. 组织扩展(域名/审批/邀请链接/License/组织 2FA)

**已实现**:域名端点全 + 权限(manageSso)+ TXT 生成 + DoH 验证 + 冲突检查 + 验证后启用 SingleOrg + claimed 限制 + `/domain/sso/verified`;组织 auth requests 三端点 + ManageResetPassword + 密钥交付(approve 必带 encryptedUserKey)+ 7 天过期 + 1513/1514 + approve 推送;邀请链接管理 5 端点 + 1624-1628 + 匿名公共端点 + 接受流程主干;license 三端点 + CanUse 基础校验 + LicenseKey 唯一性 + 创建 owner/默认集合;组织 Duo(get-duo/put duo 密码验证 + health check + secret 加密存 duo_configs + 登录侧 type 6 生效)。

**偏差**:
- **license 更新无 Owner 校验(见 P0,`organization-licenses.ts:438`)**;无签名/Hash 校验;无降级保护(可上传低配 license 关掉在用功能位产生僵尸配置);创建忽略 keys 表单字段(组织无密钥对 → 账户恢复不可用);MaxStorageGb 语义不同;sync 端点尾斜杠路由可能 404(`organization-licenses.ts:579`);无周期性 license 复核(过期永不失效)。
- 定时任务反验证已验证域名(`scheduled.ts:287`:官方只复检 `verifiedDate IS NULL`)→ 删 TXT 后 24h 内静默取消认领;verify 已验证域名不返回 409;验证失败不记 2003;验证成功不发认领邮件;SingleOrg 启用绕过 SavePolicyCommand 管线;重试调度 24h 固定(官方 12/24/36h + 72h 提醒邮件);创建多了 useOrganizationDomains 门槛。
- 批量 auth request 失败即中断且部分提交(`organization-auth-requests.ts:241`,官方逐条容错继续);pending 列表过滤过期(官方不过滤);approve 后不发 `SendTrustedDeviceAdminApprovalEmail`。
- 邀请链接 status 端点 sso 恒 null(`organization-invite-links.ts:180`)→ 强制 SSO 组织流程断裂;AutoConfirm 时不删用户 Emergency Access;resetPasswordKey 不校验格式;接受后不发管理员邮件。
- 组织 Duo 端点权限过严(用 owner/admin 应为 managePolicies);二次验证只支持主密码(无 OTP);disable 不清 duo_configs 密文;无事件日志。

**未实现**:域名验证失败/过期提醒邮件;云端 Billing Sync;邀请链接 confirmation 预检消费端点(官方也未暴露)。

### 7. 2FA / WebAuthn

**已实现**:Authenticator(TOTP)核心(SHA1/6 位/30s/±1 窗口)、Email 2FA 骨架、WebAuthn 作 2FA 注册/删除(挑战、excludeCredentials、上限 5/10、不允许删最后一把)、多数受保护端点密码验证、recovery code 核心、Passkey 凭证管理(prfStatus、attestation/assertion options、PRF 三元组、keyset 轮换)、Passkey 无密码登录(HMAC token、userHandle 解析、COSE 签名验证、PRF 解密选项)、twoFactorEnabled 口径一致、2FA 用户跳过新设备验证。

**偏差**(安全):authenticator userVerificationToken 可伪造(P0 #4);GET /recover 无密码返回恢复码(P0 #5);登录 WebAuthn 2FA 不校验 challenge 可重放(`identity.ts:981`);TOTP 无防重放缓存(见 P1);remember 2FA(provider 5)缺失(见 P1);Email 挑战缺打码邮箱/SsoEmail2faSessionToken(`identity.ts:819`);恢复码使用后缺副作用(不发邮件、不记 1004、不做组织 2FA revoke,`identity.ts:943`);禁用 2FA 无组织策略副作用 + 误删恢复码 + 无事件(`two-factor.ts:498`);登录 2FA 失败无告警邮件/失败计数;send-email-login 缺 AuthRequestAccessCode 路径(`two-factor.ts:35`,「用设备登录 + Email 2FA」卡死);Passkey 无数量上限 + 响应模型偏差 + challenge 未强制单次 + UV flag 未校验(`webauthn.ts:274,369`)。

**未实现**:个人 Duo、YubiKey OTP、组织 Duo 登录流(配置存在但登录不生效)、U2F AppID 扩展、RequireSso 对 passkey 创建限制、premium 对 2FA 的门槛。

### 8. 设备 / AuthRequest / 紧急访问

**设备已实现**:端点面完整(列表/查询/密钥更新/untrust/lost-trust/token/web-push-auth/knowndevice/deactivate)、设备密钥更新、untrust、deactivate 删 refresh。

**设备偏差**:update-trust 不强制验证(P0 #9)+ 轮换语义不完整(不自动 untrust 未列出的 trusted 设备,`devices.ts:296`);DELETE 不清设备信任密钥(`devices.ts:449`);`devicePendingAuthRequest` 恒 null(`devices.ts:60`,设备管理页看不到待批准登录);knowndevice 过滤 active(`devices.ts:140`);PUT 强制 active:true 可复活停用设备;推送注册副作用缺失(organizationIds 恒空);无 (userId,identifier) 唯一约束。

**AuthRequest 已实现**:端点完整、三种 TTL 正确、匿名不泄露存在性、批准才写 key、拒绝不推送、pending 按设备取最新、identity 登录消费防重放、组织审批(ManageResetPassword + 7 天 + 1513/1514)。

**AuthRequest 偏差**:cron 无差别 15min 删除(P1,摧毁 TDE 审批,`scheduled.ts:178`);PUT 缺「最近请求」批准校验(`auth-requests.ts:391`,反钓鱼);创建未实现 KnownDevicesOnly(推送疲劳攻击面);admin-request 缺管理员通知邮件;组织批准后缺用户邮件;pending 未按类型过滤且缺 requestDeviceId;accessCode 非常量时间;origin 硬编码 `bitwarden-workers`、requestCountryName 恒 null。

**紧急访问**:`emergency-access.ts`(206 行)是纯占位——所有写操作返回假成功(P1),schema 无 emergency_access 表落地流程。未实现:数据表、invite/accept/confirm(密钥托管)、initiate/approve/reject 状态机、等待期自动批准 job、takeover 托管密钥、password 接管副作用(清 2FA/移出组织)、view(grantor ciphers)、附件下载、policies、全套邮件模板、密钥轮换时的 EA 重加密。

### 9. 平台(通知/推送/事件/config/icons/reports/plans/HIBP/计划任务)

**已实现**:SignalR 协议兼容层(MessagePack、handshake、Ping、Invocation 帧、PascalCase、保留官方拼写错误 `AuthRequestResponseRecieved`)、通知中心 API(read/deleted 过滤、pageSize 10-1000、NotificationStatus 推送)、事件核心(/events/collect 双挂载、30/367 天范围、游标分页、组织权限)、equivalent domains 读写、Icons 服务(默认图标字节一致、SSRF 防护更严)、Reports(1093 行,覆盖度高:password-health/member-access/member-cipher-details/report CRUD/文件上传 501MB)、计划任务核心(Send 删除/回收站/过期 grant/紧急访问超时/域名复验)、Web Push(RFC 8291/8292 自研,但见下方死代码)。

**偏差**:全局等价域名仅 5 组 + Type 编号错 + 忽略 excludedGlobalEquivalentDomains(见 P1);/config 的 vapidPublicKey 恒 null(`config.ts:52`,使 Web Push 栈对客户端不可达)、version 硬编码、featureStates 仅 8 个;Hub 分组无 ClientType/Installation、组织成员未过滤 status=2(`hub.ts:63`);组织密文推送 collectionIds 恒 null;/collect 缺事件类型(1119-1132、1522、1627、2400-2402)+ 不校验上报者成员身份(P0 #11)+ 不记 ipAddress;事件查询缺口(cipher 事件仅 50 条无分页、无 `/organizations/{id}/users/{id}/events`);通知中心不按 clientType 过滤;域名复验反验证已验证域名(见组织扩展);plans 仅 4 个年付计划;setup-intent 返回假 Stripe secret(`setup-intent.ts`,前端 Stripe.js 会初始化失败)。

**未实现**:HIBP `/api/hibp/breach`(P1);PushType 生产者缺口(PolicyChanged 25 无推送、SyncOrganizationStatusChanged 18 零调用点、PremiumStatusChanged 27);计划任务缺失(auth request cron bug、EmergencyAccessNotificationJob、RecoveryApproved/TimedOut 邮件、ValidateUsers/OrganizationsJob license 复核);Icons `~/config` 与 ChangePasswordUriController。

### 10. 顶层缺失模块

**(a) 对个人用户无影响**:Billing 计费服务(Stripe/PayPal/Apple/BitPay webhook)、EventsProcessor(workers 直写 D1)、Installations、Admin Razor 门户(由 system-admin.ts 自建 API 替代)。

**(b) 影响企业/商业功能**:SSO 全链路(仅简化 OIDC,缺 SAML/authorization_code/SsoController/TDE/Key Connector)、SCIM、Secrets Manager(无 `/sm` 路由)、Provider/MSP、公共 API `/api/public/*` + client_credentials(Directory Connector/SIEM/自动化)、Key Connector、OrganizationConnections(仅 GET /connections/enabled)、Dirt 集成(Slack/Teams)。

**(c) 影响个人可感知功能**:HIBP、用户 API key + client_credentials(CLI)、POST /accounts/kdf、OrganizationExport、OrganizationSponsorships(免费家庭版)、账户散件(verify-email/delete-recover/set-password/update-temp-password/verify-devices/request-otp)、存根类(SecurityTask/Premium 订阅/Duo/Yubikey)。

**路径映射**:整体正确。官方五服务前缀(/api、/identity、/notifications、/events/collect、/icons)均覆盖;附件匿名下载刻意注册在认证路由前;尾斜杠有全局规范化。潜在隐患:`/api/organizations/licenses` 挂载在通配 `organizationsRoutes` 之后(目前无冲突);/sso、/scim 前缀未挂载(SSO 靠 identity 友好报错,SCIM 直接 404)。

---

## 修复优先级建议

**P0(安全,尽快)**:上表第 1-11 项越权/绕过 + refresh token 校验 securityStamp。纯逻辑修复,不涉架构。

**P1(破坏官方客户端核心流程)**:auth request cron 类型化 TTL、Send 编辑保留密码、client_credentials/API key、KDF 端点、update-temp-password、email 端点方法、2FA remember、新设备验证豁免规则、密钥轮换完整性校验、紧急访问改成明确报错或真实实现。

**P2(功能完善)**:紧急访问真实实现、HIBP 代理、等价域名对齐、Security Task 闭环、组织 cipher 跨成员 revision、冲突检测、事件类型码修正、组织细粒度授权(Custom 权限/按集合 Manage/最后 Owner 保护)。

**P3(取舍项)**:Duo/YubiKey、组织级 2FA 生效、防重放缓存、防枚举延迟、各类副作用邮件、V2 加密体系。企业模块(SSO/SCIM/SM/Provider)按产品定位决定是否补。
