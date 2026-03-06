/**
 * Bitwarden Workers - Accounts 路由
 * 对应原始项目 Api/Auth/Controllers/AccountsController.cs
 * 处理：Profile、Keys、Password、Revision Date
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users, organizations, organizationUsers } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateSecureRandomString, verifyPassword } from '../services/crypto';
import type { Bindings, Variables, ProfileResponse, AccountKeysResponse } from '../types';
import { pushLogOut, pushSyncUser } from '../services/push-notification';
import { PushType } from '../types/push-notification';

const accounts = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * POST /api/accounts/register
 * 用户注册 (免鉴权)
 */
accounts.post('/register', async (c) => {
    const body = await c.req.json<any>(); // Reusing specific types or any for simplicity as it was imported in identity

    if (!body.email || !body.masterPasswordHash) {
        throw new BadRequestError('Email and master password hash are required.');
    }

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    // 检查邮箱是否已注册
    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (existing) {
        throw new BadRequestError('Email is already taken.');
    }

    const now = new Date().toISOString();
    const userId = crypto.randomUUID(); // generateUuid is in crypto.ts, we'll assume it's imported or we use crypto.randomUUID

    await db.insert(users).values({
        id: userId,
        name: body.name || null,
        email,
        emailVerified: false,
        masterPassword: body.masterPasswordHash,
        masterPasswordHint: body.masterPasswordHint || null,
        culture: 'en-US',
        securityStamp: generateSecureRandomString(50),
        key: body.key,
        publicKey: body.keys?.publicKey || null,
        privateKey: body.keys?.encryptedPrivateKey || null,
        kdf: body.kdf ?? 0,
        kdfIterations: body.kdfIterations ?? 600000,
        kdfMemory: body.kdfMemory ?? null,
        kdfParallelism: body.kdfParallelism ?? null,
        apiKey: generateSecureRandomString(30),
        accountRevisionDate: now,
        creationDate: now,
        revisionDate: now,
    });

    return c.json(null, 200);
});

// 其他端点都需要认证
accounts.use('/*', authMiddleware);

/**
 * 构建 ProfileResponse - 对应 ProfileResponseModel.cs
 */
function hasTwoFactorEnabled(user: any): boolean {
    if (!user.twoFactorProviders) return false;
    try {
        const providers = JSON.parse(user.twoFactorProviders);
        return Object.values(providers).some((p: any) => p.enabled);
    } catch {
        return false;
    }
}

function toProfileResponse(user: any, env: Bindings): ProfileResponse {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        premium: user.premium || String(env.GLOBAL_PREMIUM).toLowerCase() === 'true',
        premiumFromOrganization: false, // 个人用户无组织 premium
        masterPasswordHint: user.masterPasswordHint,
        culture: user.culture,
        twoFactorEnabled: hasTwoFactorEnabled(user),
        key: user.key,
        privateKey: user.privateKey,
        accountKeys: buildAccountKeys(user),
        securityStamp: user.securityStamp,
        forcePasswordReset: user.forcePasswordReset,
        usesKeyConnector: user.usesKeyConnector,
        avatarColor: user.avatarColor,
        creationDate: user.creationDate,
        verifyDevices: true, // 默认开启设备验证
        object: 'profile',
        organizations: [],
        providers: [],
        providerOrganizations: [],
    };
}

function buildAccountKeys(user: any): AccountKeysResponse | null {
    const accountKeys: AccountKeysResponse | null = (user.publicKey && user.privateKey) ? {
        publicKeyEncryptionKeyPair: {
            publicKey: user.publicKey,
            wrappedPrivateKey: user.privateKey,
            signedPublicKey: user.signedPublicKey || null,
        },
        signatureKeyPair: null,
        securityState: null,
        object: 'privateKeys',
    } : null;
    return accountKeys;
}

/**
 * GET /api/accounts/profile
 * 对应 AccountsController.GetProfile
 */
accounts.get('/profile', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        throw new NotFoundError('User not found.');
    }

    // 获取组织数据
    const orgsData = await db
        .select({
            org: organizations,
            orgUser: organizationUsers,
        })
        .from(organizationUsers)
        .innerJoin(organizations, eq(organizations.id, organizationUsers.organizationId))
        .where(eq(organizationUsers.userId, userId))
        .all();

    const globalPremium = String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true';

    const profileOrgs = orgsData.map(d => ({
        id: d.org.id,
        name: d.org.name,
        key: d.orgUser.key,
        status: d.orgUser.status,
        type: d.orgUser.type,
        enabled: d.org.enabled,
        useTotp: d.org.useTotp ?? true,
        use2fa: true,
        useApi: true,
        useSso: false,
        useKeyConnector: false,
        useScim: false,
        useGroups: false,
        useDirectory: false,
        useEvents: true,
        usePolicies: true,
        useResetPassword: false,
        useCustomPermissions: false,
        useActivateAutofillPolicy: false,
        useRiskInsights: false,
        useOrganizationDomains: false,
        useAdminSponsoredFamilies: false,
        useSecretsManager: false,
        usePhishingBlocker: false,
        useDisableSMAdsForUsers: false,
        usePasswordManager: true,
        useMyItems: true,
        useAutomaticUserConfirmation: false,
        usersGetPremium: globalPremium || (d.org.planType ?? 0) >= 1,
        keyConnectorEnabled: false,
        maxStorageGb: d.org.maxStorageGb ?? 1,
        seats: d.org.seats ?? 0,
        maxCollections: null,
        accessSecretsManager: false,
        planProductType: d.org.planType ?? 0,
        permissions: d.orgUser.permissions ? JSON.parse(d.orgUser.permissions) : null,
        object: 'profileOrganization',
    }));

    const response = toProfileResponse(user, c.env);
    response.organizations = profileOrgs;

    // 更新 premiumFromOrganization
    const premiumFromOrg = profileOrgs.some(o => o.enabled && o.usersGetPremium);
    if (premiumFromOrg) {
        response.premiumFromOrganization = true;
        response.premium = true;
    }

    return c.json(response);
});

/**
 * PUT /api/accounts/profile
 * 对应 AccountsController.PutProfile
 */
accounts.put('/profile', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ name?: string; masterPasswordHint?: string }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        throw new NotFoundError('User not found.');
    }

    const now = new Date().toISOString();
    await db.update(users).set({
        name: body.name !== undefined ? body.name : user.name,
        masterPasswordHint: body.masterPasswordHint !== undefined ? body.masterPasswordHint : user.masterPasswordHint,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const updated = await db.select().from(users).where(eq(users.id, userId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncSettings, userId, contextId));

    return c.json(toProfileResponse(updated!, c.env));
});

/**
 * POST /api/accounts/profile (alias for PUT)
 */
accounts.post('/profile', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ name?: string; masterPasswordHint?: string }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const now = new Date().toISOString();
    await db.update(users).set({
        name: body.name !== undefined ? body.name : user.name,
        masterPasswordHint: body.masterPasswordHint !== undefined ? body.masterPasswordHint : user.masterPasswordHint,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const updated = await db.select().from(users).where(eq(users.id, userId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncSettings, userId, contextId));

    return c.json(toProfileResponse(updated!, c.env));
});

/**
 * GET /api/accounts/revision-date
 * 对应 AccountsController.GetAccountRevisionDate
 */
accounts.get('/revision-date', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select({ accountRevisionDate: users.accountRevisionDate })
        .from(users)
        .where(eq(users.id, userId))
        .get();

    // 官方实现：如果无法获取用户或修订时间，返回 200 + null（long?）
    if (!user || !user.accountRevisionDate) {
        return c.json(null);
    }

    // Bitwarden 返回毫秒时间戳（epoch ms）
    return c.json(new Date(user.accountRevisionDate).getTime());
});

/**
 * GET /api/accounts/subscription
 * 对应 Billing/Controllers/AccountsController.GetSubscriptionAsync（自托管简化版）
 *
 * 自托管环境下官方实现只是基于 User 与 License 构建 SubscriptionResponseModel，
 * 未关联 Stripe 等外部网关。Workers 目前未持久化用户存储/License 信息，
 * 因此这里返回一个最小且结构兼容的响应，确保 Web/iOS/桌面客户端能够正常渲染
 * 「订阅」页面，而不会 404。
 */
accounts.get('/subscription', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        throw new NotFoundError('User not found.');
    }

    // 目前未单独记录个人订阅/存储信息，自托管场景下保持简单：
    // - storageName: null（不展示）
    // - storageGb: 0
    // - maxStorageGb: 1（与组织默认一致，仅用于 UI 展示）
    // - subscription / upcomingInvoice / customerDiscount / license: null
    // - expiration: null（不展示到期时间）
    return c.json({
        storageName: null,
        storageGb: 0,
        maxStorageGb: 1,
        subscription: null,
        upcomingInvoice: null,
        customerDiscount: null,
        license: null,
        expiration: null,
        object: 'subscription',
    });
});

/**
 * GET /api/accounts/keys
 * 对应 AccountsController.GetKeys
 */
accounts.get('/keys', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select({
        key: users.key,
        publicKey: users.publicKey,
        privateKey: users.privateKey,
    }).from(users).where(eq(users.id, userId)).get();

    if (!user) {
        throw new NotFoundError('User not found.');
    }

    return c.json({
        key: user.key,
        publicKey: user.publicKey,
        privateKey: user.privateKey,
        object: 'keys',
    });
});

/**
 * POST /api/accounts/keys
 * 对应 AccountsController.PostKeys
 */
accounts.post('/keys', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ publicKey: string; encryptedPrivateKey: string }>();

    if (!body.publicKey || !body.encryptedPrivateKey) {
        throw new BadRequestError('Public key and encrypted private key are required.');
    }

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    // 如果已有密钥，不允许覆盖
    if (user.publicKey && user.privateKey) {
        throw new BadRequestError('Keys already exist.');
    }

    const now = new Date().toISOString();
    await db.update(users).set({
        publicKey: body.publicKey,
        privateKey: body.encryptedPrivateKey,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncSettings, userId, contextId));

    return c.json({
        key: user.key,
        publicKey: body.publicKey,
        privateKey: body.encryptedPrivateKey,
        object: 'keys',
    });
});

/**
 * POST /api/accounts/password
 * 对应 AccountsController.PostPassword
 */
accounts.post('/password', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        masterPasswordHash: string;
        newMasterPasswordHash: string;
        masterPasswordHint?: string;
        key: string;
    }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    // 验证当前密码
    const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
    if (!valid) {
        throw new BadRequestError('Invalid current password.');
    }

    const now = new Date().toISOString();
    await db.update(users).set({
        masterPassword: body.newMasterPasswordHash,
        masterPasswordHint: body.masterPasswordHint ?? user.masterPasswordHint,
        securityStamp: generateSecureRandomString(50),
        key: body.key,
        revisionDate: now,
        accountRevisionDate: now,
        lastPasswordChangeDate: now,
    }).where(eq(users.id, userId));

    // 密码变更后通知其他设备登出
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushLogOut(c.env, userId, contextId));

    return c.body(null, 204);
});

/**
 * POST /api/accounts/password-hint
 * 对应 AccountsController.PostPasswordHint
 */
accounts.post('/password-hint', async (c) => {
    // 安全考虑：不管邮箱是否存在都返回 200
    return c.json(null, 200);
});

/**
 * PUT /api/accounts/avatar
 * 对应 AccountsController.PutAvatar
 */
accounts.put('/avatar', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ avatarColor?: string | null }>();

    const now = new Date().toISOString();
    await db.update(users).set({
        avatarColor: body.avatarColor ?? null,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const updated = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!updated) throw new NotFoundError('User not found.');
    return c.json(toProfileResponse(updated, c.env));
});

/**
 * POST /api/accounts/verify-password
 * 对应 AccountsController.PostVerifyPassword
 */
accounts.post('/verify-password', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ masterPasswordHash: string }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
    if (!valid) throw new BadRequestError('Invalid master password.');

    return c.json({ masterPasswordPolicy: null });
});

/**
 * POST /api/accounts/security-stamp
 * 对应 AccountsController.PostSecurityStamp - 刷新安全戳（使所有 token 失效）
 */
accounts.post('/security-stamp', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ masterPasswordHash: string }>().catch(() => ({ masterPasswordHash: '' }));

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    if (body.masterPasswordHash) {
        const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
        if (!valid) throw new BadRequestError('Invalid master password.');
    }

    const now = new Date().toISOString();
    await db.update(users).set({
        securityStamp: generateSecureRandomString(50),
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushLogOut(c.env, userId, contextId));

    return c.body(null, 204);
});

/**
 * POST /api/accounts/email-token
 * 发送邮箱变更验证码（stub - 不真正发邮件，直接返回成功）
 */
accounts.post('/email-token', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ masterPasswordHash: string; newEmail: string }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
    if (!valid) throw new BadRequestError('Invalid master password.');

    return c.body(null, 204);
});

/**
 * PUT /api/accounts/email
 * 对应 AccountsController.PutEmail - 更新邮箱地址
 */
accounts.put('/email', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        masterPasswordHash: string;
        newEmail: string;
        newMasterPasswordHash: string;
        token: string;
        key: string;
    }>();

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
    if (!valid) throw new BadRequestError('Invalid master password.');

    const newEmail = body.newEmail.toLowerCase().trim();
    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, newEmail)).get();
    if (existing && existing.id !== userId) throw new BadRequestError('Email already taken.');

    const now = new Date().toISOString();
    await db.update(users).set({
        email: newEmail,
        masterPassword: body.newMasterPasswordHash || user.masterPassword,
        key: body.key || user.key,
        securityStamp: generateSecureRandomString(50),
        revisionDate: now,
        accountRevisionDate: now,
        lastEmailChangeDate: now,
    }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushLogOut(c.env, userId, contextId));

    return c.body(null, 204);
});

/**
 * DELETE /api/accounts
 * 对应 AccountsController.Delete - 删除账户
 */
accounts.delete('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ masterPasswordHash: string }>().catch(() => ({ masterPasswordHash: '' }));

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    if (body.masterPasswordHash) {
        const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
        if (!valid) throw new BadRequestError('Invalid master password.');
    }

    await db.delete(users).where(eq(users.id, userId));

    return c.body(null, 204);
});

export default accounts;
