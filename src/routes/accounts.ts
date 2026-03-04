/**
 * Bitwarden Workers - Accounts 路由
 * 对应原始项目 Api/Auth/Controllers/AccountsController.cs
 * 处理：Profile、Keys、Password、Revision Date
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateSecureRandomString, verifyPassword } from '../services/crypto';
import type { Bindings, Variables, ProfileResponse, AccountKeysResponse } from '../types';

const accounts = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有端点都需要认证
accounts.use('/*', authMiddleware);

/**
 * 构建 ProfileResponse - 对应 ProfileResponseModel.cs
 */
function toProfileResponse(user: any): ProfileResponse {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        premium: user.premium,
        premiumFromOrganization: false, // 个人用户无组织 premium
        masterPasswordHint: user.masterPasswordHint,
        culture: user.culture,
        twoFactorEnabled: false,
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
    if (!user.publicKey && !user.privateKey) return null;
    return {
        accountPublicKey: user.publicKey || null,
        accountEncryptedPrivateKey: user.privateKey || null,
        signedPublicKey: user.signedPublicKey || null,
        object: 'accountKeys',
    };
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

    return c.json(toProfileResponse(user));
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
    return c.json(toProfileResponse(updated!));
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
    return c.json(toProfileResponse(updated!));
});

/**
 * GET /api/accounts/revision-date
 * 对应 AccountsController.GetAccountRevisionDate
 */
accounts.get('/revision-date', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select({ accountRevisionDate: users.accountRevisionDate })
        .from(users).where(eq(users.id, userId)).get();

    if (!user) {
        throw new NotFoundError('User not found.');
    }

    // Bitwarden 返回毫秒时间戳
    return c.json(new Date(user.accountRevisionDate).getTime());
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

    return c.json(null, 200);
});

/**
 * POST /api/accounts/password-hint
 * 对应 AccountsController.PostPasswordHint
 */
accounts.post('/password-hint', async (c) => {
    const body = await c.req.json<{ email: string }>();

    // 安全考虑：不管邮箱是否存在都返回 200
    return c.json(null, 200);
});

export default accounts;
