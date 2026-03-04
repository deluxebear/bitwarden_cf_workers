/**
 * Bitwarden Workers - TwoFactor 路由
 * 对应原始项目 Api/Auth/Controllers/TwoFactorController.cs
 */

import { Hono, Context } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError } from '../middleware/error';
import { verifyPassword, generateSecureRandomString } from '../services/crypto';
import { generateAuthenticatorKey, verifyAuthenticatorCode } from '../services/totp';
import type {
    Bindings, Variables, TwoFactorProviderType, TwoFactorProviderResponse,
    TwoFactorAuthenticatorResponse, TwoFactorRecoverResponse, TwoFactorProvider
} from '../types';

const twoFactor = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有 2FA 配置端点都需要认证
twoFactor.use('/*', authMiddleware);

/**
 * 验证 Secret (master password hash)
 */
async function verifySecret(db: any, userId: string, secret: string) {
    if (!secret) throw new BadRequestError('User verification failed.');
    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new BadRequestError('User verification failed.');

    const ok = await verifyPassword(secret, user.masterPassword);
    if (!ok) throw new BadRequestError('User verification failed.');
    return user;
}

/**
 * 解析用户的 providers JSON
 */
function getProviders(user: any): Record<number, TwoFactorProvider> {
    if (!user.twoFactorProviders) return {};
    try {
        return JSON.parse(user.twoFactorProviders);
    } catch {
        return {};
    }
}

/**
 * GET /api/two-factor
 * 获取所有已配置的 2FA 提供商
 */
twoFactor.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const user = await db.select().from(users).where(eq(users.id, userId)).get();

    const providers = getProviders(user);
    const responseData: TwoFactorProviderResponse[] = Object.keys(providers).map(type => ({
        type: parseInt(type, 10),
        enabled: providers[type as any].enabled,
        object: 'twoFactorProvider',
    }));

    return c.json({
        data: responseData,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/two-factor/get-authenticator
 * 验证密码并获取 Authenticator Key
 */
twoFactor.post('/get-authenticator', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ secret: string }>();

    const user = await verifySecret(db, userId, body.secret);
    const providers = getProviders(user);
    const authProvider = providers[0]; // TwoFactorProviderType.Authenticator

    let key: string;
    let enabled: boolean = false;

    if (authProvider && authProvider.metaData?.Key) {
        key = authProvider.metaData.Key;
        enabled = authProvider.enabled;
    } else {
        key = generateAuthenticatorKey();
    }

    const userVerificationToken = btoa(JSON.stringify({ userId, key }));

    const response: TwoFactorAuthenticatorResponse = {
        enabled,
        key,
        userVerificationToken,
        object: 'twoFactorAuthenticator',
    };

    return c.json(response);
});

/**
 * 处理 PUT 和 POST /authenticator
 */
async function enableAuthenticator(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ token: string; key: string; userVerificationToken: string }>();

    if (!body.userVerificationToken) {
        throw new BadRequestError('User verification failed.');
    }

    if (!verifyAuthenticatorCode(body.key, body.token)) {
        throw new BadRequestError('Invalid token.');
    }

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    const providers = getProviders(user);

    providers[0] = {
        metaData: { Key: body.key },
        enabled: true,
    };

    const now = new Date().toISOString();
    let recoveryCode = user!.twoFactorRecoveryCode;
    if (!recoveryCode) {
        recoveryCode = generateSecureRandomString(32);
    }

    await db.update(users).set({
        twoFactorProviders: JSON.stringify(providers),
        twoFactorRecoveryCode: recoveryCode,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const response: TwoFactorAuthenticatorResponse = {
        enabled: true,
        key: body.key,
        userVerificationToken: null,
        object: 'twoFactorAuthenticator',
    };

    return c.json(response);
}

twoFactor.put('/authenticator', enableAuthenticator);
twoFactor.post('/authenticator', enableAuthenticator);

/**
 * 处理 PUT 和 POST /disable
 */
async function disableProvider(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ type: number; secret: string }>();

    const user = await verifySecret(db, userId, body.secret);
    const providers = getProviders(user);

    if (providers[body.type]) {
        delete providers[body.type];

        const now = new Date().toISOString();
        const updateData: any = {
            twoFactorProviders: JSON.stringify(providers),
            accountRevisionDate: now,
        };

        // 如果没有任何启用的提供商了，删除恢复代码
        if (Object.keys(providers).length === 0) {
            updateData.twoFactorRecoveryCode = null;
        }

        await db.update(users).set(updateData).where(eq(users.id, userId));
    }

    return c.json({
        type: body.type,
        enabled: false,
        object: 'twoFactorProvider',
    });
}

twoFactor.put('/disable', disableProvider);
twoFactor.post('/disable', disableProvider);

/**
 * POST /api/two-factor/get-recover
 * 获取现有的两步验证恢复代码
 */
twoFactor.post('/get-recover', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ secret: string }>();

    const user = await verifySecret(db, userId, body.secret);

    const code = user.twoFactorRecoveryCode || generateSecureRandomString(32);

    if (!user.twoFactorRecoveryCode && Object.keys(getProviders(user)).length > 0) {
        await db.update(users).set({ twoFactorRecoveryCode: code }).where(eq(users.id, userId));
    }

    const response: TwoFactorRecoverResponse = {
        code,
        object: 'twoFactorRecover',
    };

    return c.json(response);
});

/**
 * GET /api/two-factor/recover
 * 获取现有的两步验证恢复代码 (无密码验证)
 */
twoFactor.get('/recover', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new BadRequestError('User not found.');

    const code = user.twoFactorRecoveryCode || generateSecureRandomString(32);

    if (!user.twoFactorRecoveryCode && Object.keys(getProviders(user)).length > 0) {
        await db.update(users).set({ twoFactorRecoveryCode: code }).where(eq(users.id, userId));
    }

    const response: TwoFactorRecoverResponse = {
        code,
        object: 'twoFactorRecover',
    };

    return c.json(response);
});

/**
 * POST /api/two-factor/recover
 * 重新生成恢复代码
 */
twoFactor.post('/recover', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ secret: string }>();

    await verifySecret(db, userId, body.secret);

    const code = generateSecureRandomString(32);
    await db.update(users).set({ twoFactorRecoveryCode: code }).where(eq(users.id, userId));

    const response: TwoFactorRecoverResponse = {
        code,
        object: 'twoFactorRecover',
    };

    return c.json(response);
});

export default twoFactor;
