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
import {
    startWebAuthnRegistration,
    completeWebAuthnRegistration,
    deleteWebAuthnCredential,
    getWebAuthnProvider,
    getRegisteredKeys,
} from '../services/webauthn';
import type {
    Bindings, Variables, TwoFactorProviderResponse,
    TwoFactorAuthenticatorResponse, TwoFactorRecoverResponse, TwoFactorProvider
} from '../types';
import { TwoFactorProviderType } from '../types';

const twoFactor = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * POST /api/two-factor/send-email-login
 * 登录过程发送 Email 2FA 验证码。此端点必须匿名可访问，但仍要求 secret
 * 与主密钥哈希匹配；没有配置投递方式时明确失败，避免绕过 2FA。
 */
twoFactor.post('/send-email-login', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<{
        email?: string;
        Email?: string;
        secret?: string;
        masterPasswordHash?: string;
    }>();
    const email = normalizeEmail(body.email ?? body.Email);
    if (!email) throw new BadRequestError('Email is required.');

    const user = await db.select().from(users).where(eq(users.email, email)).get();
    if (!user) throw new BadRequestError('Cannot send two-factor email.');

    const secret = body.secret ?? body.masterPasswordHash;
    if (!secret || !await verifyPassword(secret, user.masterPassword || '')) {
        throw new BadRequestError('Cannot send two-factor email.');
    }

    const providers = getProviders(user);
    const emailProvider = providers[TwoFactorProviderType.Email];
    if (!emailProvider?.enabled) {
        throw new BadRequestError('Email two-factor provider is not enabled.');
    }

    const targetEmail = normalizeEmail(emailProvider.metaData?.Email ?? emailProvider.metaData?.email) ?? user.email.toLowerCase();
    await storeAndDeliverEmailToken(c.env, db, user, providers, targetEmail);

    return c.body(null, 200);
});

// 所有 2FA 配置端点都需要认证
twoFactor.use('/*', authMiddleware);

/**
 * 验证 Secret (master password hash)
 */
async function verifySecret(db: any, userId: string, body: any) {
    const secret = body.secret || body.masterPasswordHash || body.otp;
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

function normalizeEmail(value: unknown): string | null {
    if (typeof value !== 'string') return null;
    const email = value.trim().toLowerCase();
    if (!email || !email.includes('@') || email.length > 256) return null;
    return email;
}

function generateEmailToken(): string {
    const bytes = new Uint8Array(4);
    crypto.getRandomValues(bytes);
    const value = ((bytes[0] << 24) >>> 0) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
    return String(value % 1000000).padStart(6, '0');
}

function maskSecret(secret: string | null | undefined): string | null {
    if (!secret) return secret ?? null;
    if (secret.length <= 6) return secret;
    return `${secret.slice(0, 6)}${'*'.repeat(secret.length - 6)}`;
}

function toEmailResponse(providers: Record<number, TwoFactorProvider>) {
    const provider = providers[TwoFactorProviderType.Email];
    const email = normalizeEmail(provider?.metaData?.Email ?? provider?.metaData?.email);
    return {
        enabled: provider?.enabled ?? false,
        email,
        object: 'twoFactorEmail',
    };
}

function toYubiKeyResponse(providers: Record<number, TwoFactorProvider>) {
    const metadata = providers[TwoFactorProviderType.YubiKey]?.metaData ?? {};
    return {
        enabled: providers[TwoFactorProviderType.YubiKey]?.enabled ?? false,
        key1: metadata.Key1 ?? null,
        key2: metadata.Key2 ?? null,
        key3: metadata.Key3 ?? null,
        key4: metadata.Key4 ?? null,
        key5: metadata.Key5 ?? null,
        nfc: metadata.Nfc ?? false,
        object: 'twoFactorYubiKey',
    };
}

function toDuoResponse(providers: Record<number, TwoFactorProvider>) {
    const metadata = providers[TwoFactorProviderType.Duo]?.metaData ?? {};
    return {
        enabled: providers[TwoFactorProviderType.Duo]?.enabled ?? false,
        host: metadata.Host ?? null,
        clientSecret: maskSecret(metadata.ClientSecret),
        clientId: metadata.ClientId ?? null,
        object: 'twoFactorDuo',
    };
}

async function deliverEmailToken(env: Bindings, email: string, token: string): Promise<void> {
    const delivery = env.TWO_FACTOR_EMAIL_DELIVERY?.toLowerCase();
    const debugEnabled = env.TWO_FACTOR_EMAIL_DEBUG === 'true';
    if (delivery === 'console' || debugEnabled) {
        console.info(`[2FA_EMAIL] email=${email} token=${token}`);
        return;
    }

    throw new BadRequestError('Email 2FA delivery is not configured. Set TWO_FACTOR_EMAIL_DELIVERY=console for development or wire a real email service before enabling Email 2FA.');
}

async function storeAndDeliverEmailToken(
    env: Bindings,
    db: ReturnType<typeof drizzle>,
    user: any,
    providers: Record<number, TwoFactorProvider>,
    email: string,
): Promise<void> {
    const token = generateEmailToken();
    const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const current = providers[TwoFactorProviderType.Email];
    providers[TwoFactorProviderType.Email] = {
        enabled: current?.enabled ?? false,
        metaData: {
            ...(current?.metaData ?? {}),
            Email: email,
            Token: token,
            TokenExpirationDate: expires,
        },
    };

    await deliverEmailToken(env, email, token);
    await db.update(users).set({
        twoFactorProviders: JSON.stringify(providers),
        accountRevisionDate: new Date().toISOString(),
    }).where(eq(users.id, user.id));
}

function verifyStoredEmailToken(provider: TwoFactorProvider | undefined, token: string | undefined): boolean {
    if (!provider?.metaData || !token) return false;
    const storedToken = String(provider.metaData.Token ?? provider.metaData.token ?? '');
    const expiresRaw = provider.metaData.TokenExpirationDate ?? provider.metaData.tokenExpirationDate;
    if (!storedToken || !expiresRaw) return false;
    if (Date.now() > new Date(String(expiresRaw)).getTime()) return false;
    return storedToken === token.trim();
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
 * POST /api/two-factor/get-email
 * 获取 Email 2FA 当前配置。
 */
twoFactor.post('/get-email', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({}));

    const user = await verifySecret(db, userId, body);
    return c.json(toEmailResponse(getProviders(user)));
});

/**
 * POST /api/two-factor/send-email
 * 发送 Email 2FA 设置验证码。验证码只写入 provider metadata，
 * PUT/POST /email 校验通过后才会真正启用 Email provider。
 */
twoFactor.post('/send-email', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        email?: string;
        Email?: string;
        secret?: string;
        masterPasswordHash?: string;
    }>();

    const user = await verifySecret(db, userId, body);
    const email = normalizeEmail(body.email ?? body.Email);
    if (!email) throw new BadRequestError('Email is required.');

    await storeAndDeliverEmailToken(c.env, db, user, getProviders(user), email);
    return c.body(null, 200);
});

/**
 * PUT/POST /api/two-factor/email
 * 校验 Email 2FA 设置验证码并启用 provider。
 */
async function enableEmail(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        email?: string;
        Email?: string;
        token?: string;
        Token?: string;
        secret?: string;
        masterPasswordHash?: string;
    }>();

    const user = await verifySecret(db, userId, body);
    const providers = getProviders(user);
    const email = normalizeEmail(body.email ?? body.Email);
    if (!email) throw new BadRequestError('Email is required.');

    if (!verifyStoredEmailToken(providers[TwoFactorProviderType.Email], body.token ?? body.Token)) {
        throw new BadRequestError('Invalid token.');
    }

    const now = new Date().toISOString();
    let recoveryCode = user.twoFactorRecoveryCode;
    if (!recoveryCode) {
        recoveryCode = generateSecureRandomString(32);
    }

    providers[TwoFactorProviderType.Email] = {
        enabled: true,
        metaData: { Email: email },
    };

    await db.update(users).set({
        twoFactorProviders: JSON.stringify(providers),
        twoFactorRecoveryCode: recoveryCode,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    return c.json(toEmailResponse(providers));
}

twoFactor.put('/email', enableEmail);
twoFactor.post('/email', enableEmail);

/**
 * GET /api/two-factor/get-device-verification-settings
 * PUT /api/two-factor/device-verification-settings
 *
 * 官方已标记为旧客户端兼容端点；返回值与当前邮件投递能力保持一致。
 */
function isUnknownDeviceVerificationEnabled(env: Bindings): boolean {
    return String(env.EMAIL_MODE ?? 'disabled').toLowerCase() !== 'disabled' ||
        String(env.EMAIL_RETURN_TOKENS ?? '').toLowerCase() === 'true';
}

function deviceVerificationSettingsResponse(env: Bindings) {
    const enabled = isUnknownDeviceVerificationEnabled(env);
    return {
        isDeviceVerificationSectionEnabled: enabled,
        unknownDeviceVerificationEnabled: enabled,
        object: 'deviceVerificationSettings',
    };
}

twoFactor.get('/get-device-verification-settings', (c) => c.json(deviceVerificationSettingsResponse(c.env)));
twoFactor.put('/device-verification-settings', (c) => c.json(deviceVerificationSettingsResponse(c.env)));

/**
 * POST /api/two-factor/get-yubikey
 */
twoFactor.post('/get-yubikey', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({}));

    const user = await verifySecret(db, userId, body);
    return c.json(toYubiKeyResponse(getProviders(user)));
});

/**
 * POST /api/two-factor/get-duo
 */
twoFactor.post('/get-duo', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({}));

    const user = await verifySecret(db, userId, body);
    return c.json(toDuoResponse(getProviders(user)));
});

async function unsupportedPremiumProvider() {
    throw new BadRequestError('This two-factor provider is not implemented for this Workers deployment.');
}

twoFactor.put('/yubikey', unsupportedPremiumProvider);
twoFactor.post('/yubikey', unsupportedPremiumProvider);
twoFactor.put('/duo', unsupportedPremiumProvider);
twoFactor.post('/duo', unsupportedPremiumProvider);

/**
 * POST /api/two-factor/get-authenticator
 * 验证密码并获取 Authenticator Key
 */
twoFactor.post('/get-authenticator', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ secret: string }>();

    const user = await verifySecret(db, userId, body);
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
 * DELETE /api/two-factor/authenticator
 * 禁用 Authenticator 2FA
 */
twoFactor.delete('/authenticator', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ type: number; key: string; userVerificationToken: string }>();

    if (!body.userVerificationToken || !body.key) {
        throw new BadRequestError('User verification failed.');
    }

    // 验证 userVerificationToken
    try {
        const decoded = JSON.parse(atob(body.userVerificationToken));
        if (decoded.userId !== userId || decoded.key !== body.key) {
            throw new BadRequestError('User verification failed.');
        }
    } catch (e) {
        if (e instanceof BadRequestError) throw e;
        throw new BadRequestError('User verification failed.');
    }

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new BadRequestError('User not found.');

    const providers = getProviders(user);

    // 删除 Authenticator provider (type 0)
    delete providers[0];

    const now = new Date().toISOString();
    const updateData: any = {
        twoFactorProviders: JSON.stringify(providers),
        accountRevisionDate: now,
    };

    if (Object.keys(providers).length === 0) {
        updateData.twoFactorRecoveryCode = null;
    }

    await db.update(users).set(updateData).where(eq(users.id, userId));

    return c.json({
        enabled: false,
        type: 0,
        object: 'twoFactorProvider',
    });
});

/**
 * 处理 PUT 和 POST /disable
 */
async function disableProvider(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ type: number; secret: string }>();

    const user = await verifySecret(db, userId, body);
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

    const user = await verifySecret(db, userId, body);

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

    await verifySecret(db, userId, body);

    const code = generateSecureRandomString(32);
    await db.update(users).set({ twoFactorRecoveryCode: code }).where(eq(users.id, userId));

    const response: TwoFactorRecoverResponse = {
        code,
        object: 'twoFactorRecover',
    };

    return c.json(response);
});

/**
 * 获取请求的 Origin（用于 WebAuthn RP ID 推导）
 */
function getOrigin(c: Context<{ Bindings: Bindings; Variables: Variables }>): string {
    return c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
}

/**
 * 构造 WebAuthn 响应 - 对应 TwoFactorWebAuthnResponseModel
 */
function buildWebAuthnResponse(providers: Record<number, any>) {
    const provider = getWebAuthnProvider(providers);
    const keys = getRegisteredKeys(provider);

    return {
        enabled: provider?.enabled ?? false,
        keys: keys.map(k => ({
            name: k.data.Name,
            id: k.id,
            migrated: k.data.Migrated ?? false,
            object: 'webAuthnKey',
        })),
        object: 'twoFactorWebAuthn',
    };
}

/**
 * POST /api/two-factor/get-webauthn
 * 获取 WebAuthn 密钥列表
 */
twoFactor.post('/get-webauthn', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json();

    const user = await verifySecret(db, userId, body);
    const providers = getProviders(user);

    return c.json(buildWebAuthnResponse(providers));
});

/**
 * POST /api/two-factor/get-webauthn-challenge
 * 生成 WebAuthn 注册 challenge
 */
twoFactor.post('/get-webauthn-challenge', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json();

    const user = await verifySecret(db, userId, body);
    const providers = getProviders(user);
    const origin = getOrigin(c);
    const isPremium = c.get('jwtPayload')?.premium || c.env.GLOBAL_PREMIUM === 'true';

    const { options, updatedProviders } = await startWebAuthnRegistration(
        { id: userId, name: user.name || '', email: user.email },
        providers,
        isPremium,
        origin,
    );

    // 保存 pending challenge 到数据库
    const now = new Date().toISOString();
    await db.update(users).set({
        twoFactorProviders: JSON.stringify(updatedProviders),
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    return c.json(options);
});

/**
 * PUT/POST /api/two-factor/webauthn
 * 完成 WebAuthn 注册
 */
async function completeWebAuthn(c: Context<{ Bindings: Bindings; Variables: Variables }>) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        id: number;
        name: string;
        deviceResponse: any;
        secret?: string;
        masterPasswordHash?: string;
    }>();

    const user = await verifySecret(db, userId, body);
    const providers = getProviders(user);
    const origin = getOrigin(c);
    const isPremium = c.get('jwtPayload')?.premium || c.env.GLOBAL_PREMIUM === 'true';

    const { success, updatedProviders } = await completeWebAuthnRegistration(
        { id: userId },
        providers,
        body.id,
        body.name,
        body.deviceResponse,
        isPremium,
        origin,
    );

    if (!success) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    // 确保有 recovery code
    const now = new Date().toISOString();
    let recoveryCode = user.twoFactorRecoveryCode;
    if (!recoveryCode) {
        recoveryCode = generateSecureRandomString(32);
    }

    await db.update(users).set({
        twoFactorProviders: JSON.stringify(updatedProviders),
        twoFactorRecoveryCode: recoveryCode,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    return c.json(buildWebAuthnResponse(updatedProviders));
}

twoFactor.put('/webauthn', completeWebAuthn);
twoFactor.post('/webauthn', completeWebAuthn);

/**
 * DELETE /api/two-factor/webauthn
 * 删除 WebAuthn 凭证
 */
twoFactor.delete('/webauthn', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ id: number; secret?: string; masterPasswordHash?: string }>();

    const user = await verifySecret(db, userId, body);
    const providers = getProviders(user);

    const { success, updatedProviders } = deleteWebAuthnCredential(providers, body.id);

    if (!success) {
        throw new BadRequestError('Unable to delete WebAuthn credential.');
    }

    const now = new Date().toISOString();
    await db.update(users).set({
        twoFactorProviders: JSON.stringify(updatedProviders),
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    return c.json(buildWebAuthnResponse(updatedProviders));
});

export default twoFactor;
