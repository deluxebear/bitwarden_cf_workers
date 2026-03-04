/**
 * Bitwarden Workers - Identity 路由
 * 对应原始项目 Identity/Controllers/AccountsController.cs
 * 处理：Prelogin、Register、Token（登录）
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users, devices, refreshTokens } from '../db/schema';
import { signJwt } from '../middleware/auth';
import { generateUuid, generateSecureRandomString, generateRefreshToken, sha256, verifyPassword } from '../services/crypto';
import { BadRequestError } from '../middleware/error';
import type { Bindings, Variables, KdfType, PreloginRequest, PreloginResponse, RegisterRequest, TokenRequest } from '../types';

const identity = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * POST /identity/accounts/prelogin
 * 对应 Identity/Controllers/AccountsController.cs -> PostPrelogin
 * 返回用户的 KDF 类型和参数，客户端据此派生 master key
 */
identity.post('/accounts/prelogin', async (c) => {
    const body = await c.req.json<PreloginRequest>();
    if (!body.email) {
        throw new BadRequestError('Email is required.');
    }

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    const user = await db.select({
        kdf: users.kdf,
        kdfIterations: users.kdfIterations,
        kdfMemory: users.kdfMemory,
        kdfParallelism: users.kdfParallelism,
    }).from(users).where(eq(users.email, email)).get();

    // 即使用户不存在也返回默认 KDF 参数（防止用户枚举攻击）
    const kdfType = (user?.kdf as KdfType) ?? 0;
    const kdfIter = user?.kdfIterations ?? 600000;
    const kdfMem = user?.kdfMemory ?? null;
    const kdfPar = user?.kdfParallelism ?? null;

    const response: PreloginResponse = {
        kdf: kdfType,
        kdfIterations: kdfIter,
        kdfMemory: kdfMem,
        kdfParallelism: kdfPar,
        // 新版字段 - 对应 PasswordPreloginResponseModel
        kdfSettings: {
            kdfType: kdfType,
            iterations: kdfIter,
            memory: kdfMem,
            parallelism: kdfPar,
        },
        salt: email, // 与官方一致，返回 email 作为 salt
    };

    return c.json(response);
});

/**
 * POST /identity/accounts/register
 * 对应 Identity/Controllers/AccountsController.cs -> PostRegisterFinish
 * 用户注册
 */
identity.post('/accounts/register', async (c) => {
    const body = await c.req.json<RegisterRequest>();

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
    const userId = generateUuid();

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

/**
 * POST /identity/connect/token
 * 对应原始项目 Identity 模块的 OAuth2 Token 端点
 * 支持 password grant (登录) 和 refresh_token grant (刷新)
 */
identity.post('/connect/token', async (c) => {
    // Bitwarden 客户端发送 application/x-www-form-urlencoded
    const contentType = c.req.header('content-type') || '';
    let body: TokenRequest;

    if (contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await c.req.parseBody();
        body = {
            grant_type: formData['grant_type'] as any,
            username: formData['username'] as string,
            password: formData['password'] as string,
            scope: formData['scope'] as string,
            client_id: formData['client_id'] as string,
            deviceType: formData['deviceType'] ? Number(formData['deviceType']) : undefined,
            deviceIdentifier: formData['deviceIdentifier'] as string,
            deviceName: formData['deviceName'] as string,
            refresh_token: formData['refresh_token'] as string,
        };
    } else {
        body = await c.req.json<TokenRequest>();
    }

    const db = drizzle(c.env.DB);

    if (body.grant_type === 'password') {
        return await handlePasswordGrant(c, db, body);
    } else if (body.grant_type === 'refresh_token') {
        return await handleRefreshTokenGrant(c, db, body);
    }

    throw new BadRequestError('Unsupported grant_type.');
});

/**
 * Password grant - 用户名密码登录
 */
async function handlePasswordGrant(c: any, db: any, body: TokenRequest) {
    if (!body.username || !body.password) {
        throw new BadRequestError('Username and password are required.');
    }

    const email = body.username.toLowerCase().trim();
    const user = await db.select().from(users).where(eq(users.email, email)).get();

    if (!user) {
        return c.json({
            error: 'invalid_grant',
            error_description: 'invalid_username_or_password',
            ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
        }, 400);
    }

    // 验证密码
    const passwordValid = await verifyPassword(body.password, user.masterPassword || '');
    if (!passwordValid) {
        // 更新失败登录计数
        await db.update(users).set({
            failedLoginCount: user.failedLoginCount + 1,
            lastFailedLoginDate: new Date().toISOString(),
        }).where(eq(users.id, user.id));

        return c.json({
            error: 'invalid_grant',
            error_description: 'invalid_username_or_password',
            ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
        }, 400);
    }

    // 登录成功，重置失败计数
    await db.update(users).set({
        failedLoginCount: 0,
        lastFailedLoginDate: null,
    }).where(eq(users.id, user.id));

    // 处理设备
    let deviceId = generateUuid();
    if (body.deviceIdentifier) {
        const existingDevice = await db.select().from(devices)
            .where(eq(devices.identifier, body.deviceIdentifier)).get();
        if (existingDevice) {
            deviceId = existingDevice.id;
            await db.update(devices).set({
                name: body.deviceName || existingDevice.name,
                type: body.deviceType ?? existingDevice.type,
                revisionDate: new Date().toISOString(),
            }).where(eq(devices.id, deviceId));
        } else {
            await db.insert(devices).values({
                id: deviceId,
                userId: user.id,
                name: body.deviceName || 'Unknown',
                type: body.deviceType ?? 14,
                identifier: body.deviceIdentifier,
                creationDate: new Date().toISOString(),
                revisionDate: new Date().toISOString(),
            });
        }
    }

    // 签发 access token
    const expiresIn = parseInt(c.env.JWT_EXPIRATION || '3600');
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        name: user.name || '',
        premium: user.premium,
        sstamp: user.securityStamp,
        device: deviceId,
        scope: ['api', 'offline_access'],
        amr: ['Application'],
    }, c.env.JWT_SECRET, expiresIn);

    // 签发 refresh token
    const refreshToken = generateRefreshToken();
    const refreshTokenHash = await sha256(refreshToken);
    const refreshExpiresIn = parseInt(c.env.JWT_REFRESH_EXPIRATION || '2592000');

    await db.insert(refreshTokens).values({
        id: generateUuid(),
        userId: user.id,
        deviceId,
        tokenHash: refreshTokenHash,
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });

    return c.json({
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
        refresh_token: refreshToken,
        Key: user.key,
        PrivateKey: user.privateKey,
        Kdf: user.kdf,
        KdfIterations: user.kdfIterations,
        KdfMemory: user.kdfMemory,
        KdfParallelism: user.kdfParallelism,
        ResetMasterPassword: false,
        ForcePasswordReset: user.forcePasswordReset,
        scope: 'api offline_access',
        unofficialServer: true,
        UserDecryptionOptions: {
            hasMasterPassword: !!user.masterPassword,
        },
    });
}

/**
 * Refresh token grant - 刷新 access token
 */
async function handleRefreshTokenGrant(c: any, db: any, body: TokenRequest) {
    if (!body.refresh_token) {
        throw new BadRequestError('Refresh token is required.');
    }

    const tokenHash = await sha256(body.refresh_token);
    const storedToken = await db.select().from(refreshTokens)
        .where(eq(refreshTokens.tokenHash, tokenHash)).get();

    if (!storedToken) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token.' }, 400);
    }

    // 检查过期
    if (new Date(storedToken.expirationDate) < new Date()) {
        await db.delete(refreshTokens).where(eq(refreshTokens.id, storedToken.id));
        return c.json({ error: 'invalid_grant', error_description: 'Refresh token expired.' }, 400);
    }

    const user = await db.select().from(users).where(eq(users.id, storedToken.userId)).get();
    if (!user) {
        return c.json({ error: 'invalid_grant', error_description: 'User not found.' }, 400);
    }

    // 删除旧 refresh token
    await db.delete(refreshTokens).where(eq(refreshTokens.id, storedToken.id));

    // 新的 access token
    const expiresIn = parseInt(c.env.JWT_EXPIRATION || '3600');
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        name: user.name || '',
        premium: user.premium,
        sstamp: user.securityStamp,
        device: storedToken.deviceId || '',
        scope: ['api', 'offline_access'],
        amr: ['Application'],
    }, c.env.JWT_SECRET, expiresIn);

    // 签发新 refresh token（rotation）
    const newRefreshToken = generateRefreshToken();
    const newRefreshHash = await sha256(newRefreshToken);
    const refreshExpiresIn = parseInt(c.env.JWT_REFRESH_EXPIRATION || '2592000');

    await db.insert(refreshTokens).values({
        id: generateUuid(),
        userId: user.id,
        deviceId: storedToken.deviceId,
        tokenHash: newRefreshHash,
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });

    return c.json({
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
        refresh_token: newRefreshToken,
        Key: user.key,
        PrivateKey: user.privateKey,
        Kdf: user.kdf,
        KdfIterations: user.kdfIterations,
        KdfMemory: user.kdfMemory,
        KdfParallelism: user.kdfParallelism,
        ResetMasterPassword: false,
        ForcePasswordReset: user.forcePasswordReset,
        scope: 'api offline_access',
        unofficialServer: true,
        UserDecryptionOptions: {
            hasMasterPassword: !!user.masterPassword,
        },
    });
}

export default identity;
