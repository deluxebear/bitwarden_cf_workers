/**
 * Bitwarden Workers - Identity 路由
 * 对应原始项目 Identity/Controllers/AccountsController.cs
 * 处理：Prelogin、Register、Token（登录）
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and } from 'drizzle-orm';
import { users, devices, refreshTokens } from '../db/schema';
import { signJwt } from '../middleware/auth';
import { generateUuid, generateSecureRandomString, generateRefreshToken, sha256, verifyPassword } from '../services/crypto';
import { verifyAuthenticatorCode } from '../services/totp';
import { logEvent } from '../services/events';
import { BadRequestError } from '../middleware/error';
import { bytesToBase64Url, base64UrlToBytes, verifyWebAuthnAuthentication } from '../services/webauthn';
import { webAuthnCredentials } from '../db/schema';
import type { Bindings, Variables, KdfType, PreloginRequest, PreloginResponse, RegisterRequest, TokenRequest, TokenResponse } from '../types';

const identity = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * POST /identity/accounts/prelogin
 * POST /identity/accounts/prelogin/password (新版端点)
 * 对应 Identity/Controllers/AccountsController.cs -> PostPrelogin
 * 返回用户的 KDF 类型和参数，客户端据此派生 master key
 */
async function handlePrelogin(c: any) {
    const body = await c.req.json() as PreloginRequest;
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
}

identity.post('/accounts/prelogin', handlePrelogin);
identity.post('/accounts/prelogin/password', handlePrelogin);

/**
 * GET /identity/accounts/webauthn/assertion-options
 * 对应 Identity/Controllers/AccountsController.cs -> GetWebAuthnLoginAssertionOptions
 * 返回 WebAuthn 登录的 assertion challenge（无需认证，用于 passkey 登录）
 */
identity.get('/accounts/webauthn/assertion-options', async (c) => {
    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }

    // 生成 32 字节随机 challenge
    const challengeBytes = new Uint8Array(32);
    crypto.getRandomValues(challengeBytes);
    const challenge = bytesToBase64Url(challengeBytes);

    const options = {
        challenge,
        allowCredentials: [] as any[],
        rpId,
        timeout: 60000,
        userVerification: 'required' as const,
        extensions: {},
        status: 'ok',
        errorMessage: '',
    };

    // 生成 token（HMAC 签名的 JSON，包含 challenge 和过期时间）
    const tokenData = {
        identifier: 'WebAuthnLoginAssertionOptionsToken',
        scope: 0, // Authentication
        options,
        exp: Math.floor(Date.now() / 1000) + 17 * 60, // 17 分钟
    };
    const tokenJson = JSON.stringify(tokenData);
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(c.env.JWT_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(tokenJson));
    const sigB64 = bytesToBase64Url(new Uint8Array(signature));
    const token = `BWWebAuthnLoginAssertionOptions_${btoa(tokenJson)}.${sigB64}`;

    return c.json({
        options,
        token,
        object: 'webAuthnLoginAssertionOptions',
    });
});

/**
 * POST /identity/accounts/register
 * 旧版注册 - 兼容旧版客户端从 identity 路由发起注册
 */
identity.post('/accounts/register', async (c) => {
    const body = await c.req.json<any>();

    if (!body.email || !body.masterPasswordHash) {
        throw new BadRequestError('Email and master password hash are required.');
    }

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    const { generateSecureRandomString } = await import('../services/crypto');
    const { users } = await import('../db/schema');

    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (existing) {
        throw new BadRequestError('Email is already taken.');
    }

    const now = new Date().toISOString();
    const userId = crypto.randomUUID();

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
 * 生成注册验证 token（HMAC-SHA256，无需存储，1小时有效）
 */
async function generateRegistrationToken(email: string, secret: string): Promise<string> {
    const hour = Math.floor(Date.now() / 3600000);
    const data = new TextEncoder().encode(`register:${email}:${hour}`);
    const key = await crypto.subtle.importKey(
        'raw', new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

/**
 * POST /identity/accounts/register/send-verification-email
 * 新注册流程第一步：发送验证邮件。
 * 自托管无邮件服务时，直接在响应中返回 token（客户端/管理员可取用）。
 */
identity.post('/accounts/register/send-verification-email', async (c) => {
    const body = await c.req.json() as { email: string; name?: string; receiveMarketingEmails?: boolean };

    if (!body.email) throw new BadRequestError('Email is required.');

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (existing) throw new BadRequestError('Email is already registered.');

    // 自托管：直接返回 token（无邮件服务时的 bypass）
    const token = await generateRegistrationToken(email, c.env.JWT_SECRET);
    return c.json({ emailVerificationToken: token }, 200);
});

/**
 * POST /identity/accounts/register/verification-email-clicked
 * 新注册流程第二步：验证邮件 token。
 */
identity.post('/accounts/register/verification-email-clicked', async (c) => {
    const body = await c.req.json() as { email: string; emailVerificationToken: string };

    if (!body.email || !body.emailVerificationToken) {
        throw new BadRequestError('Email and token are required.');
    }

    // 自托管：接受任意 token（不严格验证），直接返回成功
    return c.json(null, 200);
});

/**
 * POST /identity/accounts/register/finish
 * 新注册流程第三步：完成注册，提交加密密钥和密码哈希。
 * 新 API 字段名与旧版不同：
 *   userSymmetricKey  (旧: key)
 *   userAsymmetricKeys.publicKey / .encryptedPrivateKey (旧: keys.publicKey / .encryptedPrivateKey)
 *   kdfType (旧: kdf)
 */
identity.post('/accounts/register/finish', async (c) => {
    const body = await c.req.json() as {
        email: string;
        masterPasswordHash: string;
        masterPasswordHint?: string;
        kdfType?: number;
        kdf?: number;
        kdfIterations: number;
        kdfMemory?: number;
        kdfParallelism?: number;
        userSymmetricKey?: string;
        key?: string;
        userAsymmetricKeys?: { publicKey: string; encryptedPrivateKey: string };
        keys?: { publicKey: string; encryptedPrivateKey: string };
        emailVerificationToken?: string;
        name?: string;
    };

    if (!body.email || !body.masterPasswordHash) {
        throw new BadRequestError('Email and master password hash are required.');
    }

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (existing) throw new BadRequestError('Email is already registered.');

    const { generateSecureRandomString } = await import('../services/crypto');
    const now = new Date().toISOString();
    const userId = crypto.randomUUID();

    // 兼容新旧字段名
    const symmetricKey = body.userSymmetricKey || body.key || null;
    const asymKeys = body.userAsymmetricKeys || body.keys;
    const kdfType = body.kdfType ?? body.kdf ?? 0;

    await db.insert(users).values({
        id: userId,
        name: body.name || null,
        email,
        emailVerified: true,
        masterPassword: body.masterPasswordHash,
        masterPasswordHint: body.masterPasswordHint || null,
        culture: 'en-US',
        securityStamp: generateSecureRandomString(50),
        key: symmetricKey,
        publicKey: asymKeys?.publicKey || null,
        privateKey: asymKeys?.encryptedPrivateKey || null,
        kdf: kdfType,
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

    // WebAuthn grant 特有字段
    let webAuthnToken: string | undefined;
    let webAuthnDeviceResponse: string | undefined;

    console.log(`[TOKEN] Content-Type: ${contentType}`);

    if (contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await c.req.parseBody();
        console.log(`[TOKEN] Form fields: ${Object.keys(formData).join(', ')}`);
        console.log(`[TOKEN] grant_type=${formData['grant_type']}, username=${formData['username'] ? '***' : 'MISSING'}, password=${formData['password'] ? '***' : 'MISSING'}`);
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
            TwoFactorProvider: formData['TwoFactorProvider'] ? Number(formData['TwoFactorProvider']) : (formData['twoFactorProvider'] ? Number(formData['twoFactorProvider']) : undefined),
            TwoFactorToken: (formData['TwoFactorToken'] || formData['twoFactorToken']) as string,
        };
        webAuthnToken = formData['token'] as string;
        webAuthnDeviceResponse = formData['deviceResponse'] as string;
    } else {
        const rawBody = await c.req.json<any>();
        console.log(`[TOKEN] JSON body keys: ${Object.keys(rawBody).join(', ')}`);
        body = rawBody as TokenRequest;
        webAuthnToken = rawBody.token;
        webAuthnDeviceResponse = rawBody.deviceResponse;
    }

    console.log(`[TOKEN] Parsed grant_type: ${body.grant_type}`);

    const db = drizzle(c.env.DB);

    if (body.grant_type === 'password') {
        return await handlePasswordGrant(c, db, body);
    } else if (body.grant_type === 'refresh_token') {
        return await handleRefreshTokenGrant(c, db, body);
    } else if (body.grant_type === 'webauthn') {
        return await handleWebAuthnGrant(c, db, body, webAuthnToken, webAuthnDeviceResponse);
    }

    throw new BadRequestError('Unsupported grant_type.');
});

/**
 * 构建 2FA provider 的元数据，用于 TwoFactorProviders2 响应
 * 对应 TwoFactorAuthenticationValidator.BuildTwoFactorParams
 */
async function buildTwoFactorParams(
    providerType: number,
    provider: any,
    origin: string,
): Promise<Record<string, any> | null> {
    switch (providerType) {
        case 0: // Authenticator - 不需要额外参数
            return null;
        case 7: { // WebAuthn - 需要返回 assertion challenge
            const metaData = provider?.metaData || {};
            const allowCredentials: any[] = [];

            // 从已注册的 key 中提取 credential descriptors
            for (const keyName of Object.keys(metaData)) {
                const keyData = metaData[keyName];
                if (keyData?.Descriptor) {
                    allowCredentials.push({
                        id: keyData.Descriptor.Id,
                        type: keyData.Descriptor.Type || 'public-key',
                    });
                }
            }

            // 生成 challenge
            const challengeBytes = new Uint8Array(32);
            crypto.getRandomValues(challengeBytes);
            const challenge = bytesToBase64Url(challengeBytes);

            let rpId: string;
            try {
                rpId = new URL(origin).hostname;
            } catch {
                rpId = 'localhost';
            }

            return {
                challenge,
                allowCredentials,
                rpId,
                timeout: 60000,
                userVerification: 'discouraged',
                extensions: {},
                status: 'ok',
                errorMessage: '',
            };
        }
        default:
            return null;
    }
}

/**
 * Password grant - 用户名密码登录
 */
async function handlePasswordGrant(c: any, db: any, body: TokenRequest) {
    if (!body.username || !body.password) {
        throw new BadRequestError('Username and password are required.');
    }

    const email = body.username.toLowerCase().trim();
    console.log(`[TOKEN] Looking up user: ${email}`);
    const user = await db.select().from(users).where(eq(users.email, email)).get();
    console.log(`[TOKEN] User found: ${!!user}, hasPassword: ${!!user?.masterPassword}`);

    if (!user) {
        return c.json({
            error: 'invalid_grant',
            error_description: 'invalid_username_or_password',
            ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
        }, 400);
    }

    // 验证密码
    const passwordValid = await verifyPassword(body.password, user.masterPassword || '');
    console.log(`[TOKEN] Password valid: ${passwordValid}`);
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

    // ================= 检查二步验证 =================
    let providers: any = {};
    if (user.twoFactorProviders) {
        try {
            providers = JSON.parse(user.twoFactorProviders);
        } catch { }
    }

    const enabledProviders = Object.keys(providers).filter(k => providers[k].enabled).map(Number);
    console.log(`[TOKEN] 2FA providers: ${JSON.stringify(providers)}, enabled: ${JSON.stringify(enabledProviders)}`);
    if (enabledProviders.length > 0) {
        // 支持大小写
        const twoFactorProvider = body.TwoFactorProvider ?? body.twoFactorProvider;
        const twoFactorToken = body.TwoFactorToken ?? body.twoFactorToken;
        console.log(`[TOKEN] 2FA required but twoFactorProvider=${twoFactorProvider}, twoFactorToken=${twoFactorToken ? '***' : 'MISSING'}`);

        if (twoFactorProvider === undefined || !twoFactorToken) {
            // 构建每个 provider 的元数据
            const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
            const providers2: Record<string, any> = {};
            for (const p of enabledProviders) {
                providers2[String(p)] = await buildTwoFactorParams(p, providers[p], origin);
            }

            const twoFactorResponse: Record<string, any> = {
                error: 'invalid_grant',
                error_description: 'Two factor required.',
                TwoFactorProviders: enabledProviders.map(String),
                TwoFactorProviders2: providers2,
            };
            console.log(`[TOKEN] Returning 2FA challenge: ${JSON.stringify(twoFactorResponse)}`);
            return c.json(twoFactorResponse, 400);
        }

        const providerType = Number(twoFactorProvider);
        const token = twoFactorToken;
        let isValid = false;

        if (providerType === 8) {
            // Recovery code — 特殊处理，不需要在 enabledProviders 中
            const normalizedToken = token.replace(/\s/g, '').trim().toLowerCase();
            const storedCode = (user.twoFactorRecoveryCode || '').toLowerCase();
            isValid = !!storedCode && normalizedToken === storedCode;
            if (isValid) {
                // 恢复码使用后，清除所有 2FA providers，重新生成恢复码
                const now = new Date().toISOString();
                await db.update(users).set({
                    twoFactorProviders: null,
                    twoFactorRecoveryCode: generateSecureRandomString(32),
                    accountRevisionDate: now,
                }).where(eq(users.id, user.id));
            }
        } else if (!enabledProviders.includes(providerType)) {
            return c.json({ error: 'invalid_grant', error_description: 'invalid_two_factor_provider', ErrorModel: { Message: 'Invalid 2FA provider.', Object: 'error' } }, 400);
        } else if (providerType === 0) { // Authenticator
            const authProvider = providers[0];
            isValid = verifyAuthenticatorCode(authProvider.metaData.Key, token);
        } else if (providerType === 7) { // WebAuthn
            try {
                const assertionResponse = typeof token === 'string' ? JSON.parse(token) : token;
                const resp = assertionResponse.response || {};
                const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
                let rpId: string;
                try { rpId = new URL(origin).hostname; } catch { rpId = 'localhost'; }

                // 查找匹配的 credential
                const webAuthnProvider = providers[7];
                const metaData = webAuthnProvider?.metaData || {};
                let matchedKey: any = null;
                const credentialId = assertionResponse.id;

                for (const keyName of Object.keys(metaData)) {
                    if (metaData[keyName]?.Descriptor?.Id === credentialId) {
                        matchedKey = metaData[keyName];
                        break;
                    }
                }

                if (!matchedKey) {
                    console.log(`[TOKEN] WebAuthn 2FA: no matching credential for id=${credentialId}`);
                    isValid = false;
                } else {
                    // 验证 clientDataJSON
                    const clientDataBytes = base64UrlToBytes(resp.clientDataJSON || resp.clientDataJson);
                    const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

                    if (clientData.type !== 'webauthn.get') {
                        console.log(`[TOKEN] WebAuthn 2FA: invalid type ${clientData.type}`);
                        isValid = false;
                    } else {
                        // 验证 authenticatorData rpId hash
                        const authDataBytes = base64UrlToBytes(resp.authenticatorData);
                        const expectedRpIdHash = new Uint8Array(
                            await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
                        );
                        const rpIdHash = authDataBytes.slice(0, 32);
                        const rpIdMatch = rpIdHash.length === 32 && rpIdHash.every((b: number, i: number) => b === expectedRpIdHash[i]);

                        if (!rpIdMatch) {
                            console.log(`[TOKEN] WebAuthn 2FA: RP ID mismatch`);
                            isValid = false;
                        } else {
                            // 验证签名
                            const signatureBytes = base64UrlToBytes(resp.signature);
                            const clientDataHash = new Uint8Array(
                                await crypto.subtle.digest('SHA-256', clientDataBytes)
                            );
                            const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
                            signedData.set(authDataBytes);
                            signedData.set(clientDataHash, authDataBytes.length);

                            const publicKeyBytes = base64UrlToBytes(matchedKey.PublicKey);
                            const { verifySignatureWithCoseKey } = await import('../services/webauthn');
                            isValid = await verifySignatureWithCoseKey(publicKeyBytes, signedData, signatureBytes);
                            console.log(`[TOKEN] WebAuthn 2FA: signature valid=${isValid}`);
                        }
                    }
                }
            } catch (e) {
                console.log(`[TOKEN] WebAuthn 2FA verification error: ${e}`);
                isValid = false;
            }
        } else {
            return c.json({ error: 'invalid_grant', error_description: 'unsupported_provider', ErrorModel: { Message: 'Unsupported 2FA provider.', Object: 'error' } }, 400);
        }

        if (!isValid) {
            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_totp_code',
                ErrorModel: { Message: 'Invalid TOTP code.', Object: 'error' }
            }, 400);
        }
    }
    // ================= 2FA 检查完毕 =================
    console.log(`[TOKEN] 2FA check passed, proceeding to device/token generation`);

    // 处理设备
    let deviceId = generateUuid();
    if (body.deviceIdentifier) {
        const existingDevice = await db.select().from(devices)
            .where(and(eq(devices.userId, user.id), eq(devices.identifier, body.deviceIdentifier))).get();
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
        email_verified: !!user.emailVerified,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
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

    // 记录审计日志
    await logEvent(c.env.DB, 1000, {
        userId: user.id,
        deviceType: body.deviceType,
        ipAddress: c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for') || null,
    });

    const response: any = {
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
        refresh_token: refreshToken,
        Key: user.key,
        PrivateKey: user.privateKey,
        AccountKeys: {
            publicKeyEncryptionKeyPair: {
                wrappedPrivateKey: user.privateKey || '',
                publicKey: user.publicKey || '',
            }
        },
        Kdf: user.kdf,
        KdfIterations: user.kdfIterations,
        KdfMemory: user.kdfMemory,
        KdfParallelism: user.kdfParallelism,
        ResetMasterPassword: false,
        ForcePasswordReset: user.forcePasswordReset,
        scope: 'api offline_access',
        unofficialServer: false,
        UserDecryptionOptions: {
            HasMasterPassword: !!user.masterPassword,
            object: 'userDecryptionOptions',
        },
    };

    // 新版客户端需要 MasterPasswordUnlock 字段（在 UserDecryptionOptions 内）
    if (user.masterPassword && user.key) {
        response.UserDecryptionOptions.MasterPasswordUnlock = {
            Kdf: {
                KdfType: user.kdf,
                Iterations: user.kdfIterations,
                Memory: user.kdfMemory ?? null,
                Parallelism: user.kdfParallelism ?? null,
            },
            MasterKeyEncryptedUserKey: user.key,
            Salt: user.email.toLowerCase(),
        };
    }

    console.log(`[TOKEN] Response for user ${user.email}: Kdf=${user.kdf}, KdfIterations=${user.kdfIterations}, HasKey=${!!user.key}, HasMasterPasswordUnlock=${!!response.UserDecryptionOptions.MasterPasswordUnlock}`);

    return c.json(response);
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
        email_verified: !!user.emailVerified,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
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

    const response: any = {
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
        unofficialServer: false,
        UserDecryptionOptions: {
            HasMasterPassword: !!user.masterPassword,
            object: 'userDecryptionOptions',
        },
    };

    if (user.masterPassword && user.key) {
        response.UserDecryptionOptions.MasterPasswordUnlock = {
            Kdf: {
                KdfType: user.kdf,
                Iterations: user.kdfIterations,
                Memory: user.kdfMemory ?? null,
                Parallelism: user.kdfParallelism ?? null,
            },
            MasterKeyEncryptedUserKey: user.key,
            Salt: user.email.toLowerCase(),
        };
    }

    return c.json(response);
}

/**
 * WebAuthn grant - Passkey 登录
 * 对应 Identity/IdentityServer/RequestValidators/WebAuthnGrantValidator.cs
 */
async function handleWebAuthnGrant(c: any, db: any, body: TokenRequest, rawToken?: string, rawDeviceResponse?: string) {
    if (!rawToken || !rawDeviceResponse) {
        return c.json({ error: 'invalid_grant', error_description: 'Token and deviceResponse are required.' }, 400);
    }

    // 1. 验证 token（HMAC 签名）
    const tokenParts = rawToken.replace('BWWebAuthnLoginAssertionOptions_', '');
    const [tokenB64, sigB64] = tokenParts.split('.');
    if (!tokenB64 || !sigB64) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid token format.' }, 400);
    }

    const tokenJson = atob(tokenB64);
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(c.env.JWT_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify'],
    );
    const sigBytes = base64UrlToBytes(sigB64);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(tokenJson));
    if (!valid) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid token signature.' }, 400);
    }

    const tokenData = JSON.parse(tokenJson);
    if (tokenData.exp < Math.floor(Date.now() / 1000)) {
        return c.json({ error: 'invalid_grant', error_description: 'Token expired.' }, 400);
    }

    // 2. 解析 deviceResponse（WebAuthn assertion）
    let assertionResponse: any;
    try {
        assertionResponse = typeof rawDeviceResponse === 'string' ? JSON.parse(rawDeviceResponse) : rawDeviceResponse;
    } catch {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid deviceResponse.' }, 400);
    }

    const resp = assertionResponse.response || {};

    // 3. 从 userHandle 中提取用户 ID
    // userHandle 是 Base64URL 编码的 UUID bytes
    let userId: string | null = null;
    const userHandleB64 = resp.userHandle;
    if (userHandleB64) {
        const userHandleBytes = base64UrlToBytes(userHandleB64);
        if (userHandleBytes.length === 16) {
            // 将 bytes 转回 UUID 字符串
            const hex = Array.from(userHandleBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            userId = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        }
    }

    if (!userId) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid credential.' }, 400);
    }

    // 4. 查找用户
    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid credential.' }, 400);
    }

    // 5. 查找匹配的 WebAuthn 凭证
    const credentialId = assertionResponse.id;
    const credential = await db.select().from(webAuthnCredentials)
        .where(and(
            eq(webAuthnCredentials.userId, userId),
            eq(webAuthnCredentials.credentialId, credentialId),
        )).get();

    if (!credential) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid credential.' }, 400);
    }

    // 6. 验证 WebAuthn assertion 签名
    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    const expectedChallenge = tokenData.options.challenge;

    // 构建 providers 格式以复用 verifyWebAuthnAuthentication
    // 但这里使用的是独立的 webAuthnCredentials 表，直接手动验证
    const clientDataBytes = base64UrlToBytes(resp.clientDataJSON || resp.clientDataJson);
    const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

    if (clientData.type !== 'webauthn.get') {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid assertion type.' }, 400);
    }
    if (clientData.challenge !== expectedChallenge) {
        return c.json({ error: 'invalid_grant', error_description: 'Challenge mismatch.' }, 400);
    }
    if (clientData.origin !== origin) {
        return c.json({ error: 'invalid_grant', error_description: 'Origin mismatch.' }, 400);
    }

    // 验证 authenticatorData
    const authDataBytes = base64UrlToBytes(resp.authenticatorData);
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }
    const expectedRpIdHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId))
    );
    const rpIdHash = authDataBytes.slice(0, 32);
    if (rpIdHash.length !== 32 || !rpIdHash.every((b: number, i: number) => b === expectedRpIdHash[i])) {
        return c.json({ error: 'invalid_grant', error_description: 'RP ID mismatch.' }, 400);
    }

    const flags = authDataBytes[32];
    if ((flags & 0x01) === 0) { // UP not set
        return c.json({ error: 'invalid_grant', error_description: 'User presence not verified.' }, 400);
    }

    // 验证签名
    const signatureBytes = base64UrlToBytes(resp.signature);
    const clientDataHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', clientDataBytes)
    );
    const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
    signedData.set(authDataBytes);
    signedData.set(clientDataHash, authDataBytes.length);

    // 导入 COSE 公钥并验证
    const publicKeyBytes = base64UrlToBytes(credential.publicKey);
    const { verifySignatureWithCoseKey } = await import('../services/webauthn');
    const signatureValid = await verifySignatureWithCoseKey(publicKeyBytes, signedData, signatureBytes);
    if (!signatureValid) {
        return c.json({ error: 'invalid_grant', error_description: 'Signature verification failed.' }, 400);
    }

    // 更新 counter
    const newCounter = (authDataBytes[33] << 24) | (authDataBytes[34] << 16) | (authDataBytes[35] << 8) | authDataBytes[36];
    await db.update(webAuthnCredentials).set({
        counter: newCounter,
        revisionDate: new Date().toISOString(),
    }).where(eq(webAuthnCredentials.id, credential.id));

    // 7. 签发 token（与 password grant 相同流程）
    let deviceId = generateUuid();
    if (body.deviceIdentifier) {
        const existingDevice = await db.select().from(devices)
            .where(and(eq(devices.userId, user.id), eq(devices.identifier, body.deviceIdentifier))).get();
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

    const expiresIn = parseInt(c.env.JWT_EXPIRATION || '3600');
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        email_verified: !!user.emailVerified,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
        sstamp: user.securityStamp,
        device: deviceId,
        scope: ['api', 'offline_access'],
        amr: ['Application'],
    }, c.env.JWT_SECRET, expiresIn);

    const refreshTokenValue = generateRefreshToken();
    const refreshTokenHash = await sha256(refreshTokenValue);
    const refreshExpiresIn = parseInt(c.env.JWT_REFRESH_EXPIRATION || '2592000');

    await db.insert(refreshTokens).values({
        id: generateUuid(),
        userId: user.id,
        deviceId,
        tokenHash: refreshTokenHash,
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });

    await logEvent(c.env.DB, 1000, {
        userId: user.id,
        deviceType: body.deviceType,
        ipAddress: c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for') || null,
    });

    const response: any = {
        access_token: accessToken,
        expires_in: expiresIn,
        token_type: 'Bearer',
        refresh_token: refreshTokenValue,
        Key: user.key,
        PrivateKey: user.privateKey,
        AccountKeys: {
            publicKeyEncryptionKeyPair: {
                wrappedPrivateKey: user.privateKey || '',
                publicKey: user.publicKey || '',
            }
        },
        Kdf: user.kdf,
        KdfIterations: user.kdfIterations,
        KdfMemory: user.kdfMemory,
        KdfParallelism: user.kdfParallelism,
        ResetMasterPassword: false,
        ForcePasswordReset: user.forcePasswordReset,
        scope: 'api offline_access',
        unofficialServer: false,
        UserDecryptionOptions: {
            HasMasterPassword: !!user.masterPassword,
            object: 'userDecryptionOptions',
        },
    };

    if (user.masterPassword && user.key) {
        response.UserDecryptionOptions.MasterPasswordUnlock = {
            Kdf: {
                KdfType: user.kdf,
                Iterations: user.kdfIterations,
                Memory: user.kdfMemory ?? null,
                Parallelism: user.kdfParallelism ?? null,
            },
            MasterKeyEncryptedUserKey: user.key,
            Salt: user.email.toLowerCase(),
        };
    }

    // WebAuthn PRF decryption options
    if (credential.supportsPrf && credential.encryptedUserKey) {
        response.UserDecryptionOptions.WebAuthnPrfOption = {
            EncryptedPrivateKey: credential.encryptedPrivateKey,
            EncryptedUserKey: credential.encryptedUserKey,
        };
    }

    return c.json(response);
}

export default identity;
