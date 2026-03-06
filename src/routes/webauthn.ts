/**
 * Bitwarden Workers - WebAuthn Login (Passkeys) 路由
 *
 * 对应原始项目 Api/Auth/Controllers/WebAuthnController.cs
 * 负责通行密钥（Passkey）注册、列表、删除以及 PRF 加密密钥的开启/更新。
 *
 * 路由前缀：/api/webauthn
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq } from 'drizzle-orm';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { users, webAuthnCredentials } from '../db/schema';
import type { Bindings, Variables } from '../types';
import { base64UrlToBytes, bytesToBase64Url, verifySignatureWithCoseKey } from '../services/webauthn';
import { verifyPassword } from '../services/crypto';

const webauthn = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有端点均需要认证（对应原项目的 [Authorize]）
webauthn.use('/*', authMiddleware);

/**
 * 计算 PRF 状态：
 * - 0 Enabled: supportsPrf=true 且 encryptedUserKey 非空
 * - 1 Supported: supportsPrf=true 但 encryptedUserKey 为空
 * - 2 Unsupported: supportsPrf=false
 */
function getPrfStatus(credential: {
    supportsPrf: boolean | null;
    encryptedUserKey: string | null;
}): 0 | 1 | 2 {
    if (!credential.supportsPrf) {
        return 2;
    }
    return credential.encryptedUserKey ? 0 : 1;
}

/**
 * GET /api/webauthn
 * 列出当前用户已注册的通行密钥
 * 对应 WebAuthnController.Get
 */
webauthn.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const creds = await db.select().from(webAuthnCredentials)
        .where(eq(webAuthnCredentials.userId, userId))
        .all();

    const data = creds.map((cred) => ({
        id: cred.id,
        name: cred.name,
        prfStatus: getPrfStatus(cred),
        encryptedUserKey: cred.encryptedUserKey,
        encryptedPrivateKey: cred.encryptedPrivateKey,
        encryptedPublicKey: cred.encryptedPublicKey,
        object: 'webAuthnCredential',
    }));

    return c.json({
        data,
        continuationToken: null,
        object: 'list',
    });
});

/**
 * Secret 验证：使用当前 masterPasswordHash 验证用户
 * 对应 WebAuthnController.VerifyUserAsync
 */
async function verifyUserSecret(
    db: ReturnType<typeof drizzle>,
    userId: string,
    secret: string | undefined,
) {
    if (!secret) {
        throw new BadRequestError('User verification failed.');
    }

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        throw new NotFoundError('User not found.');
    }

    const valid = await verifyPassword(secret, user.masterPassword || '');
    if (!valid) {
        // 与官方实现类似：延迟略去，直接抛错
        throw new BadRequestError('User verification failed.');
    }

    return user;
}

/**
 * 生成通行密钥注册/更新 token（HMAC 签名的 JSON）
 * 结构与 identity.ts 中 WebAuthnLoginAssertionOptionsToken 保持一致：
 * {
 *   identifier: 'WebAuthnCredentialCreateOptionsToken' | 'WebAuthnLoginAssertionOptionsToken',
 *   scope: number,
 *   options: {...},
 *   exp: unixSeconds
 * }
 */
async function signWebAuthnToken(
    env: Bindings,
    identifier: string,
    scope: number,
    options: Record<string, unknown>,
): Promise<string> {
    const encoder = new TextEncoder();
    const tokenData = {
        identifier,
        scope,
        options,
        exp: Math.floor(Date.now() / 1000) + 17 * 60, // 17 分钟
    };
    const tokenJson = JSON.stringify(tokenData);
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(env.JWT_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(tokenJson));
    const sigB64 = bytesToBase64Url(new Uint8Array(signature));
    const token = `BWWebAuthn_${btoa(tokenJson)}.${sigB64}`;
    return token;
}

async function verifyWebAuthnToken(env: Bindings, rawToken: string, expectedIdentifier: string, expectedScope: number) {
    const encoder = new TextEncoder();
    const tokenParts = rawToken.replace('BWWebAuthn_', '');
    const [tokenB64, sigB64] = tokenParts.split('.');
    if (!tokenB64 || !sigB64) {
        throw new BadRequestError('Invalid token format.');
    }

    const tokenJson = atob(tokenB64);
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(env.JWT_SECRET),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify'],
    );
    const sigBytes = base64UrlToBytes(sigB64);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(tokenJson));
    if (!valid) {
        throw new BadRequestError('Invalid token signature.');
    }

    const tokenData = JSON.parse(tokenJson);
    if (tokenData.exp < Math.floor(Date.now() / 1000)) {
        throw new BadRequestError('The token associated with your request is invalid or has expired. A valid token is required to continue.');
    }
    if (tokenData.identifier !== expectedIdentifier || tokenData.scope !== expectedScope) {
        throw new BadRequestError('The token associated with your request is invalid or has expired. A valid token is required to continue.');
    }

    return tokenData.options;
}

/**
 * POST /api/webauthn/attestation-options
 * 生成通行密钥注册选项
 * 对应 WebAuthnController.AttestationOptions
 *
 * 请求体：{ secret: string }（SecretVerificationRequest）
 */
webauthn.post('/attestation-options', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as { masterPasswordHash?: string };

    const user = await verifyUserSecret(db, userId, body.masterPasswordHash);

    // 计算 rpId
    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }

    // 生成 32 字节 challenge
    const challengeBytes = new Uint8Array(32);
    crypto.getRandomValues(challengeBytes);

    // user handle (UUID bytes -> base64url)
    const userIdBytes = base64UrlToBytes(bytesToBase64Url(uuidToBytes(user.id)));

    // 排除已有凭证
    const existing = await db.select().from(webAuthnCredentials)
        .where(eq(webAuthnCredentials.userId, user.id))
        .all();
    const excludeCredentials = existing.map((cred: typeof existing[number]) => ({
        type: 'public-key',
        id: cred.credentialId,
    }));

    const options = {
        rp: {
            name: 'Bitwarden',
            id: rpId,
        },
        user: {
            id: bytesToBase64Url(userIdBytes),
            name: user.email,
            displayName: user.name || '',
        },
        challenge: bytesToBase64Url(challengeBytes),
        pubKeyCredParams: [
            { type: 'public-key', alg: -7 },   // ES256
            { type: 'public-key', alg: -257 }, // RS256
            { type: 'public-key', alg: -8 },   // EdDSA
        ],
        timeout: 60000,
        excludeCredentials,
        authenticatorSelection: {
            requireResidentKey: true,
            residentKey: 'required',
            userVerification: 'required',
        },
        attestation: 'none',
        extensions: {},
    };

    const token = await signWebAuthnToken(c.env, 'WebAuthnCredentialCreateOptionsToken', 0, options);

    return c.json({
        options,
        token,
        object: 'webAuthnCredentialCreateOptions',
    });
});

/**
 * POST /api/webauthn
 * 完成通行密钥注册，保存凭证
 * 对应 WebAuthnController.Post
 *
 * 请求体：
 * {
 *   name: string;
 *   deviceResponse: { id, rawId, type, response: { attestationObject / clientDataJSON } };
 *   token: string;
 *   supportsPrf: boolean;
 *   encryptedUserKey?: string;
 *   encryptedPublicKey?: string;
 *   encryptedPrivateKey?: string;
 * }
 */
webauthn.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        name: string;
        token: string;
        deviceResponse: {
            id: string;
            rawId?: string;
            type: string;
            response: {
                AttestationObject?: string;
                attestationObject?: string;
                clientDataJson?: string;
                clientDataJSON?: string;
            };
        };
        supportsPrf?: boolean;
        encryptedUserKey?: string;
        encryptedPublicKey?: string;
        encryptedPrivateKey?: string;
    }>();

    if (!body?.token || !body?.deviceResponse || !body?.name) {
        throw new BadRequestError('Invalid request.');
    }

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) {
        throw new NotFoundError('User not found.');
    }

    const options = await verifyWebAuthnToken(
        c.env,
        body.token,
        'WebAuthnCredentialCreateOptionsToken',
        0,
    );

    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }

    const deviceResponse = body.deviceResponse;
    const resp = deviceResponse.response || {};
    const attestationObjectB64 = resp.AttestationObject || resp.attestationObject;
    const clientDataJsonB64 = resp.clientDataJson || resp.clientDataJSON;

    if (!attestationObjectB64 || !clientDataJsonB64) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    // 解码 clientDataJSON 并验证（客户端使用 Utils.fromBufferToUrlB64，采用 Base64URL 编码）
    const clientDataBytes = base64UrlToBytes(clientDataJsonB64);
    const clientDataStr = new TextDecoder().decode(clientDataBytes);
    const clientData = JSON.parse(clientDataStr);

    if (clientData.type !== 'webauthn.create') {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }
    if (clientData.challenge !== options.challenge) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }
    if (clientData.origin !== origin) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    // 解码 attestationObject (CBOR，Base64URL 编码)
    const attestationObjectBytes = base64UrlToBytes(attestationObjectB64);
    const { decodeCBOR } = (await import('../services/webauthn')) as {
        decodeCBOR(data: Uint8Array): { authData: Uint8Array };
    };
    const attestation = decodeCBOR(attestationObjectBytes);
    const authData: Uint8Array = attestation.authData;
    if (!(authData instanceof Uint8Array) || authData.length < 37) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    // rpIdHash
    const rpIdHash = authData.slice(0, 32);
    const expectedRpIdHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)),
    );
    for (let i = 0; i < 32; i++) {
        if (rpIdHash[i] !== expectedRpIdHash[i]) {
            throw new BadRequestError('Unable to complete WebAuthn registration.');
        }
    }

    // flags
    const flags = authData[32];
    if ((flags & 0x01) === 0) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    // signCount
    const signCount = (authData[33] << 24) | (authData[34] << 16) | (authData[35] << 8) | authData[36];

    // AAGUID
    const aaguid = authData.slice(37, 53);
    const aaguidHex = Array.from(aaguid).map((b) => b.toString(16).padStart(2, '0')).join('');
    const aaGuidFormatted = `${aaguidHex.slice(0, 8)}-${aaguidHex.slice(8, 12)}-${aaguidHex.slice(12, 16)}-${aaguidHex.slice(16, 20)}-${aaguidHex.slice(20)}`;

    // credentialId
    const credIdLen = (authData[53] << 8) | authData[54];
    const credentialIdBytes = authData.slice(55, 55 + credIdLen);
    const credentialIdB64Url = bytesToBase64Url(credentialIdBytes);

    // public key (剩余部分)
    const publicKeyCose = authData.slice(55 + credIdLen);

    // 校验 deviceResponse.id
    if (credentialIdB64Url !== deviceResponse.id && credentialIdB64Url !== deviceResponse.rawId) {
        throw new BadRequestError('Unable to complete WebAuthn registration.');
    }

    const now = new Date().toISOString();
    const id = crypto.randomUUID();

    await db.insert(webAuthnCredentials).values({
        id,
        userId: user.id,
        name: body.name,
        publicKey: bytesToBase64Url(publicKeyCose),
        credentialId: credentialIdB64Url,
        counter: signCount,
        type: 'public-key',
        aaGuid: aaGuidFormatted,
        supportsPrf: !!body.supportsPrf,
        encryptedUserKey: body.encryptedUserKey || null,
        encryptedPrivateKey: body.encryptedPrivateKey || null,
        encryptedPublicKey: body.encryptedPublicKey || null,
        creationDate: now,
        revisionDate: now,
    });

    return c.body(null, 200);
});

/**
 * POST /api/webauthn/assertion-options
 * 生成用于更新加密密钥的 assertion options
 * 对应 WebAuthnController.AssertionOptions
 */
webauthn.post('/assertion-options', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as { masterPasswordHash?: string };

    await verifyUserSecret(db, userId, body.masterPasswordHash);

    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }

    const challengeBytes = new Uint8Array(32);
    crypto.getRandomValues(challengeBytes);

    const existing = await db.select().from(webAuthnCredentials)
        .where(eq(webAuthnCredentials.userId, userId))
        .all();
    const allowCredentials = existing.map((cred) => ({
        type: 'public-key',
        id: cred.credentialId,
    }));

    const options = {
        challenge: bytesToBase64Url(challengeBytes),
        allowCredentials,
        rpId,
        timeout: 60000,
        userVerification: 'required' as const,
        extensions: {},
        status: 'ok',
        errorMessage: '',
    };

    // scope=1 代表 UpdateKeySet
    const token = await signWebAuthnToken(c.env, 'WebAuthnLoginAssertionOptionsToken', 1, options);

    return c.json({
        options,
        token,
        object: 'webAuthnLoginAssertionOptions',
    });
});

/**
 * PUT /api/webauthn
 * 使用 WebAuthn 断言更新凭证的 PRF 加密密钥
 * 对应 WebAuthnController.UpdateCredential
 */
webauthn.put('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        token: string;
        deviceResponse: unknown;
        encryptedUserKey?: string;
        encryptedPrivateKey?: string;
        encryptedPublicKey?: string;
    }>();

    if (!body?.token || !body?.deviceResponse) {
        throw new BadRequestError('Invalid request.');
    }

    const options = await verifyWebAuthnToken(
        c.env,
        body.token,
        'WebAuthnLoginAssertionOptionsToken',
        1,
    );

    const deviceResponse = typeof body.deviceResponse === 'string'
        ? JSON.parse(body.deviceResponse) as { id: string; response: Record<string, string> }
        : (body.deviceResponse as { id: string; response: Record<string, string> });
    const resp = deviceResponse.response ?? {} as Record<string, string>;

    const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
    let rpId: string;
    try {
        rpId = new URL(origin).hostname;
    } catch {
        rpId = 'localhost';
    }

    // 解码 clientDataJSON
    const clientDataBytes = base64UrlToBytes(resp.clientDataJSON || resp.clientDataJson);
    const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

    if (clientData.type !== 'webauthn.get') {
        throw new BadRequestError('Unable to update credential.');
    }
    if (clientData.challenge !== options.challenge) {
        throw new BadRequestError('Unable to update credential.');
    }
    if (clientData.origin !== origin) {
        throw new BadRequestError('Unable to update credential.');
    }

    // 解码 authenticatorData
    const authDataBytes = base64UrlToBytes(resp.authenticatorData);

    // rpIdHash
    const rpIdHash = authDataBytes.slice(0, 32);
    const expectedRpIdHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', new TextEncoder().encode(rpId)),
    );
    for (let i = 0; i < 32; i++) {
        if (rpIdHash[i] !== expectedRpIdHash[i]) {
            throw new BadRequestError('Unable to update credential.');
        }
    }

    // flags
    const flags = authDataBytes[32];
    if ((flags & 0x01) === 0) {
        throw new BadRequestError('Unable to update credential.');
    }

    // signCount
    const signCount = (authDataBytes[33] << 24) | (authDataBytes[34] << 16) | (authDataBytes[35] << 8) | authDataBytes[36];

    const credentialId = deviceResponse.id;
    const credential = await db.select().from(webAuthnCredentials)
        .where(and(
            eq(webAuthnCredentials.userId, userId),
            eq(webAuthnCredentials.credentialId, credentialId),
        ))
        .get();

    if (!credential || !credential.supportsPrf) {
        throw new BadRequestError('Unable to update credential.');
    }

    // 验证签名
    const signatureBytes = base64UrlToBytes(resp.signature);
    const clientDataHash = new Uint8Array(
        await crypto.subtle.digest('SHA-256', clientDataBytes),
    );
    const signedData = new Uint8Array(authDataBytes.length + clientDataHash.length);
    signedData.set(authDataBytes);
    signedData.set(clientDataHash, authDataBytes.length);

    const publicKeyBytes = base64UrlToBytes(credential.publicKey);
    const signatureValid = await verifySignatureWithCoseKey(publicKeyBytes, signedData, signatureBytes);
    if (!signatureValid) {
        throw new BadRequestError('Unable to update credential.');
    }

    const now = new Date().toISOString();
    await db.update(webAuthnCredentials).set({
        counter: signCount,
        encryptedUserKey: body.encryptedUserKey,
        encryptedPrivateKey: body.encryptedPrivateKey,
        encryptedPublicKey: body.encryptedPublicKey,
        revisionDate: now,
    }).where(eq(webAuthnCredentials.id, credential.id));

    return c.body(null, 200);
});

/**
 * POST /api/webauthn/:id/delete
 * 删除通行密钥
 * 对应 WebAuthnController.Delete
 */
webauthn.post('/:id/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({})) as { masterPasswordHash?: string };

    await verifyUserSecret(db, userId, body.masterPasswordHash);

    const credential = await db.select().from(webAuthnCredentials)
        .where(and(
            eq(webAuthnCredentials.id, id),
            eq(webAuthnCredentials.userId, userId),
        ))
        .get();

    if (!credential) {
        throw new NotFoundError('Credential not found.');
    }

    await db.delete(webAuthnCredentials)
        .where(and(
            eq(webAuthnCredentials.id, id),
            eq(webAuthnCredentials.userId, userId),
        ));

    return c.body(null, 200);
});

// 将 uuid 字符串转为 bytes（与 services/webauthn 中逻辑一致，这里内联一份避免循环依赖）
function uuidToBytes(uuid: string): Uint8Array {
    const hex = uuid.replace(/-/g, '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

export default webauthn;

