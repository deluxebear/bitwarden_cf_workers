/**
 * Bitwarden Workers - Identity 路由
 * 对应原始项目 Identity/Controllers/AccountsController.cs
 * 处理：Prelogin、Register、Token（登录）
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, isNull, sql } from 'drizzle-orm';
import { users, devices, refreshTokens, organizationUsers, sends, organizations, ssoConfigs, oidcIdentities } from '../db/schema';
import { signJwt, signJwtClaims } from '../middleware/auth';
import { generateUuid, generateSecureRandomString, generateRefreshToken, sha256, verifyPassword, verifySendPassword, verifyInviteToken } from '../services/crypto';
import { verifyAuthenticatorCode } from '../services/totp';
import { logEvent } from '../services/events';
import { BadRequestError } from '../middleware/error';
import { bytesToBase64Url, base64UrlToBytes, verifyWebAuthnAuthentication } from '../services/webauthn';
import { webAuthnCredentials, authRequests } from '../db/schema';
import { isSignupAllowed } from '../services/signup-guard';
import { normalizeRegistrationRequest } from '../services/registration';
import {
    buildDevTokenResponse,
    consumeVerificationToken,
    sendNewDeviceVerification,
    sendRegistrationVerification,
    sendSendAccessOtp,
    verifyVerificationToken,
} from '../services/email';
import { AuthRequestType, DeviceType } from '../types';
import type { Bindings, Variables, KdfType, PreloginRequest, PreloginResponse, RegisterRequest, TokenRequest, TokenResponse } from '../types';
import type { OrganizationUserRow } from '../db/schema';
import {
    assertEmailNotBlockedByClaimedDomain,
    getMasterPasswordPolicyForUser,
} from '../services/policy-requirements';
import { getDeviceTypeFromRequest } from './events';
import { isLoginBackoffActive } from '../services/login-security';
import { getYubicoValidationConfig, parseYubiKeyOtp, verifyYubicoOtp } from '../services/yubikey';
import {
    exchangeOidcAuthorizationCode,
    fetchOidcDiscovery,
    fetchOidcJwks,
    generateOidcNonce,
    generatePkcePair,
    verifyOidcIdToken,
} from '../services/oidc';
import {
    consumeOidcAuthorizationCode,
    consumeOidcLoginState,
    createOidcAuthorizationCode,
    createOidcLoginState,
    createSsoPrevalidationToken,
    hasVerifiedOidcEmailClaim,
    readMappedStringClaim,
    validateClientRedirectUri,
    verifySsoPrevalidationToken,
} from '../services/oidc-login';
import {
    buildDuoRedirectUri,
    checkDuoHealth,
    createDuoAuthorizationUrl,
    exchangeDuoAuthorizationCode,
} from '../services/duo';
import {
    consumeDuoLoginState,
    createDuoLoginState,
    getDuoConfigById,
    getDuoConfigByOwner,
} from '../services/duo-storage';
import { canAccessPremium } from '../services/premium';

const identity = new Hono<{ Bindings: Bindings; Variables: Variables }>();
const SEND_ACCESS_TOKEN_LIFETIME_SECONDS = 15 * 60;
const OFFICIAL_CLIENT_IDS = new Set(['web', 'browser', 'desktop', 'mobile', 'cli', 'connector']);
const CLIENT_BOUND_GRANTS = new Set(['password', 'refresh_token', 'authorization_code', 'webauthn']);

type RegisterFinishInvite = {
    organizationUserId?: string;
    orgInviteToken?: string;
};

type D1Db = ReturnType<typeof drizzle>;

function getRegisterFinishInvite(body: Record<string, unknown>): RegisterFinishInvite {
    const organizationUserId = typeof body.organizationUserId === 'string'
        ? body.organizationUserId
        : typeof body.organization_user_id === 'string'
            ? body.organization_user_id
            : undefined;
    const orgInviteToken = typeof body.orgInviteToken === 'string'
        ? body.orgInviteToken
        : typeof body.org_invite_token === 'string'
            ? body.org_invite_token
            : undefined;

    return { organizationUserId, orgInviteToken };
}

async function getValidRegisterFinishInvite(
    db: D1Db,
    env: Bindings,
    email: string,
    invite: RegisterFinishInvite,
) {
    if (!invite.organizationUserId && !invite.orgInviteToken) return null;
    if (!invite.organizationUserId || !invite.orgInviteToken) {
        throw new BadRequestError('Organization invitation token is invalid.');
    }

    const payload = await verifyInviteToken(invite.orgInviteToken, env.JWT_SECRET);
    if (!payload ||
        payload.orgUserId !== invite.organizationUserId ||
        payload.email.toLowerCase() !== email.toLowerCase()) {
        throw new BadRequestError('Organization invitation token is invalid.');
    }

    const orgUser = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.id, payload.orgUserId),
            eq(organizationUsers.organizationId, payload.orgId),
        ))
        .get();

    if (!orgUser ||
        orgUser.status !== 0 ||
        orgUser.email.toLowerCase() !== email.toLowerCase()) {
        throw new BadRequestError('Organization invitation token is invalid.');
    }

    return orgUser;
}

async function acceptRegisterFinishInvite(
    db: D1Db,
    c: any,
    invite: OrganizationUserRow,
    userId: string,
    now: string,
) {
    await db.update(organizationUsers).set({
        userId,
        status: 1, // Accepted
        revisionDate: now,
    }).where(and(
        eq(organizationUsers.id, invite.id),
        eq(organizationUsers.status, 0),
    ));

    await logEvent(c.env.DB, 1501, {
        userId,
        organizationId: invite.organizationId,
        organizationUserId: invite.id,
        deviceType: getDeviceTypeFromRequest(c),
    });
}

async function attachMasterPasswordPolicy(db: D1Db, userId: string, response: Record<string, any>): Promise<void> {
    const policy = await getMasterPasswordPolicyForUser(db, userId);
    response.MasterPasswordPolicy = policy;
}

function unsupportedSsoResponse(c: any) {
    return c.json({
        error: 'unsupported_sso',
        error_description: 'SSO/OIDC is not supported by this Workers deployment.',
        ErrorModel: {
            Message: 'SSO/OIDC is not supported by this Workers deployment.',
            Object: 'error',
        },
        message: 'SSO/OIDC is not supported by this Workers deployment.',
        object: 'error',
    }, 400);
}

type RuntimeSsoConfig = {
    organizationId: string;
    issuer: string;
    clientId: string;
    clientSecretEnv: string;
    redirectUri: string;
    claimMapping: Record<string, string[]>;
};

function oidcError(c: any, error: string, description: string, status = 400) {
    return c.json({
        error,
        error_description: description,
        ErrorModel: { Message: description, Object: 'error' },
    }, status);
}

function parseClaimMapping(value: string | null): Record<string, string[]> {
    if (!value) return {};
    try {
        const parsed = JSON.parse(value) as unknown;
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
        const result: Record<string, string[]> = {};
        for (const [target, names] of Object.entries(parsed)) {
            if (Array.isArray(names) && names.every((name) => typeof name === 'string')) {
                result[target] = names as string[];
            }
        }
        return result;
    } catch {
        return {};
    }
}

async function getRuntimeSsoConfigByIdentifier(db: D1Db, identifier: string): Promise<RuntimeSsoConfig | null> {
    const row = await db.select({
        organizationId: organizations.id,
        issuer: ssoConfigs.issuer,
        clientId: ssoConfigs.clientId,
        clientSecretEnv: ssoConfigs.clientSecretEnv,
        redirectUri: ssoConfigs.redirectUri,
        claimMapping: ssoConfigs.claimMapping,
    }).from(organizations).innerJoin(ssoConfigs, eq(ssoConfigs.organizationId, organizations.id))
        .where(and(
            sql`lower(${organizations.identifier}) = ${identifier.toLowerCase()}`,
            eq(organizations.useSso, true),
            eq(organizations.enabled, true),
            eq(ssoConfigs.enabled, true),
        )).get();
    if (!row?.issuer || !row.clientId || !row.clientSecretEnv || !row.redirectUri) return null;
    return { ...row, claimMapping: parseClaimMapping(row.claimMapping) } as RuntimeSsoConfig;
}

async function getRuntimeSsoConfigByOrganization(db: D1Db, organizationId: string): Promise<RuntimeSsoConfig | null> {
    const row = await db.select({
        organizationId: organizations.id,
        issuer: ssoConfigs.issuer,
        clientId: ssoConfigs.clientId,
        clientSecretEnv: ssoConfigs.clientSecretEnv,
        redirectUri: ssoConfigs.redirectUri,
        claimMapping: ssoConfigs.claimMapping,
    }).from(organizations).innerJoin(ssoConfigs, eq(ssoConfigs.organizationId, organizations.id))
        .where(and(
            eq(organizations.id, organizationId),
            eq(organizations.useSso, true),
            eq(organizations.enabled, true),
            eq(ssoConfigs.enabled, true),
        )).get();
    if (!row?.issuer || !row.clientId || !row.clientSecretEnv || !row.redirectUri) return null;
    return { ...row, claimMapping: parseClaimMapping(row.claimMapping) } as RuntimeSsoConfig;
}

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

/** GET /identity/sso/prevalidate */
identity.get('/sso/prevalidate', async (c) => {
    const domainHint = c.req.query('domainHint')?.trim().toLowerCase();
    if (!domainHint) return oidcError(c, 'invalid_request', 'No domain hint was provided.');
    const db = drizzle(c.env.DB);
    const config = await getRuntimeSsoConfigByIdentifier(db, domainHint);
    if (!config) return oidcError(c, 'invalid_request', 'SSO identifier is invalid or disabled.');
    const secret = c.env[config.clientSecretEnv];
    if (typeof secret !== 'string' || !secret.trim()) {
        return oidcError(c, 'server_error', 'SSO configuration is unavailable.', 503);
    }
    const token = await createSsoPrevalidationToken(config.organizationId, c.env.JWT_SECRET);
    return c.json({ token, object: 'ssoPreValidate' });
});

/** GET /identity/connect/authorize */
identity.get('/connect/authorize', async (c) => {
    const domainHint = c.req.query('domain_hint')?.trim().toLowerCase();
    const ssoToken = c.req.query('ssoToken') ?? c.req.query('sso_token');
    const clientId = c.req.query('client_id')?.trim();
    const redirectUriRaw = c.req.query('redirect_uri');
    const codeChallenge = c.req.query('code_challenge')?.trim();
    const challengeMethod = c.req.query('code_challenge_method');
    if (!domainHint || !ssoToken || !clientId || !redirectUriRaw || !codeChallenge) {
        return oidcError(c, 'invalid_request', 'Required authorization parameters are missing.');
    }
    if (c.req.query('response_type') !== 'code' || challengeMethod !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(codeChallenge)) {
        return oidcError(c, 'invalid_request', 'Authorization code flow with PKCE S256 is required.');
    }
    let clientRedirectUri: string;
    try {
        clientRedirectUri = validateClientRedirectUri(redirectUriRaw, clientId, c.env.VAULT_BASE_URL);
    } catch {
        return oidcError(c, 'invalid_request', 'redirect_uri is invalid.');
    }

    const db = drizzle(c.env.DB);
    const config = await getRuntimeSsoConfigByIdentifier(db, domainHint);
    const tokenOrganizationId = await verifySsoPrevalidationToken(ssoToken, c.env.JWT_SECRET);
    if (!config || tokenOrganizationId !== config.organizationId) {
        return oidcError(c, 'access_denied', 'SSO prevalidation token is invalid or expired.');
    }
    const secret = c.env[config.clientSecretEnv];
    if (typeof secret !== 'string' || !secret.trim()) {
        return oidcError(c, 'server_error', 'SSO configuration is unavailable.', 503);
    }

    try {
        const discovery = await fetchOidcDiscovery(config.issuer);
        const nonce = generateOidcNonce();
        const providerPkce = await generatePkcePair();
        const state = await createOidcLoginState(c.env.DB, {
            organizationId: config.organizationId,
            nonce,
            providerPkceVerifier: providerPkce.verifier,
            clientId,
            clientRedirectUri,
            clientState: c.req.query('state') ?? null,
            clientCodeChallenge: codeChallenge,
        });
        const authorizationUrl = new URL(discovery.authorization_endpoint);
        authorizationUrl.searchParams.set('client_id', config.clientId);
        authorizationUrl.searchParams.set('response_type', 'code');
        authorizationUrl.searchParams.set('scope', 'openid email profile');
        authorizationUrl.searchParams.set('redirect_uri', config.redirectUri);
        authorizationUrl.searchParams.set('state', state);
        authorizationUrl.searchParams.set('nonce', nonce);
        authorizationUrl.searchParams.set('code_challenge', providerPkce.challenge);
        authorizationUrl.searchParams.set('code_challenge_method', 'S256');
        return c.redirect(authorizationUrl.toString(), 302);
    } catch {
        return oidcError(c, 'server_error', 'Unable to start SSO authentication.', 502);
    }
});

function redirectOidcClient(
    redirectUri: string,
    params: { code?: string; error?: string; errorDescription?: string; state?: string | null },
) {
    const url = new URL(redirectUri);
    if (params.code) url.searchParams.set('code', params.code);
    if (params.error) url.searchParams.set('error', params.error);
    if (params.errorDescription) url.searchParams.set('error_description', params.errorDescription);
    if (params.state) url.searchParams.set('state', params.state);
    return url.toString();
}

async function resolveOidcUser(
    db: D1Db,
    d1: D1Database,
    input: { organizationId: string; issuer: string; subject: string; email: string },
) {
    const existingIdentity = await db.select().from(oidcIdentities).where(and(
        eq(oidcIdentities.organizationId, input.organizationId),
        eq(oidcIdentities.issuer, input.issuer),
        eq(oidcIdentities.subject, input.subject),
    )).get();

    const user = existingIdentity
        ? await db.select().from(users).where(eq(users.id, existingIdentity.userId)).get()
        : await db.select().from(users).where(eq(users.email, input.email)).get();
    if (!user || !user.emailVerified || user.email.toLowerCase() !== input.email) return null;

    const membership = await db.select().from(organizationUsers).where(and(
        eq(organizationUsers.organizationId, input.organizationId),
        eq(organizationUsers.email, input.email),
    )).get();
    if (!membership || membership.status < 0 || membership.status > 2) return null;
    if (membership.userId && membership.userId !== user.id) return null;

    if (existingIdentity) {
        return existingIdentity.userId === user.id ? user : null;
    }

    const now = new Date().toISOString();
    await d1.batch([
        d1.prepare(`
            INSERT INTO oidc_identities
                (organization_id, issuer, subject, user_id, email, creation_date, revision_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(input.organizationId, input.issuer, input.subject, user.id, input.email, now, now),
        d1.prepare(`
            UPDATE organization_users
            SET user_id = ?, external_id = ?, status = ?, revision_date = ?
            WHERE id = ? AND (user_id IS NULL OR user_id = ?)
        `).bind(user.id, input.subject, membership.status === 0 ? 1 : membership.status, now, membership.id, user.id),
    ]);
    return user;
}

/** IdP callback; also mounted by index.ts at the configured /oidc-signin path. */
export async function handleOidcCallback(c: any) {
    let code: string | undefined;
    let state: string | undefined;
    let providerError: string | undefined;
    if (c.req.method === 'POST') {
        const form = await c.req.parseBody();
        code = typeof form.code === 'string' ? form.code : undefined;
        state = typeof form.state === 'string' ? form.state : undefined;
        providerError = typeof form.error === 'string' ? form.error : undefined;
    } else {
        code = c.req.query('code');
        state = c.req.query('state');
        providerError = c.req.query('error');
    }
    if (!state) return oidcError(c, 'invalid_request', 'OIDC state is required.');

    const loginState = await consumeOidcLoginState(c.env.DB, state);
    if (!loginState) return oidcError(c, 'invalid_request', 'OIDC state is invalid, expired, or already used.');
    if (providerError || !code) {
        return c.redirect(redirectOidcClient(loginState.clientRedirectUri, {
            error: 'access_denied',
            errorDescription: 'The identity provider denied authentication.',
            state: loginState.clientState,
        }), 302);
    }

    const db = drizzle(c.env.DB);
    const config = await getRuntimeSsoConfigByOrganization(db, loginState.organizationId);
    if (!config) {
        return c.redirect(redirectOidcClient(loginState.clientRedirectUri, {
            error: 'server_error', errorDescription: 'SSO configuration is unavailable.', state: loginState.clientState,
        }), 302);
    }
    const clientSecret = c.env[config.clientSecretEnv];
    if (typeof clientSecret !== 'string' || !clientSecret.trim()) {
        return c.redirect(redirectOidcClient(loginState.clientRedirectUri, {
            error: 'server_error', errorDescription: 'SSO configuration is unavailable.', state: loginState.clientState,
        }), 302);
    }

    try {
        const discovery = await fetchOidcDiscovery(config.issuer);
        const tokenResponse = await exchangeOidcAuthorizationCode(discovery.token_endpoint, {
            code,
            clientId: config.clientId,
            clientSecret,
            redirectUri: config.redirectUri,
            codeVerifier: loginState.providerPkceVerifier,
        });
        const jwks = await fetchOidcJwks(discovery.jwks_uri);
        const claims = await verifyOidcIdToken(tokenResponse.id_token, jwks, {
            issuer: discovery.issuer,
            audience: config.clientId,
            nonce: loginState.nonce,
        });
        const claimRecord: Record<string, unknown> = { ...claims };
        const subject = typeof claims.sub === 'string' ? claims.sub : null;
        const email = readMappedStringClaim(claimRecord, config.claimMapping, 'email', ['email'])?.toLowerCase() ?? null;
        const emailVerified = hasVerifiedOidcEmailClaim(claimRecord, config.claimMapping);
        if (!subject || !email || !emailVerified) throw new Error('OIDC identity is missing a verified email.');

        const user = await resolveOidcUser(db, c.env.DB, {
            organizationId: config.organizationId,
            issuer: discovery.issuer.replace(/\/$/, ''),
            subject,
            email,
        });
        if (!user) throw new Error('OIDC identity is not linked to an eligible organization member.');

        const authorizationCode = await createOidcAuthorizationCode(c.env.DB, {
            organizationId: config.organizationId,
            userId: user.id,
            clientId: loginState.clientId,
            redirectUri: loginState.clientRedirectUri,
            codeChallenge: loginState.clientCodeChallenge,
        });
        return c.redirect(redirectOidcClient(loginState.clientRedirectUri, {
            code: authorizationCode,
            state: loginState.clientState,
        }), 302);
    } catch {
        return c.redirect(redirectOidcClient(loginState.clientRedirectUri, {
            error: 'access_denied',
            errorDescription: 'SSO authentication could not be completed.',
            state: loginState.clientState,
        }), 302);
    }
}

identity.on(['GET', 'POST'], '/connect/callback', handleOidcCallback);

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
    const registration = normalizeRegistrationRequest(body);

    if (!registration.email || !registration.masterPasswordHash) {
        throw new BadRequestError('Email and master password hash are required.');
    }

    const db = drizzle(c.env.DB);
    const email = registration.email.toLowerCase().trim();

    if (!await isSignupAllowed(c.env, db, email)) {
        throw new BadRequestError('Registration is disabled. Please contact the administrator for an invitation.');
    }
    await assertEmailNotBlockedByClaimedDomain(db, email, true);

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
        name: registration.name || null,
        email,
        emailVerified: false,
        masterPassword: registration.masterPasswordHash,
        masterPasswordHint: registration.masterPasswordHint || null,
        culture: 'en-US',
        securityStamp: generateSecureRandomString(50),
        key: registration.key,
        publicKey: registration.publicKey,
        privateKey: registration.privateKey,
        kdf: registration.kdf,
        kdfIterations: registration.kdfIterations,
        kdfMemory: registration.kdfMemory,
        kdfParallelism: registration.kdfParallelism,
        apiKey: generateSecureRandomString(30),
        accountRevisionDate: now,
        creationDate: now,
        revisionDate: now,
    });

    return c.json(null, 200);
});

/**
 * POST /identity/accounts/register/send-verification-email
 * 新注册流程第一步：发送验证邮件。
 */
identity.post('/accounts/register/send-verification-email', async (c) => {
    const body = await c.req.json() as { email: string; name?: string; receiveMarketingEmails?: boolean };

    if (!body.email) throw new BadRequestError('Email is required.');

    const db = drizzle(c.env.DB);
    const email = body.email.toLowerCase().trim();

    if (!await isSignupAllowed(c.env, db, email)) {
        throw new BadRequestError('Registration is disabled. Please contact the administrator for an invitation.');
    }
    await assertEmailNotBlockedByClaimedDomain(db, email, true);

    const existing = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (existing) throw new BadRequestError('Email is already registered.');

    const token = await sendRegistrationVerification(db, c.env, email);
    return c.json(buildDevTokenResponse(c.env, token), 200);
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

    await verifyVerificationToken(
        drizzle(c.env.DB),
        body.email.toLowerCase().trim(),
        'registration',
        body.emailVerificationToken,
    );
    return c.json(null, 200);
});

/**
 * POST /identity/accounts/register/finish
 * 新注册流程第三步：完成注册，提交加密密钥和密码哈希。
 * 若该邮箱已在 users 表存在且存在「待接受的组织邀请」(organization_users status=Invited)，
 * 则视为邀请完成注册：用本次提交的密码与密钥更新该用户，不报「已注册」。
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
        organizationUserId?: string;
        orgInviteToken?: string;
        organization_user_id?: string;
        org_invite_token?: string;
        name?: string;
    };
    const registration = normalizeRegistrationRequest(body);

    if (!registration.email || !registration.masterPasswordHash) {
        throw new BadRequestError('Email and master password hash are required.');
    }

    const db = drizzle(c.env.DB);
    const email = registration.email.toLowerCase().trim();
    const { generateSecureRandomString } = await import('../services/crypto');
    const now = new Date().toISOString();
    const registerInvite = await getValidRegisterFinishInvite(
        db,
        c.env,
        email,
        getRegisterFinishInvite(body),
    );

    const existingUser = await db.select().from(users).where(eq(users.email, email)).get();

    if (existingUser) {
        // 该邮箱已存在：仅当请求携带有效组织邀请 token 时允许「完成注册」（用新密码/密钥更新）。
        if (!registerInvite) {
            throw new BadRequestError('Email is already registered.');
        }
        if (registerInvite?.userId && registerInvite.userId !== existingUser.id) {
            throw new BadRequestError('This invitation belongs to a different user.');
        }
        await db.update(users).set({
            masterPassword: registration.masterPasswordHash,
            masterPasswordHint: registration.masterPasswordHint ?? null,
            key: registration.key,
            publicKey: registration.publicKey,
            privateKey: registration.privateKey,
            kdf: registration.kdf,
            kdfIterations: registration.kdfIterations,
            kdfMemory: registration.kdfMemory,
            kdfParallelism: registration.kdfParallelism,
            accountRevisionDate: now,
            revisionDate: now,
            emailVerified: true,
            name: registration.name ?? existingUser.name,
        }).where(eq(users.id, existingUser.id));

        await acceptRegisterFinishInvite(db, c, registerInvite, existingUser.id, now);
        return c.json(null, 200);
    }

    if (!registerInvite) {
        // 新用户普通注册：检查是否允许开放注册，并要求邮箱验证码。
        if (!await isSignupAllowed(c.env, db, email)) {
            throw new BadRequestError('Registration is disabled. Please contact the administrator for an invitation.');
        }
        await assertEmailNotBlockedByClaimedDomain(db, email, true);
        if (!body.emailVerificationToken) {
            throw new BadRequestError('Email verification token is required.');
        }
        await consumeVerificationToken(db, email, 'registration', body.emailVerificationToken);
    }

    const userId = crypto.randomUUID();

    await db.insert(users).values({
        id: userId,
        name: registration.name || null,
        email,
        emailVerified: true,
        masterPassword: registration.masterPasswordHash,
        masterPasswordHint: registration.masterPasswordHint || null,
        culture: 'en-US',
        securityStamp: generateSecureRandomString(50),
        key: registration.key,
        publicKey: registration.publicKey,
        privateKey: registration.privateKey,
        kdf: registration.kdf,
        kdfIterations: registration.kdfIterations,
        kdfMemory: registration.kdfMemory,
        kdfParallelism: registration.kdfParallelism,
        apiKey: generateSecureRandomString(30),
        accountRevisionDate: now,
        creationDate: now,
        revisionDate: now,
    });

    if (registerInvite) {
        await acceptRegisterFinishInvite(db, c, registerInvite, userId, now);
    }

    return c.json(null, 200);
});

type SendAccessTokenRequest = {
    send_id?: string;
    password_hash_b64?: string;
    email?: string;
    otp?: string;
};

type NewDeviceTokenRequest = TokenRequest & {
    newDeviceOtp?: string;
    NewDeviceOtp?: string;
    new_device_otp?: string;
    deeplinkScheme?: string;
};

type LoginDeviceInfo = {
    id: string;
    type: number;
};

function readStringField(source: object, ...keys: string[]): string | undefined {
    for (const key of keys) {
        const value = (source as { [key: string]: unknown })[key];
        if (typeof value === 'string' && value.trim()) return value.trim();
    }
    return undefined;
}

function readNumberField(source: object, ...keys: string[]): number | undefined {
    for (const key of keys) {
        const value = (source as { [key: string]: unknown })[key];
        if (typeof value === 'number' && Number.isInteger(value)) return value;
        if (typeof value === 'string' && value.trim()) {
            const parsed = Number(value);
            if (Number.isInteger(parsed)) return parsed;
        }
    }
    return undefined;
}

async function upsertLoginDevice(db: any, userId: string, body: object): Promise<LoginDeviceInfo> {
    const identifier = readStringField(body, 'deviceIdentifier', 'DeviceIdentifier', 'device_identifier');
    const name = readStringField(body, 'deviceName', 'DeviceName', 'device_name');
    const type = readNumberField(body, 'deviceType', 'DeviceType', 'device_type');

    if (!identifier || !name || type === undefined) {
        throw new BadRequestError('deviceIdentifier, deviceType, and deviceName are required.');
    }
    if (type < 0 || type > DeviceType.DuckDuckGoBrowser) {
        throw new BadRequestError('deviceType is invalid.');
    }

    const now = new Date().toISOString();
    const existingDevice = await db.select().from(devices)
        .where(and(eq(devices.userId, userId), eq(devices.identifier, identifier)))
        .get();
    if (existingDevice) {
        await db.update(devices).set({
            name,
            type,
            active: true,
            revisionDate: now,
        }).where(eq(devices.id, existingDevice.id));
        return { id: existingDevice.id, type };
    }

    const deviceId = generateUuid();
    await db.insert(devices).values({
        id: deviceId,
        userId,
        name,
        type,
        identifier,
        active: true,
        creationDate: now,
        revisionDate: now,
    });
    return { id: deviceId, type };
}

async function isKnownActiveLoginDevice(db: any, userId: string, body: object): Promise<boolean> {
    const identifier = readStringField(body, 'deviceIdentifier', 'DeviceIdentifier', 'device_identifier');
    if (!identifier) return false;
    const existingDevice = await db.select({
        id: devices.id,
        active: devices.active,
    }).from(devices)
        .where(and(eq(devices.userId, userId), eq(devices.identifier, identifier)))
        .get();
    return !!existingDevice?.active;
}

function getNewDeviceOtp(body: object): string | undefined {
    return readStringField(body, 'newDeviceOtp', 'NewDeviceOtp', 'new_device_otp');
}

function newDeviceVerificationRequired(c: any, devResponse: Record<string, unknown>) {
    return c.json({
        error: 'invalid_grant',
        error_description: 'New device verification required.',
        ErrorModel: {
            Message: 'new device verification required',
            Object: 'error',
        },
        DeviceVerified: false,
        ...devResponse,
    }, 400);
}

function uuidFromSendAccessId(accessId: string): string {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(accessId)) {
        return accessId.toLowerCase();
    }

    let bytes: Uint8Array;
    try {
        bytes = base64UrlToBytes(accessId);
    } catch {
        throw new Error('invalid_send_id');
    }
    if (bytes.length !== 16) {
        throw new Error('invalid_send_id');
    }

    // .NET Guid.ToByteArray uses little-endian order for the first three fields.
    const guidBytes = [
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        ...bytes.slice(8),
    ];
    const hex = guidBytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function sendAccessError(c: any, error: 'invalid_request' | 'invalid_grant', errorDescription: string, errorType: string) {
    return c.json({
        error,
        error_description: errorDescription,
        send_access_error_type: errorType,
    }, 400);
}

function sendCanBeAccessed(send: typeof sends.$inferSelect): boolean {
    const now = new Date().toISOString();
    return !send.disabled &&
        send.deletionDate > now &&
        (!send.expirationDate || send.expirationDate > now) &&
        (send.maxAccessCount === null || send.accessCount < send.maxAccessCount);
}

/**
 * POST /identity/connect/token
 * 对应原始项目 Identity 模块的 OAuth2 Token 端点
 * 支持 password grant (登录) 和 refresh_token grant (刷新)
 */
identity.post('/connect/token', async (c) => {
    // Bitwarden 客户端发送 application/x-www-form-urlencoded
    const contentType = c.req.header('content-type') || '';
    let body: NewDeviceTokenRequest;

    // WebAuthn grant 特有字段
    let webAuthnToken: string | undefined;
    let webAuthnDeviceResponse: string | undefined;

    if (contentType.includes('application/x-www-form-urlencoded')) {
        const formData = await c.req.parseBody();
        body = {
            grant_type: formData['grant_type'] as any,
            username: formData['username'] as string,
            password: formData['password'] as string,
            scope: formData['scope'] as string,
            client_id: formData['client_id'] as string,
            deviceType: formData['deviceType'] !== undefined ? Number(formData['deviceType']) : (formData['DeviceType'] !== undefined ? Number(formData['DeviceType']) : undefined),
            deviceIdentifier: (formData['deviceIdentifier'] || formData['DeviceIdentifier']) as string,
            deviceName: (formData['deviceName'] || formData['DeviceName']) as string,
            refresh_token: formData['refresh_token'] as string,
            code: formData['code'] as string,
            code_verifier: formData['code_verifier'] as string,
            redirect_uri: formData['redirect_uri'] as string,
            authRequest: (formData['authRequest'] || formData['AuthRequest']) as string,
            send_id: formData['send_id'] as string,
            password_hash_b64: formData['password_hash_b64'] as string,
            email: formData['email'] as string,
            otp: formData['otp'] as string,
            newDeviceOtp: (formData['newDeviceOtp'] || formData['NewDeviceOtp'] || formData['new_device_otp']) as string,
            deeplinkScheme: (formData['deeplinkScheme'] || formData['DeeplinkScheme']) as string,
            TwoFactorProvider: formData['TwoFactorProvider'] ? Number(formData['TwoFactorProvider']) : (formData['twoFactorProvider'] ? Number(formData['twoFactorProvider']) : undefined),
            TwoFactorToken: (formData['TwoFactorToken'] || formData['twoFactorToken']) as string,
        } as NewDeviceTokenRequest & SendAccessTokenRequest;
        webAuthnToken = formData['token'] as string;
        webAuthnDeviceResponse = formData['deviceResponse'] as string;
    } else {
        const rawBody = await c.req.json<any>();
        body = rawBody as NewDeviceTokenRequest & SendAccessTokenRequest;
        webAuthnToken = rawBody.token;
        webAuthnDeviceResponse = rawBody.deviceResponse;
    }

    if (CLIENT_BOUND_GRANTS.has(body.grant_type) && !OFFICIAL_CLIENT_IDS.has(body.client_id ?? '')) {
        return oidcError(c, 'invalid_client', 'client_id is invalid.');
    }

    const db = drizzle(c.env.DB);

    if (body.grant_type === 'password') {
        return await handlePasswordGrant(c, db, body);
    } else if (body.grant_type === 'refresh_token') {
        return await handleRefreshTokenGrant(c, db, body);
    } else if (body.grant_type === 'webauthn') {
        return await handleWebAuthnGrant(c, db, body, webAuthnToken, webAuthnDeviceResponse);
    } else if (body.grant_type === 'send_access') {
        return await handleSendAccessGrant(c, db, body as TokenRequest & SendAccessTokenRequest);
    } else if (body.grant_type === 'authorization_code') {
        return await handleAuthorizationCodeGrant(c, db, body);
    }

    throw new BadRequestError('Unsupported grant_type.');
});

async function handleAuthorizationCodeGrant(c: any, db: D1Db, body: TokenRequest) {
    if (!body.code || !body.code_verifier || !body.redirect_uri || !body.client_id) {
        return oidcError(c, 'invalid_request', 'code, code_verifier, redirect_uri, and client_id are required.');
    }
    let redirectUri: string;
    try {
        redirectUri = validateClientRedirectUri(body.redirect_uri, body.client_id, c.env.VAULT_BASE_URL);
    } catch {
        return oidcError(c, 'invalid_grant', 'Authorization code is invalid.');
    }
    const grant = await consumeOidcAuthorizationCode(c.env.DB, {
        code: body.code,
        clientId: body.client_id,
        redirectUri,
        codeVerifier: body.code_verifier,
    });
    if (!grant) return oidcError(c, 'invalid_grant', 'Authorization code is invalid, expired, or already used.');

    const user = await db.select().from(users).where(eq(users.id, grant.userId)).get();
    const membership = await db.select().from(organizationUsers).where(and(
        eq(organizationUsers.organizationId, grant.organizationId),
        eq(organizationUsers.userId, grant.userId),
    )).get();
    if (!user || !user.emailVerified || !membership || membership.status < 1 || membership.status > 2) {
        return oidcError(c, 'invalid_grant', 'SSO organization membership is no longer active.');
    }

    const loginDevice = await upsertLoginDevice(db, user.id, body);
    const expiresIn = Number.parseInt(c.env.JWT_EXPIRATION || '3600', 10);
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        email_verified: true,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
        sstamp: user.securityStamp,
        device: loginDevice.id,
        scope: ['api', 'offline_access'],
        amr: ['sso'],
    }, c.env.JWT_SECRET, expiresIn);
    const refreshToken = generateRefreshToken();
    const refreshExpiresIn = Number.parseInt(c.env.JWT_REFRESH_EXPIRATION || '2592000', 10);
    await db.insert(refreshTokens).values({
        id: generateUuid(),
        userId: user.id,
        deviceId: loginDevice.id,
        tokenHash: await sha256(refreshToken),
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });
    await logEvent(c.env.DB, 1000, {
        userId: user.id,
        organizationId: grant.organizationId,
        deviceType: loginDevice.type,
        ipAddress: c.req.header('CF-Connecting-IP') || c.req.header('x-forwarded-for') || null,
    });

    const response: Record<string, any> = {
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
            },
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
    await attachMasterPasswordPolicy(db, user.id, response);
    return c.json(response);
}

async function handleSendAccessGrant(
    c: any,
    db: any,
    body: TokenRequest & SendAccessTokenRequest,
) {
    if (!body.send_id) {
        return sendAccessError(c, 'invalid_request', 'send_id is required.', 'send_id_required');
    }

    let sendId: string;
    try {
        sendId = uuidFromSendAccessId(body.send_id);
    } catch {
        return sendAccessError(c, 'invalid_grant', 'send_id is invalid.', 'send_id_invalid');
    }

    const send = await db.select().from(sends).where(eq(sends.id, sendId)).get();
    if (!send || !sendCanBeAccessed(send)) {
        return sendAccessError(c, 'invalid_grant', 'send_id is invalid.', 'send_id_invalid');
    }

    const sendEmails = (send as any).emails as string | null | undefined;
    if (sendEmails) {
        const requestedEmail = body.email?.trim().toLowerCase();
        if (!requestedEmail) {
            return sendAccessError(c, 'invalid_request', 'email is required.', 'email_required');
        }
        const allowedEmails = sendEmails.split(',').map((email) => email.trim().toLowerCase()).filter(Boolean);
        if (!allowedEmails.includes(requestedEmail)) {
            return sendAccessError(c, 'invalid_request', 'email and otp are required.', 'email_and_otp_required');
        }
        if (!body.otp) {
            await sendSendAccessOtp(db, c.env, requestedEmail, sendId);
            return sendAccessError(c, 'invalid_request', 'email and otp are required.', 'email_and_otp_required');
        }
        try {
            await consumeVerificationToken(db, requestedEmail, `send_access:${sendId}`, body.otp);
        } catch {
            return sendAccessError(c, 'invalid_request', 'email and otp are required.', 'email_and_otp_required');
        }
    } else if (send.password) {
        const passwordHash = body.password_hash_b64;
        if (!passwordHash) {
            return sendAccessError(c, 'invalid_request', 'password_hash_b64 is required.', 'password_hash_b64_required');
        }

        let valid = passwordHash === send.password;
        if (!valid) {
            try {
                valid = await verifySendPassword(passwordHash, send.password);
            } catch {
                valid = false;
            }
        }
        if (!valid) {
            return sendAccessError(c, 'invalid_grant', 'password_hash_b64 is invalid.', 'password_hash_b64_invalid');
        }
    }

    const accessToken = await signJwtClaims({
        sub: sendId,
        send_id: sendId,
        email: sendEmails ? body.email?.trim().toLowerCase() : undefined,
        type: 'Send',
        scope: ['api.send.access'],
        amr: ['send_access'],
    }, c.env.JWT_SECRET, SEND_ACCESS_TOKEN_LIFETIME_SECONDS);
    const expiresAt = Date.now() + SEND_ACCESS_TOKEN_LIFETIME_SECONDS * 1000;

    return c.json({
        access_token: accessToken,
        token: accessToken,
        expires_in: SEND_ACCESS_TOKEN_LIFETIME_SECONDS,
        expiresAt,
        token_type: 'Bearer',
        scope: 'api.send.access',
    });
}

export type DuoProviderContext = {
    providerType: 2 | 6;
    provider: any;
    organizationId: string | null;
};

function parseTwoFactorProviders(value: string | null | undefined): Record<number, any> {
    if (!value) return {};
    try {
        const parsed = JSON.parse(value) as unknown;
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
            ? parsed as Record<number, any>
            : {};
    } catch {
        return {};
    }
}

async function findOrganizationDuoProvider(db: D1Database, userId: string): Promise<DuoProviderContext | null> {
    const rows = await db.prepare(`
        SELECT o.id, o.two_factor_providers
        FROM organizations o
        INNER JOIN organization_users ou ON ou.organization_id = o.id
        WHERE ou.user_id = ? AND ou.status = 2 AND o.enabled = 1 AND o.use_2fa = 1
        ORDER BY o.id
    `).bind(userId).all<{ id: string; two_factor_providers: string | null }>();
    for (const row of rows.results) {
        const provider = parseTwoFactorProviders(row.two_factor_providers)[6];
        if (provider?.enabled === true) {
            return { providerType: 6, provider, organizationId: row.id };
        }
    }
    return null;
}

function requireDuoEncryptionKey(env: Bindings): string {
    const key = env.DUO_CONFIG_ENCRYPTION_KEY?.trim();
    if (!key) throw new Error('Duo configuration encryption key is unavailable.');
    return key;
}

function providerConfigId(provider: any): string | null {
    const value = provider?.metaData?.ConfigId ?? provider?.metaData?.configId;
    return typeof value === 'string' && value.trim() ? value.trim() : null;
}

export async function createDuoTwoFactorParams(
    env: Bindings,
    user: typeof users.$inferSelect,
    context: DuoProviderContext,
    clientName: string | null,
    deeplinkScheme: string | undefined,
    healthCheck: typeof checkDuoHealth = checkDuoHealth,
): Promise<Record<string, string>> {
    const encryptionKey = requireDuoEncryptionKey(env);
    const configId = providerConfigId(context.provider);
    const config = configId
        ? await getDuoConfigById(env.DB, encryptionKey, configId)
        : await getDuoConfigByOwner(env.DB, encryptionKey,
            context.providerType === 2 ? { userId: user.id } : { organizationId: context.organizationId! });
    if (!config || (context.providerType === 2 && config.userId !== user.id) ||
        (context.providerType === 6 && config.organizationId !== context.organizationId)) {
        throw new Error('Duo configuration is unavailable.');
    }
    if (!await healthCheck(config)) throw new Error('Duo health check failed.');
    if (!env.VAULT_BASE_URL) throw new Error('VAULT_BASE_URL is required for Duo.');
    const redirectUri = buildDuoRedirectUri(env.VAULT_BASE_URL, clientName, deeplinkScheme);
    const { state, nonce } = await createDuoLoginState(env.DB, {
        userId: user.id,
        providerType: context.providerType,
        organizationId: context.organizationId,
        configId: config.id,
        configRevision: config.revisionDate,
        redirectUri,
    });
    return {
        Host: config.host,
        AuthUrl: await createDuoAuthorizationUrl(config, {
            username: user.email,
            state,
            nonce,
            redirectUri,
        }),
    };
}

async function verifyDuoTwoFactorToken(
    env: Bindings,
    user: typeof users.$inferSelect,
    context: DuoProviderContext,
    token: string,
): Promise<boolean> {
    const separator = token.indexOf('|');
    if (separator <= 0 || separator !== token.lastIndexOf('|')) return false;
    const code = token.slice(0, separator);
    const state = token.slice(separator + 1);
    if (!code || !state) return false;

    const loginState = await consumeDuoLoginState(env.DB, {
        state,
        userId: user.id,
        providerType: context.providerType,
    });
    if (!loginState || loginState.organizationId !== context.organizationId) return false;
    const config = await getDuoConfigById(env.DB, requireDuoEncryptionKey(env), loginState.configId);
    if (!config || config.revisionDate !== loginState.configRevision ||
        (context.providerType === 2 && config.userId !== user.id) ||
        (context.providerType === 6 && config.organizationId !== context.organizationId)) {
        return false;
    }
    try {
        await exchangeDuoAuthorizationCode(config, {
            code,
            username: user.email,
            nonce: loginState.nonce,
            redirectUri: loginState.redirectUri,
        });
        return true;
    } catch {
        return false;
    }
}

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
async function recordFailedLogin(db: any, userId: string): Promise<void> {
    await db.update(users).set({
        failedLoginCount: sql`${users.failedLoginCount} + 1`,
        lastFailedLoginDate: new Date().toISOString(),
    }).where(eq(users.id, userId));
}

async function handlePasswordGrant(c: any, db: any, body: NewDeviceTokenRequest) {
    if (!body.username || !body.password) {
        throw new BadRequestError('Username and password are required.');
    }

    const email = body.username.toLowerCase().trim();
    const user = await db.select().from(users).where(eq(users.email, email)).get();

    if (!user) {
        // 与存在用户走相同的常量工作量 hash 比较，降低账号枚举时序差异。
        await verifyPassword(body.password, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
        return c.json({
            error: 'invalid_grant',
            error_description: 'invalid_username_or_password',
            ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
        }, 400);
    }

    // 所有密码登录路径（包括 approved AuthRequest）共享账户退避，避免借 AuthRequest 暴力枚举 2FA。
    if (isLoginBackoffActive(user.failedLoginCount, user.lastFailedLoginDate)) {
        return c.json({
            error: 'invalid_grant',
            error_description: 'invalid_username_or_password',
            ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
        }, 400);
    }

    // Auth Request (设备登录) 流程：password 字段实际上是 access code
    let validatedAuthRequest: any = null;
    if (body.authRequest) {
        const authRequest = await db.select().from(authRequests)
            .where(eq(authRequests.id, body.authRequest)).get();

        if (!authRequest) {
            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_username_or_password',
                ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
            }, 400);
        }

        const isExpired = (Date.now() - new Date(authRequest.creationDate).getTime()) > 15 * 60 * 1000;
        const isValid = authRequest.responseDate
            && authRequest.approved === true
            && !isExpired
            && (authRequest.type ?? AuthRequestType.AuthenticateAndUnlock) === AuthRequestType.AuthenticateAndUnlock
            && !authRequest.authenticationDate
            && authRequest.userId === user.id
            && authRequest.accessCode === body.password;

        if (!isValid) {
            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_username_or_password',
                ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
            }, 400);
        }

        validatedAuthRequest = authRequest;
    } else {
        // 普通密码登录流程
        const passwordValid = await verifyPassword(body.password, user.masterPassword || '');
        if (!passwordValid) {
            await recordFailedLogin(db, user.id);

            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_username_or_password',
                ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
            }, 400);
        }
    }

    // ================= 检查二步验证 =================
    const providers = parseTwoFactorProviders(user.twoFactorProviders);
    const premium = await canAccessPremium(c.env.DB, user, c.env.GLOBAL_PREMIUM);
    const duoContexts = new Map<number, DuoProviderContext>();
    if (providers[2]?.enabled === true && premium) {
        duoContexts.set(2, { providerType: 2, provider: providers[2], organizationId: null });
    }
    const organizationDuo = await findOrganizationDuoProvider(c.env.DB, user.id);
    if (organizationDuo) duoContexts.set(6, organizationDuo);

    const enabledProviders = Object.keys(providers)
        .filter((key) => providers[Number(key)]?.enabled === true)
        .map(Number)
        .filter((providerType) => providerType !== 6 && (providerType !== 2 || premium));
    if (organizationDuo && !enabledProviders.includes(6)) enabledProviders.push(6);
    if (enabledProviders.length > 0) {
        // 支持大小写
        const twoFactorProvider = body.TwoFactorProvider ?? body.twoFactorProvider;
        const twoFactorToken = body.TwoFactorToken ?? body.twoFactorToken;

        if (twoFactorProvider === undefined || !twoFactorToken) {
            // 构建每个 provider 的元数据
            const origin = c.req.header('origin') || c.req.header('referer')?.replace(/\/$/, '') || `https://${c.req.header('host') || 'localhost'}`;
            const providers2: Record<string, any> = {};
            try {
                for (const p of enabledProviders) {
                    const duoContext = duoContexts.get(p);
                    providers2[String(p)] = duoContext
                        ? await createDuoTwoFactorParams(
                            c.env,
                            user,
                            duoContext,
                            c.req.header('Bitwarden-Client-Name') ?? body.client_id ?? null,
                            body.deeplinkScheme,
                        )
                        : await buildTwoFactorParams(p, providers[p], origin);
                }
            } catch {
                return c.json({
                    error: 'temporarily_unavailable',
                    error_description: 'Two factor provider is unavailable.',
                    ErrorModel: { Message: 'Two factor provider is unavailable.', Object: 'error' },
                }, 503);
            }

            const twoFactorResponse: Record<string, any> = {
                error: 'invalid_grant',
                error_description: 'Two factor required.',
                TwoFactorProviders: enabledProviders.map(String),
                TwoFactorProviders2: providers2,
            };
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
            await recordFailedLogin(db, user.id);
            return c.json({ error: 'invalid_grant', error_description: 'invalid_two_factor_provider', ErrorModel: { Message: 'Invalid 2FA provider.', Object: 'error' } }, 400);
        } else if (providerType === 2 || providerType === 6) { // Duo / Organization Duo
            const duoContext = duoContexts.get(providerType);
            isValid = !!duoContext && await verifyDuoTwoFactorToken(c.env, user, duoContext, String(token));
        } else if (providerType === 0) { // Authenticator
            const authProvider = providers[0];
            isValid = verifyAuthenticatorCode(authProvider.metaData.Key, token);
        } else if (providerType === 1) { // Email
            const emailProvider = providers[1];
            const metaData = emailProvider?.metaData ?? {};
            const storedToken = String(metaData.Token ?? metaData.token ?? '');
            const expiresRaw = metaData.TokenExpirationDate ?? metaData.tokenExpirationDate;
            isValid = !!storedToken &&
                storedToken === String(token).trim() &&
                !!expiresRaw &&
                Date.now() <= new Date(String(expiresRaw)).getTime();
            if (isValid) {
                delete metaData.Token;
                delete metaData.token;
                delete metaData.TokenExpirationDate;
                delete metaData.tokenExpirationDate;
                providers[1] = { ...emailProvider, metaData };
                await db.update(users).set({
                    twoFactorProviders: JSON.stringify(providers),
                }).where(eq(users.id, user.id));
            }
        } else if (providerType === 3) { // YubiKey
            const parsedOtp = parseYubiKeyOtp(String(token));
            const yubiProvider = providers[3];
            const metaData = yubiProvider?.metaData ?? {};
            const registeredPublicIds = new Set(
                ['Key1', 'Key2', 'Key3', 'Key4', 'Key5']
                    .map((key) => typeof metaData[key] === 'string' ? metaData[key].trim().toLowerCase() : '')
                    .filter(Boolean),
            );
            const config = getYubicoValidationConfig(c.env);
            if (parsedOtp && config && registeredPublicIds.has(parsedOtp.publicId)) {
                const result = await verifyYubicoOtp(parsedOtp.otp, config, fetch);
                isValid = result.valid && result.publicId === parsedOtp.publicId;
            }
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
                    isValid = false;
                } else {
                    // 验证 clientDataJSON
                    const clientDataBytes = base64UrlToBytes(resp.clientDataJSON || resp.clientDataJson);
                    const clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));

                    if (clientData.type !== 'webauthn.get') {
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
                        }
                    }
                }
            } catch {
                isValid = false;
            }
        } else {
            await recordFailedLogin(db, user.id);
            return c.json({ error: 'invalid_grant', error_description: 'unsupported_provider', ErrorModel: { Message: 'Unsupported 2FA provider.', Object: 'error' } }, 400);
        }

        if (!isValid) {
            await recordFailedLogin(db, user.id);
            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_totp_code',
                ErrorModel: { Message: 'Invalid TOTP code.', Object: 'error' }
            }, 400);
        }
    }
    // ================= 2FA 检查完毕 =================
    const requiresNewDeviceVerification = !validatedAuthRequest &&
        enabledProviders.length === 0 &&
        !await isKnownActiveLoginDevice(db, user.id, body);
    if (requiresNewDeviceVerification) {
        const newDeviceOtp = getNewDeviceOtp(body);
        if (!newDeviceOtp) {
            const token = await sendNewDeviceVerification(db, c.env, user.id, user.email);
            return newDeviceVerificationRequired(c, buildDevTokenResponse(c.env, token));
        }

        await consumeVerificationToken(db, user.email, 'new_device', newDeviceOtp, user.id);
    }

    // Auth Request 必须在签发任何 token 前原子消费，防止并发重放。
    if (validatedAuthRequest) {
        const consumed = await db.update(authRequests).set({
            authenticationDate: new Date().toISOString(),
        }).where(and(
            eq(authRequests.id, validatedAuthRequest.id),
            isNull(authRequests.authenticationDate),
        ));
        if (consumed.meta.changes !== 1) {
            return c.json({
                error: 'invalid_grant',
                error_description: 'invalid_username_or_password',
                ErrorModel: { Message: 'Username or password is incorrect. Try again.', Object: 'error' },
            }, 400);
        }
    }

    // 只有密码、二步验证和新设备验证全部成功后才清零失败计数。
    await db.update(users).set({
        failedLoginCount: 0,
        lastFailedLoginDate: null,
    }).where(eq(users.id, user.id));

    // 处理设备。revisionDate 同时作为 devices 响应中的 lastActivityDate。
    const loginDevice = await upsertLoginDevice(db, user.id, body);

    // 签发 access token
    const expiresIn = parseInt(c.env.JWT_EXPIRATION || '3600');
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        email_verified: !!user.emailVerified,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
        sstamp: user.securityStamp,
        device: loginDevice.id,
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
        deviceId: loginDevice.id,
        tokenHash: refreshTokenHash,
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });

    // 记录审计日志
    await logEvent(c.env.DB, 1000, {
        userId: user.id,
        deviceType: loginDevice.type,
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

    await attachMasterPasswordPolicy(db, user.id, response);
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

    if (storedToken.deviceId) {
        const tokenDevice = await db.select({
            id: devices.id,
            active: devices.active,
        }).from(devices)
            .where(and(eq(devices.id, storedToken.deviceId), eq(devices.userId, user.id)))
            .get();
        if (!tokenDevice || !tokenDevice.active) {
            return c.json({ error: 'invalid_grant', error_description: 'Device is inactive.' }, 400);
        }
        await db.update(devices).set({
            revisionDate: new Date().toISOString(),
        }).where(eq(devices.id, tokenDevice.id));
    }

    // 原子消费旧 refresh token；并发 rotation 只能有一个请求成功。
    const consumed = await db.delete(refreshTokens).where(and(
        eq(refreshTokens.id, storedToken.id),
        eq(refreshTokens.tokenHash, tokenHash),
    ));
    if (consumed.meta.changes !== 1) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token.' }, 400);
    }

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

    await attachMasterPasswordPolicy(db, user.id, response);
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
    const loginDevice = await upsertLoginDevice(db, user.id, body);

    const expiresIn = parseInt(c.env.JWT_EXPIRATION || '3600');
    const accessToken = await signJwt({
        sub: user.id,
        email: user.email,
        email_verified: !!user.emailVerified,
        name: user.name || '',
        premium: user.premium || String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true',
        sstamp: user.securityStamp,
        device: loginDevice.id,
        scope: ['api', 'offline_access'],
        amr: ['Application'],
    }, c.env.JWT_SECRET, expiresIn);

    const refreshTokenValue = generateRefreshToken();
    const refreshTokenHash = await sha256(refreshTokenValue);
    const refreshExpiresIn = parseInt(c.env.JWT_REFRESH_EXPIRATION || '2592000');

    await db.insert(refreshTokens).values({
        id: generateUuid(),
        userId: user.id,
        deviceId: loginDevice.id,
        tokenHash: refreshTokenHash,
        expirationDate: new Date(Date.now() + refreshExpiresIn * 1000).toISOString(),
        creationDate: new Date().toISOString(),
    });

    await logEvent(c.env.DB, 1000, {
        userId: user.id,
        deviceType: loginDevice.type,
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

    await attachMasterPasswordPolicy(db, user.id, response);
    return c.json(response);
}

export default identity;
