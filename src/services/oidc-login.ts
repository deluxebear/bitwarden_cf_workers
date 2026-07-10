import { sha256 } from './crypto';
import { createPkceChallenge, generateOidcState } from './oidc';
import { jwtVerify, SignJWT } from 'jose';

const LOGIN_STATE_LIFETIME_MS = 10 * 60 * 1000;
const AUTHORIZATION_CODE_LIFETIME_MS = 2 * 60 * 1000;
const PREVALIDATION_LIFETIME_SECONDS = 5 * 60;
const MAX_ACTIVE_LOGIN_STATES_PER_ORGANIZATION = 100;

export interface OidcLoginState {
    organizationId: string;
    nonce: string;
    providerPkceVerifier: string;
    clientId: string;
    clientRedirectUri: string;
    clientState: string | null;
    clientCodeChallenge: string;
}

export interface OidcAuthorizationCode {
    organizationId: string;
    userId: string;
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
}

export async function createSsoPrevalidationToken(organizationId: string, secret: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ organizationId, purpose: 'sso_prevalidate' })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuer('bitwarden-workers')
        .setIssuedAt(now)
        .setNotBefore(now)
        .setExpirationTime(now + PREVALIDATION_LIFETIME_SECONDS)
        .sign(new TextEncoder().encode(secret));
}

export async function verifySsoPrevalidationToken(token: string, secret: string): Promise<string | null> {
    try {
        const { payload } = await jwtVerify(token, new TextEncoder().encode(secret), {
            issuer: 'bitwarden-workers',
            algorithms: ['HS256'],
            requiredClaims: ['organizationId', 'purpose'],
        });
        return payload.purpose === 'sso_prevalidate' && typeof payload.organizationId === 'string'
            ? payload.organizationId
            : null;
    } catch {
        return null;
    }
}

type LoginStateRow = {
    organization_id: string;
    nonce: string;
    provider_pkce_verifier: string;
    client_id: string;
    client_redirect_uri: string;
    client_state: string | null;
    client_code_challenge: string;
};

type AuthorizationCodeRow = {
    organization_id: string;
    user_id: string;
    client_id: string;
    redirect_uri: string;
    code_challenge: string;
};

export async function createOidcLoginState(db: D1Database, value: OidcLoginState): Promise<string> {
    const state = generateOidcState();
    const now = new Date();
    const [, inserted] = await db.batch([
        db.prepare('DELETE FROM oidc_login_states WHERE expiration_date <= ?').bind(now.toISOString()),
        db.prepare(`
        INSERT INTO oidc_login_states
            (state_hash, organization_id, nonce, provider_pkce_verifier, client_id,
             client_redirect_uri, client_state, client_code_challenge, creation_date, expiration_date)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE (SELECT COUNT(*) FROM oidc_login_states
               WHERE organization_id = ? AND consumed_date IS NULL AND expiration_date > ?) < ?
    `).bind(
        await sha256(state),
        value.organizationId,
        value.nonce,
        value.providerPkceVerifier,
        value.clientId,
        value.clientRedirectUri,
        value.clientState,
        value.clientCodeChallenge,
        now.toISOString(),
        new Date(now.getTime() + LOGIN_STATE_LIFETIME_MS).toISOString(),
        value.organizationId,
        now.toISOString(),
        MAX_ACTIVE_LOGIN_STATES_PER_ORGANIZATION,
    ),
    ]);
    if (inserted.meta.changes !== 1) throw new Error('Too many active OIDC login requests.');
    return state;
}

export async function consumeOidcLoginState(db: D1Database, state: string): Promise<OidcLoginState | null> {
    const now = new Date().toISOString();
    const row = await db.prepare(`
        UPDATE oidc_login_states
        SET consumed_date = ?
        WHERE state_hash = ? AND consumed_date IS NULL AND expiration_date > ?
        RETURNING organization_id, nonce, provider_pkce_verifier, client_id,
                  client_redirect_uri, client_state, client_code_challenge
    `).bind(now, await sha256(state), now).first<LoginStateRow>();
    return row ? {
        organizationId: row.organization_id,
        nonce: row.nonce,
        providerPkceVerifier: row.provider_pkce_verifier,
        clientId: row.client_id,
        clientRedirectUri: row.client_redirect_uri,
        clientState: row.client_state,
        clientCodeChallenge: row.client_code_challenge,
    } : null;
}

export async function createOidcAuthorizationCode(
    db: D1Database,
    value: OidcAuthorizationCode,
): Promise<string> {
    const code = generateOidcState();
    const now = new Date();
    const [, inserted] = await db.batch([
        db.prepare('DELETE FROM oidc_authorization_codes WHERE expiration_date <= ?').bind(now.toISOString()),
        db.prepare(`
        INSERT INTO oidc_authorization_codes
            (code_hash, organization_id, user_id, client_id, redirect_uri, code_challenge,
             creation_date, expiration_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
        await sha256(code),
        value.organizationId,
        value.userId,
        value.clientId,
        value.redirectUri,
        value.codeChallenge,
        now.toISOString(),
        new Date(now.getTime() + AUTHORIZATION_CODE_LIFETIME_MS).toISOString(),
    ),
    ]);
    if (inserted.meta.changes !== 1) throw new Error('Unable to persist OIDC authorization code.');
    return code;
}

export async function consumeOidcAuthorizationCode(
    db: D1Database,
    input: { code: string; clientId: string; redirectUri: string; codeVerifier: string },
): Promise<OidcAuthorizationCode | null> {
    let challenge: string;
    try {
        challenge = await createPkceChallenge(input.codeVerifier);
    } catch {
        return null;
    }
    const now = new Date().toISOString();
    const row = await db.prepare(`
        UPDATE oidc_authorization_codes
        SET consumed_date = ?
        WHERE code_hash = ? AND consumed_date IS NULL AND expiration_date > ?
          AND client_id = ? AND redirect_uri = ? AND code_challenge = ?
        RETURNING organization_id, user_id, client_id, redirect_uri, code_challenge
    `).bind(
        now,
        await sha256(input.code),
        now,
        input.clientId,
        input.redirectUri,
        challenge,
    ).first<AuthorizationCodeRow>();
    return row ? {
        organizationId: row.organization_id,
        userId: row.user_id,
        clientId: row.client_id,
        redirectUri: row.redirect_uri,
        codeChallenge: row.code_challenge,
    } : null;
}

export function validateClientRedirectUri(value: string, clientId: string, vaultBaseUrl?: string): string {
    if (value.length > 2048 || /[\u0000-\u001f]/.test(value)) throw new Error('Invalid redirect_uri.');
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new Error('Invalid redirect_uri.');
    }
    if (url.username || url.password || url.hash) throw new Error('Invalid redirect_uri.');
    const normalized = url.toString();
    const localPort = url.protocol === 'http:' && url.hostname === 'localhost'
        && Number(url.port) >= 8065 && Number(url.port) <= 8070
        && url.pathname === '/' && !url.search;

    if (clientId === 'web' || clientId === 'browser') {
        if (!vaultBaseUrl) throw new Error('VAULT_BASE_URL is required for browser SSO clients.');
        const vault = new URL(vaultBaseUrl);
        if (vault.username || vault.password || vault.search || vault.hash) throw new Error('Invalid VAULT_BASE_URL.');
        const expected = new URL('/sso-connector.html', `${vault.origin}/`).toString();
        if (normalized !== expected) throw new Error('redirect_uri is not registered for this client.');
        return normalized;
    }

    const nativeCallbacks: Record<string, string> = {
        desktop: 'bitwarden://sso-callback',
        connector: 'bwdc://sso-callback',
    };
    if (nativeCallbacks[clientId] && normalized === new URL(nativeCallbacks[clientId]).toString()) return normalized;
    if (clientId === 'mobile') {
        const mobileCallbacks = new Set([
            'bitwarden://sso-callback',
            'https://bitwarden.pw/sso-callback',
            'https://bitwarden.com/sso-callback',
            'https://bitwarden.eu/sso-callback',
            'https://bitwarden-gov.com/sso-callback',
        ]);
        if (mobileCallbacks.has(normalized)) return normalized;
    }
    if (localPort && ['desktop', 'connector', 'cli'].includes(clientId)) return normalized;
    throw new Error('redirect_uri is not registered for this client.');
}

export function readMappedStringClaim(
    claims: Record<string, unknown>,
    mapping: Record<string, string[]>,
    target: string,
    defaults: string[],
): string | null {
    for (const name of mapping[target] ?? defaults) {
        const value = claims[name];
        if (typeof value === 'string' && value.trim()) return value.trim();
    }
    return null;
}

export function hasVerifiedOidcEmailClaim(
    claims: Record<string, unknown>,
    mapping: Record<string, string[]>,
): boolean {
    return (mapping.email_verified ?? ['email_verified']).some((name) => claims[name] === true);
}
