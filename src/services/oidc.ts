import { createLocalJWKSet, jwtVerify, type JWK, type JWTPayload } from 'jose';

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024;
const RANDOM_TOKEN_BYTES = 32;

export interface OidcDiscoveryDocument {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
    [key: string]: unknown;
}

export interface OidcJwkSet {
    keys: JWK[];
}

export interface OidcFetchOptions {
    fetch?: typeof fetch;
    timeoutMs?: number;
    maxResponseBytes?: number;
}

export interface PkcePair {
    verifier: string;
    challenge: string;
    method: 'S256';
}

export interface OidcTokenResponse {
    id_token: string;
    access_token?: string;
    token_type?: string;
    expires_in?: number;
}

/** Validates an issuer before it is used to construct any outbound request. */
export function validateOidcIssuer(value: string): URL {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new Error('OIDC issuer must be a valid absolute URL.');
    }

    if (url.protocol !== 'https:') {
        throw new Error('OIDC issuer must use HTTPS.');
    }
    if (url.username || url.password) {
        throw new Error('OIDC issuer must not contain credentials.');
    }
    if (url.port && url.port !== '443') {
        throw new Error('OIDC issuer must use the standard HTTPS port.');
    }
    if (url.search || url.hash) {
        throw new Error('OIDC issuer must not contain a query or fragment.');
    }

    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    if (!hostname || hostname === 'localhost' || hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
        throw new Error('OIDC issuer host is not allowed.');
    }
    if (isIpLiteral(hostname)) {
        throw new Error('OIDC issuer must not use an IP literal.');
    }

    url.hostname = hostname;
    url.pathname = url.pathname.replace(/\/+$/, '') || '/';
    return url;
}

/** Validates the public SSO origin used to construct callback URLs. */
export function validateSsoBaseUrl(value: string, allowLocalhost = false): string {
    let url: URL;
    try {
        url = new URL(value);
    } catch {
        throw new Error('SSO_BASE_URL must be a valid absolute URL.');
    }
    const local = ['localhost', '127.0.0.1', '::1'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(allowLocalhost && local && url.protocol === 'http:')) {
        throw new Error('SSO_BASE_URL must use HTTPS.');
    }
    if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
        throw new Error('SSO_BASE_URL must be an origin without credentials, path, query, or fragment.');
    }
    return url.origin;
}

export async function fetchOidcDiscovery(
    issuer: string,
    options: OidcFetchOptions = {},
): Promise<OidcDiscoveryDocument> {
    const validatedIssuer = validateOidcIssuer(issuer);
    const discoveryUrl = new URL(validatedIssuer.toString());
    const issuerPath = discoveryUrl.pathname === '/' ? '' : discoveryUrl.pathname;
    discoveryUrl.pathname = `${issuerPath}/.well-known/openid-configuration`;

    const document = await fetchJson(discoveryUrl, options);
    if (!isRecord(document)) throw new Error('OIDC discovery response must be a JSON object.');

    const expectedIssuer = canonicalIssuer(validatedIssuer);
    if (typeof document.issuer !== 'string' || canonicalIssuer(validateOidcIssuer(document.issuer)) !== expectedIssuer) {
        throw new Error('OIDC discovery issuer does not match the configured issuer.');
    }

    for (const field of ['authorization_endpoint', 'token_endpoint', 'jwks_uri'] as const) {
        const endpoint = document[field];
        if (typeof endpoint !== 'string') throw new Error(`OIDC discovery is missing ${field}.`);
        validateOidcEndpoint(endpoint, field);
    }

    return document as OidcDiscoveryDocument;
}

export async function fetchOidcJwks(
    jwksUri: string,
    options: OidcFetchOptions = {},
): Promise<OidcJwkSet> {
    const url = validateOidcEndpoint(jwksUri, 'jwks_uri');
    const document = await fetchJson(url, options);
    if (!isRecord(document) || !Array.isArray(document.keys) || document.keys.length === 0) {
        throw new Error('OIDC JWKS response must contain a non-empty keys array.');
    }
    if (!document.keys.every(isJsonWebKey)) {
        throw new Error('OIDC JWKS contains an invalid key.');
    }
    return { keys: document.keys };
}

/** Exchanges the provider code without following redirects or buffering an unbounded body. */
export async function exchangeOidcAuthorizationCode(
    tokenEndpoint: string,
    input: { code: string; clientId: string; clientSecret: string; redirectUri: string; codeVerifier: string },
    options: OidcFetchOptions = {},
): Promise<OidcTokenResponse> {
    const url = validateOidcEndpoint(tokenEndpoint, 'token_endpoint');
    const body = new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        client_id: input.clientId,
        client_secret: input.clientSecret,
        redirect_uri: input.redirectUri,
        code_verifier: input.codeVerifier,
    });
    const value = await fetchJson(url, options, {
        method: 'POST',
        headers: {
            Accept: 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: body.toString(),
    });
    if (!isRecord(value) || typeof value.id_token !== 'string' || value.id_token.length === 0) {
        throw new Error('OIDC token response is missing id_token.');
    }
    return value as unknown as OidcTokenResponse;
}

/** Verifies signature, issuer, audience and nonce using the provider's fetched JWKS. */
export async function verifyOidcIdToken(
    idToken: string,
    jwks: OidcJwkSet,
    expected: { issuer: string; audience: string; nonce: string },
): Promise<JWTPayload> {
    const keySet = createLocalJWKSet(jwks);
    const { payload, protectedHeader } = await jwtVerify(idToken, keySet, {
        issuer: expected.issuer,
        audience: expected.audience,
        requiredClaims: ['sub', 'nonce'],
    });
    if (!protectedHeader.alg || protectedHeader.alg === 'none') {
        throw new Error('OIDC ID token uses an invalid signing algorithm.');
    }
    if (typeof payload.nonce !== 'string' || !verifyOpaqueValue(expected.nonce, payload.nonce)) {
        throw new Error('OIDC ID token nonce does not match.');
    }
    return payload;
}

export function generateOidcState(): string {
    return randomBase64Url(RANDOM_TOKEN_BYTES);
}

export function generateOidcNonce(): string {
    return randomBase64Url(RANDOM_TOKEN_BYTES);
}

export async function generatePkcePair(): Promise<PkcePair> {
    const verifier = randomBase64Url(RANDOM_TOKEN_BYTES);
    return {
        verifier,
        challenge: await createPkceChallenge(verifier),
        method: 'S256',
    };
}

export async function createPkceChallenge(verifier: string): Promise<string> {
    if (!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)) {
        throw new Error('PKCE verifier is invalid.');
    }
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
    return base64Url(new Uint8Array(digest));
}

export function verifyOpaqueValue(expected: string, actual: string): boolean {
    const left = new TextEncoder().encode(expected);
    const right = new TextEncoder().encode(actual);
    let difference = left.length ^ right.length;
    const length = Math.max(left.length, right.length);
    for (let index = 0; index < length; index += 1) {
        difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
    }
    return difference === 0;
}

function validateOidcEndpoint(value: string, field: string): URL {
    try {
        return validateOidcIssuer(value);
    } catch {
        throw new Error(`OIDC ${field} is not a safe HTTPS URL.`);
    }
}

async function fetchJson(url: URL, options: OidcFetchOptions, init: RequestInit = {}): Promise<unknown> {
    const fetchImpl = options.fetch ?? fetch;
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const maxBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || !Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
        throw new Error('OIDC fetch limits are invalid.');
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetchImpl(url, {
            ...init,
            headers: init.headers ?? { Accept: 'application/json' },
            redirect: 'manual',
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(`OIDC endpoint returned HTTP ${response.status}.`);
        const contentType = response.headers.get('content-type')?.toLowerCase() ?? '';
        if (!contentType.startsWith('application/json') && !contentType.includes('+json')) {
            throw new Error('OIDC endpoint did not return JSON.');
        }
        const declaredLength = Number(response.headers.get('content-length'));
        if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
            throw new Error('OIDC response exceeds the maximum allowed size.');
        }

        const bytes = await readLimitedBody(response.body, maxBytes);
        try {
            return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
        } catch {
            throw new Error('OIDC endpoint returned invalid JSON.');
        }
    } finally {
        clearTimeout(timeout);
    }
}

async function readLimitedBody(body: ReadableStream<Uint8Array> | null, maxBytes: number): Promise<Uint8Array> {
    if (!body) throw new Error('OIDC endpoint returned an empty response.');
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) throw new Error('OIDC response exceeds the maximum allowed size.');
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return result;
}

function randomBase64Url(byteLength: number): string {
    const bytes = new Uint8Array(byteLength);
    crypto.getRandomValues(bytes);
    return base64Url(bytes);
}

function base64Url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function canonicalIssuer(url: URL): string {
    return url.toString().replace(/\/$/, '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJsonWebKey(value: unknown): value is JWK {
    return isRecord(value) && typeof value.kty === 'string' && value.kty.length > 0;
}

function isIpLiteral(hostname: string): boolean {
    if (hostname.includes(':')) return true;
    const parts = hostname.split('.');
    return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}
