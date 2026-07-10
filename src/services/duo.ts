import { jwtVerify, SignJWT, type JWTPayload } from 'jose';

const DUO_CLIENT_ID_LENGTH = 20;
const DUO_CLIENT_SECRET_LENGTH = 40;
const JWT_LIFETIME_SECONDS = 5 * 60;
const JWT_CLOCK_TOLERANCE_SECONDS = 60;
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 32 * 1024;
const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

export type DuoConfig = {
    clientId: string;
    clientSecret: string;
    host: string;
};

export type DuoFetch = (
    input: string | URL | Request,
    init?: RequestInit,
) => Promise<Response>;

export type DuoRequestOptions = {
    fetch?: DuoFetch;
    timeoutMs?: number;
    maxResponseBytes?: number;
    now?: Date;
};

export type DuoAuthenticationResult = JWTPayload & {
    preferred_username: string;
    nonce: string;
    auth_result: {
        result: string;
        status?: string;
        status_msg?: string;
    };
};

function bytesToBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function generateDuoOpaqueValue(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return bytesToBase64Url(bytes);
}

export function normalizeDuoHost(value: string): string {
    const host = value.trim().toLowerCase();
    if (host.length > 253 || !/^api-[a-z0-9]+\.(?:duosecurity|duofederal)\.com$/.test(host)) {
        throw new Error('Duo API host is invalid.');
    }
    return host;
}

export function validateDuoConfig(config: DuoConfig): DuoConfig {
    if (config.clientId.length !== DUO_CLIENT_ID_LENGTH || !/^[A-Za-z0-9]+$/.test(config.clientId)) {
        throw new Error('Duo Client ID must be exactly 20 alphanumeric characters.');
    }
    if (config.clientSecret.length !== DUO_CLIENT_SECRET_LENGTH || /[\u0000-\u001f\u007f]/.test(config.clientSecret)) {
        throw new Error('Duo Client Secret must be exactly 40 characters.');
    }
    return { ...config, host: normalizeDuoHost(config.host) };
}

export function buildDuoRedirectUri(
    vaultBaseUrl: string,
    clientNameValue?: string | null,
    deeplinkSchemeValue?: string | null,
): string {
    const base = new URL(vaultBaseUrl);
    if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash) {
        throw new Error('VAULT_BASE_URL must be a clean HTTPS URL.');
    }

    // Directory Connector 不是上游 ClientType，必须像官方服务一样回退到 Web。
    const supportedClients = new Set(['web', 'browser', 'desktop', 'mobile', 'cli']);
    const candidate = clientNameValue?.trim().toLowerCase() ?? '';
    const client = supportedClients.has(candidate) ? candidate : 'web';
    const redirect = new URL(`${base.pathname.replace(/\/+$/, '')}/duo-redirect-connector.html`, base.origin);
    redirect.searchParams.set('client', client);

    if (client === 'desktop') {
        redirect.searchParams.set('deeplinkScheme', 'bitwarden');
    } else if (client === 'mobile') {
        const scheme = deeplinkSchemeValue?.trim().toLowerCase();
        redirect.searchParams.set('deeplinkScheme', scheme === 'https' ? 'https' : 'bitwarden');
    }
    return redirect.toString();
}

function endpoint(config: DuoConfig, path: string): string {
    return `https://${normalizeDuoHost(config.host)}${path}`;
}

async function createClientAssertion(config: DuoConfig, audience: string, now: Date): Promise<string> {
    const nowSeconds = Math.floor(now.getTime() / 1000);
    return new SignJWT({})
        .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
        .setIssuer(config.clientId)
        .setSubject(config.clientId)
        .setAudience(audience)
        .setJti(generateDuoOpaqueValue())
        .setIssuedAt(nowSeconds)
        .setExpirationTime(nowSeconds + JWT_LIFETIME_SECONDS)
        .sign(new TextEncoder().encode(config.clientSecret));
}

async function readLimitedJson(response: Response, maxBytes: number): Promise<unknown> {
    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
        throw new Error('Duo response exceeds the allowed size.');
    }
    if (!response.body) throw new Error('Duo returned an empty response.');

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > maxBytes) {
                await reader.cancel();
                throw new Error('Duo response exceeds the allowed size.');
            }
            chunks.push(value);
        }
    } finally {
        reader.releaseLock();
    }

    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    try {
        return JSON.parse(new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes));
    } catch {
        throw new Error('Duo returned malformed JSON.');
    }
}

async function postDuoForm(
    url: string,
    form: URLSearchParams,
    options: DuoRequestOptions,
): Promise<unknown> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    try {
        const response = await (options.fetch ?? fetch)(url, {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: form.toString(),
            redirect: 'manual',
            signal: controller.signal,
        });
        if (!response.ok) throw new Error(`Duo request failed with HTTP ${response.status}.`);
        return await readLimitedJson(response, options.maxResponseBytes ?? MAX_RESPONSE_BYTES);
    } catch (error) {
        if (controller.signal.aborted) throw new Error('Duo request timed out.');
        if (error instanceof Error &&
            (error.message.startsWith('Duo request failed') ||
             error.message.startsWith('Duo response') ||
             error.message.startsWith('Duo returned'))) {
            throw error;
        }
        throw new Error('Unable to connect to Duo.', { cause: error });
    } finally {
        clearTimeout(timeout);
    }
}

export async function checkDuoHealth(configValue: DuoConfig, options: DuoRequestOptions = {}): Promise<boolean> {
    const config = validateDuoConfig(configValue);
    const healthEndpoint = endpoint(config, '/oauth/v1/health_check');
    const assertion = await createClientAssertion(config, healthEndpoint, options.now ?? new Date());
    const result = await postDuoForm(healthEndpoint, new URLSearchParams({
        client_id: config.clientId,
        client_assertion: assertion,
    }), options);
    return typeof result === 'object' && result !== null && (result as { stat?: unknown }).stat === 'OK';
}

export async function createDuoAuthorizationUrl(
    configValue: DuoConfig,
    input: { username: string; state: string; nonce: string; redirectUri: string },
    now: Date = new Date(),
): Promise<string> {
    const config = validateDuoConfig(configValue);
    if (!input.username.trim()) throw new Error('Duo username is required.');
    if (!/^[A-Za-z0-9_-]{22,1024}$/.test(input.state)) throw new Error('Duo state is invalid.');
    if (!/^[A-Za-z0-9_-]{16,1024}$/.test(input.nonce)) throw new Error('Duo nonce is invalid.');
    const redirectUri = new URL(input.redirectUri);
    if (redirectUri.protocol !== 'https:' || redirectUri.username || redirectUri.password || redirectUri.hash) {
        throw new Error('Duo redirect URI is invalid.');
    }

    const nowSeconds = Math.floor(now.getTime() / 1000);
    const authorizeEndpoint = endpoint(config, '/oauth/v1/authorize');
    const requestJwt = await new SignJWT({
        response_type: 'code',
        scope: 'openid',
        client_id: config.clientId,
        redirect_uri: redirectUri.toString(),
        state: input.state,
        nonce: input.nonce,
        duo_uname: input.username,
    })
        .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
        .setIssuer(config.clientId)
        .setAudience(`https://${config.host}`)
        .setIssuedAt(nowSeconds)
        .setExpirationTime(nowSeconds + JWT_LIFETIME_SECONDS)
        .sign(new TextEncoder().encode(config.clientSecret));

    const url = new URL(authorizeEndpoint);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', config.clientId);
    url.searchParams.set('request', requestJwt);
    url.searchParams.set('redirect_uri', redirectUri.toString());
    url.searchParams.set('scope', 'openid');
    return url.toString();
}

function constantTimeEqual(left: string, right: string): boolean {
    const leftBytes = new TextEncoder().encode(left);
    const rightBytes = new TextEncoder().encode(right);
    const length = Math.max(leftBytes.length, rightBytes.length);
    let difference = leftBytes.length ^ rightBytes.length;
    for (let index = 0; index < length; index += 1) {
        difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
    }
    return difference === 0;
}

export async function exchangeDuoAuthorizationCode(
    configValue: DuoConfig,
    input: { code: string; username: string; nonce: string; redirectUri: string },
    options: DuoRequestOptions = {},
): Promise<DuoAuthenticationResult> {
    const config = validateDuoConfig(configValue);
    if (!input.code || input.code.length > 4096 || !input.username.trim()) {
        throw new Error('Duo authorization result is invalid.');
    }
    const tokenEndpoint = endpoint(config, '/oauth/v1/token');
    const assertion = await createClientAssertion(config, tokenEndpoint, options.now ?? new Date());
    const raw = await postDuoForm(tokenEndpoint, new URLSearchParams({
        grant_type: 'authorization_code',
        code: input.code,
        redirect_uri: input.redirectUri,
        client_id: config.clientId,
        client_assertion_type: CLIENT_ASSERTION_TYPE,
        client_assertion: assertion,
    }), options);
    if (!raw || typeof raw !== 'object') throw new Error('Duo token response is invalid.');
    const response = raw as Record<string, unknown>;
    if (typeof response.id_token !== 'string' || typeof response.access_token !== 'string' ||
        response.token_type !== 'Bearer' || !Object.hasOwn(response, 'expires_in')) {
        throw new Error('Duo token response is invalid.');
    }

    const { payload } = await jwtVerify(response.id_token, new TextEncoder().encode(config.clientSecret), {
        algorithms: ['HS512'],
        issuer: tokenEndpoint,
        audience: config.clientId,
        clockTolerance: JWT_CLOCK_TOLERANCE_SECONDS,
        requiredClaims: ['exp', 'iat', 'iss', 'aud', 'preferred_username', 'nonce', 'auth_result'],
    });
    const preferredUsername = payload.preferred_username;
    const nonce = payload.nonce;
    const authResult = payload.auth_result;
    if (typeof preferredUsername !== 'string' ||
        preferredUsername.toLowerCase() !== input.username.toLowerCase() ||
        typeof nonce !== 'string' || !constantTimeEqual(nonce, input.nonce) ||
        !authResult || typeof authResult !== 'object' ||
        (authResult as { result?: unknown }).result !== 'allow') {
        throw new Error('Duo authentication result is invalid.');
    }

    // Access only after jwtVerify so malformed payloads never influence authentication.
    return {
        ...payload,
        preferred_username: preferredUsername,
        nonce,
        auth_result: authResult as DuoAuthenticationResult['auth_result'],
    };
}
