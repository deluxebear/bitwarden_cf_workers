/** Web Push Protocol (RFC 8291/8292) implementation using Workers Web Crypto. */

const encoder = new TextEncoder();
const MAX_PAYLOAD_BYTES = 3072;
const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_ATTEMPTS = 2;

export type WebPushSubscription = {
    endpoint: string;
    p256dh: string;
    auth: string;
};

export type WebPushConfig = {
    publicKey: string;
    privateKey: string;
    subject: string;
};

export type WebPushDeliveryResult = {
    status: 'delivered' | 'expired' | 'retryable' | 'failed' | 'duplicate';
    statusCode?: number;
    attempts: number;
    retryAfterSeconds?: number;
};

export type WebPushIdempotencyStore = {
    has(key: string): Promise<boolean>;
    put(key: string, ttlSeconds: number): Promise<void>;
};

export function createCacheIdempotencyStore(cache: Cache): WebPushIdempotencyStore {
    const requestFor = async (key: string) => {
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(key)));
        return new Request(`https://web-push-idempotency.invalid/${encodeBase64Url(digest)}`);
    };
    return {
        has: async (key) => !!await cache.match(await requestFor(key)),
        put: async (key, ttlSeconds) => {
            await cache.put(await requestFor(key), new Response(null, {
                headers: { 'Cache-Control': `public, max-age=${ttlSeconds}` },
            }));
        },
    };
}

type WebPushOptions = {
    fetch?: typeof fetch;
    now?: Date;
    timeoutMs?: number;
    maxAttempts?: number;
    idempotency?: WebPushIdempotencyStore;
};

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> {
    if (!/^[A-Za-z0-9_-]+={0,2}$/.test(value)) throw new Error('Invalid Web Push key encoding.');
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    const raw = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
    return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function encodeBase64Url(value: Uint8Array): string {
    let raw = '';
    for (const byte of value) raw += String.fromCharCode(byte);
    return btoa(raw).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
    const length = parts.reduce((total, part) => total + part.byteLength, 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.byteLength;
    }
    return result;
}

async function hmac(key: Uint8Array, value: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, value));
}

async function hkdfExtract(salt: Uint8Array, input: Uint8Array): Promise<Uint8Array<ArrayBuffer>> {
    return hmac(salt, input);
}

async function hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array<ArrayBuffer>> {
    const output = new Uint8Array(length);
    let previous = new Uint8Array(0);
    let offset = 0;
    for (let counter = 1; offset < length; counter++) {
        previous = await hmac(prk, concat(previous, info, Uint8Array.of(counter)));
        const chunk = previous.slice(0, Math.min(previous.length, length - offset));
        output.set(chunk, offset);
        offset += chunk.length;
    }
    return output;
}

export function validateWebPushEndpoint(endpoint: string): URL {
    const url = new URL(endpoint);
    const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
    const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const ipLiteral = ipv4 || hostname.includes(':');
    if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
        (url.port && url.port !== '443') || !hostname || ipLiteral || hostname === 'localhost' ||
        hostname.endsWith('.localhost') || hostname.endsWith('.local')) {
        throw new Error('Web Push endpoint must be an HTTPS URL without credentials.');
    }
    return url;
}

function parseRetryAfter(value: string | null, now: Date): number | undefined {
    if (!value) return undefined;
    if (/^\d+$/.test(value)) return Math.min(Number(value), 3600);
    const retryAt = Date.parse(value);
    if (!Number.isFinite(retryAt)) return undefined;
    return Math.min(3600, Math.max(0, Math.ceil((retryAt - now.getTime()) / 1000)));
}

async function createVapidJwt(endpoint: URL, config: WebPushConfig, now: Date): Promise<string> {
    const publicKey = decodeBase64Url(config.publicKey);
    const privateKey = decodeBase64Url(config.privateKey);
    if (publicKey.length !== 65 || publicKey[0] !== 4 || privateKey.length !== 32) {
        throw new Error('VAPID keys must be an uncompressed P-256 public key and a 32-byte private key.');
    }
    if (!config.subject.startsWith('mailto:') && !config.subject.startsWith('https://')) {
        throw new Error('VAPID subject must be a mailto: or HTTPS URI.');
    }

    const key = await crypto.subtle.importKey('jwk', {
        kty: 'EC', crv: 'P-256',
        x: encodeBase64Url(publicKey.slice(1, 33)),
        y: encodeBase64Url(publicKey.slice(33, 65)),
        d: encodeBase64Url(privateKey),
        ext: true,
    }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const issuedAt = Math.floor(now.getTime() / 1000);
    const header = encodeBase64Url(encoder.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
    const claims = encodeBase64Url(encoder.encode(JSON.stringify({
        aud: endpoint.origin,
        exp: issuedAt + 12 * 60 * 60,
        sub: config.subject,
    })));
    const unsigned = `${header}.${claims}`;
    const signature = new Uint8Array(await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, key, encoder.encode(unsigned),
    ));
    return `${unsigned}.${encodeBase64Url(signature)}`;
}

export async function encryptWebPushPayload(
    subscription: WebPushSubscription,
    payload: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
    if (payload.byteLength > MAX_PAYLOAD_BYTES) throw new Error('Web Push payload exceeds 3072 bytes.');
    const userPublic = decodeBase64Url(subscription.p256dh);
    const authSecret = decodeBase64Url(subscription.auth);
    if (userPublic.length !== 65 || userPublic[0] !== 4 || authSecret.length !== 16) {
        throw new Error('Invalid Web Push subscription keys.');
    }

    const userKey = await crypto.subtle.importKey(
        'raw', userPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, [],
    );
    const serverKeys = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    if (!('publicKey' in serverKeys)) throw new Error('Failed to generate a Web Push ECDH key pair.');
    const exportedServerPublic = await crypto.subtle.exportKey('raw', serverKeys.publicKey);
    if (!(exportedServerPublic instanceof ArrayBuffer)) throw new Error('Failed to export Web Push public key.');
    const serverPublic = new Uint8Array(exportedServerPublic);
    const deriveAlgorithm: SubtleCryptoDeriveKeyAlgorithm = { name: 'ECDH' };
    // The Workers type generator exposes this member as `$public`, while the
    // standards-compatible Web Crypto runtime property is `public`.
    Reflect.set(deriveAlgorithm, 'public', userKey);
    const sharedSecret = new Uint8Array(await crypto.subtle.deriveBits(
        deriveAlgorithm, serverKeys.privateKey, 256,
    ));

    const keyInfo = concat(encoder.encode('WebPush: info\0'), userPublic, serverPublic);
    const authPrk = await hkdfExtract(authSecret, sharedSecret);
    const inputKeyMaterial = await hkdfExpand(authPrk, keyInfo, 32);
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const contentPrk = await hkdfExtract(salt, inputKeyMaterial);
    const contentKey = await hkdfExpand(contentPrk, encoder.encode('Content-Encoding: aes128gcm\0'), 16);
    const nonce = await hkdfExpand(contentPrk, encoder.encode('Content-Encoding: nonce\0'), 12);
    const aesKey = await crypto.subtle.importKey('raw', contentKey, 'AES-GCM', false, ['encrypt']);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce }, aesKey, concat(payload, Uint8Array.of(2)),
    ));

    const recordSize = new Uint8Array(4);
    new DataView(recordSize.buffer).setUint32(0, 4096);
    return concat(salt, recordSize, Uint8Array.of(serverPublic.length), serverPublic, ciphertext);
}

export async function sendWebPush(
    subscription: WebPushSubscription,
    payload: unknown,
    eventId: string,
    config: WebPushConfig,
    options: WebPushOptions = {},
): Promise<WebPushDeliveryResult> {
    const endpoint = validateWebPushEndpoint(subscription.endpoint);
    const idempotencyKey = `${eventId}:${subscription.endpoint}`;
    if (options.idempotency && await options.idempotency.has(idempotencyKey)) {
        return { status: 'duplicate', attempts: 0 };
    }

    const encodedPayload = encoder.encode(JSON.stringify(payload));
    const encrypted = await encryptWebPushPayload(subscription, encodedPayload);
    const jwt = await createVapidJwt(endpoint, config, options.now ?? new Date());
    const requestFetch = options.fetch ?? fetch;
    const maxAttempts = Math.max(1, Math.min(options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS, 3));
    let lastStatus: number | undefined;

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
        try {
            const response = await requestFetch(endpoint, {
                method: 'POST',
                redirect: 'manual',
                signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_TIMEOUT_MS),
                headers: {
                    Authorization: `vapid t=${jwt}, k=${config.publicKey}`,
                    'Content-Encoding': 'aes128gcm',
                    'Content-Type': 'application/octet-stream',
                    TTL: '60',
                    Urgency: 'normal',
                },
                body: encrypted,
            });
            lastStatus = response.status;
            if (response.status >= 200 && response.status < 300) {
                await options.idempotency?.put(idempotencyKey, 24 * 60 * 60);
                return { status: 'delivered', statusCode: response.status, attempts: attempt };
            }
            if (response.status === 404 || response.status === 410) {
                await options.idempotency?.put(idempotencyKey, 24 * 60 * 60);
                return { status: 'expired', statusCode: response.status, attempts: attempt };
            }
            if (response.status !== 429 && response.status < 500) {
                return { status: 'failed', statusCode: response.status, attempts: attempt };
            }
            const retryAfterSeconds = parseRetryAfter(response.headers.get('Retry-After'), options.now ?? new Date());
            if (attempt === maxAttempts) {
                return { status: 'retryable', statusCode: response.status, attempts: attempt, retryAfterSeconds };
            }
        } catch {
            // Timeouts and network errors are retryable, within the bounded attempt budget.
        }
    }
    return { status: 'retryable', statusCode: lastStatus, attempts: maxAttempts };
}
