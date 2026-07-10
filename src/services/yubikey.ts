const MODHEX_PATTERN = /^[cbdefghijklnrtuv]+$/;
const DEFAULT_VALIDATION_URL = 'https://api.yubico.com/wsapi/2.0/verify';
const DEFAULT_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 16 * 1024;

export type YubiKeyOtp = {
    otp: string;
    /** Bitwarden upstream stores and matches the first 12 modhex characters. */
    publicId: string;
};

export type YubicoValidationConfig = {
    clientId: string;
    /** Base64 encoded Yubico API secret, used for request and response HMAC-SHA1. */
    secret: string;
    validationUrl?: string;
    timeoutMs?: number;
};

export type YubicoEnvironment = {
    YUBICO_CLIENT_ID?: string;
    YUBICO_SECRET?: string;
    YUBICO_VALIDATION_URL?: string;
};

export type YubicoValidationRequest = {
    url: string;
    nonce: string;
};

export type YubicoResultKind =
    | 'ok'
    | 'invalid_otp'
    | 'replayed_otp'
    | 'replayed_request'
    | 'provider_rejected'
    | 'invalid_response'
    | 'configuration_error'
    | 'timeout'
    | 'network_error';

export type YubicoValidationResult = {
    valid: boolean;
    kind: YubicoResultKind;
    status?: string;
    publicId?: string;
    replayed: boolean;
    sessionCounter?: number;
    sessionUse?: number;
    tokenTimestamp?: number;
};

export type YubicoFetch = (
    input: string | URL | Request,
    init?: RequestInit,
) => Promise<Response>;

export function getYubicoValidationConfig(env: YubicoEnvironment): YubicoValidationConfig | null {
    const clientId = env.YUBICO_CLIENT_ID?.trim();
    const secret = env.YUBICO_SECRET?.trim();
    const validationUrl = env.YUBICO_VALIDATION_URL?.trim();
    if (!clientId || !/^\d+$/.test(clientId) || !secret) return null;

    return {
        clientId,
        secret,
        ...(validationUrl ? { validationUrl } : {}),
    };
}

export function parseYubiKeyOtp(value: string): YubiKeyOtp | null {
    const otp = value.trim().toLowerCase();
    // 与 Bitwarden 上游 YubicoOtpTokenProvider 的长度边界保持一致。
    if (otp.length < 32 || otp.length > 48 || !MODHEX_PATTERN.test(otp)) return null;

    return { otp, publicId: otp.slice(0, 12) };
}

export function isYubiKeyPublicId(value: string): boolean {
    return value.length === 12 && MODHEX_PATTERN.test(value.toLowerCase());
}

function makeNonce(): string {
    const bytes = new Uint8Array(20);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base64ToBytes(value: string): Uint8Array | null {
    try {
        const decoded = atob(value.trim());
        return Uint8Array.from(decoded, (char) => char.charCodeAt(0));
    } catch {
        return null;
    }
}

function bytesToBase64(value: ArrayBuffer): string {
    const bytes = new Uint8Array(value);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

function canonicalize(fields: Readonly<Record<string, string>>): string {
    return Object.keys(fields)
        .filter((key) => key !== 'h')
        .sort()
        .map((key) => `${key}=${fields[key]}`)
        .join('&');
}

async function signFields(fields: Readonly<Record<string, string>>, secret: string): Promise<string | null> {
    const keyBytes = base64ToBytes(secret);
    if (!keyBytes || keyBytes.length === 0) return null;

    try {
        const key = await crypto.subtle.importKey(
            'raw',
            keyBytes,
            { name: 'HMAC', hash: 'SHA-1' },
            false,
            ['sign'],
        );
        const signature = await crypto.subtle.sign(
            'HMAC',
            key,
            new TextEncoder().encode(canonicalize(fields)),
        );
        return bytesToBase64(signature);
    } catch {
        return null;
    }
}

function constantTimeEqual(left: string, right: string): boolean {
    const leftBytes = new TextEncoder().encode(left);
    const rightBytes = new TextEncoder().encode(right);
    const length = Math.max(leftBytes.length, rightBytes.length);
    let difference = leftBytes.length ^ rightBytes.length;
    for (let i = 0; i < length; i += 1) {
        difference |= (leftBytes[i] ?? 0) ^ (rightBytes[i] ?? 0);
    }
    return difference === 0;
}

function validateValidationUrl(value: string): URL | null {
    try {
        const url = new URL(value);
        const hostname = url.hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
        const ipv4 = hostname.split('.');
        const isIpLiteral = hostname.includes(':') ||
            (ipv4.length === 4 && ipv4.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255));
        if (url.protocol !== 'https:' || url.username || url.password || url.hash ||
            !hostname || hostname === 'localhost' || hostname.endsWith('.localhost') ||
            hostname.endsWith('.local') || isIpLiteral) {
            return null;
        }
        return url;
    } catch {
        return null;
    }
}

async function readLimitedText(response: Response): Promise<string | null> {
    const declaredLength = Number(response.headers.get('content-length'));
    if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) return null;
    if (!response.body) return null;

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            total += value.byteLength;
            if (total > MAX_RESPONSE_BYTES) {
                await reader.cancel();
                return null;
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
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes);
    } catch {
        return null;
    }
}

export async function buildYubicoValidationRequest(
    otp: string,
    config: YubicoValidationConfig,
    nonce: string = makeNonce(),
): Promise<YubicoValidationRequest | null> {
    const parsedOtp = parseYubiKeyOtp(otp);
    if (!parsedOtp || !/^\d+$/.test(config.clientId) || !/^[A-Za-z0-9]{16,40}$/.test(nonce)) return null;

    const url = validateValidationUrl(config.validationUrl ?? DEFAULT_VALIDATION_URL);
    if (!url) return null;

    const fields: Record<string, string> = {
        id: config.clientId,
        nonce,
        otp: parsedOtp.otp,
    };
    const signature = await signFields(fields, config.secret);
    if (!signature) return null;

    for (const [key, value] of Object.entries(fields)) url.searchParams.set(key, value);
    url.searchParams.set('h', signature);
    return { url: url.toString(), nonce };
}

export function parseYubicoResponse(body: string): Record<string, string> | null {
    if (!body || body.length > MAX_RESPONSE_BYTES) return null;
    const fields: Record<string, string> = {};

    for (const rawLine of body.split(/\r?\n/)) {
        if (!rawLine) continue;
        const separator = rawLine.indexOf('=');
        if (separator <= 0) return null;
        const key = rawLine.slice(0, separator);
        if (Object.hasOwn(fields, key)) return null;
        fields[key] = rawLine.slice(separator + 1);
    }

    return fields.status && fields.h ? fields : null;
}

function optionalInteger(value: string | undefined): number | undefined {
    if (value === undefined || !/^\d+$/.test(value)) return undefined;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function classifyStatus(status: string): YubicoResultKind {
    if (status === 'OK') return 'ok';
    if (status === 'BAD_OTP') return 'invalid_otp';
    if (status === 'REPLAYED_OTP') return 'replayed_otp';
    if (status === 'REPLAYED_REQUEST') return 'replayed_request';
    return 'provider_rejected';
}

function failure(kind: YubicoResultKind, status?: string): YubicoValidationResult {
    return {
        valid: false,
        kind,
        status,
        replayed: kind === 'replayed_otp' || kind === 'replayed_request',
    };
}

export async function verifyYubicoOtp(
    otp: string,
    config: YubicoValidationConfig,
    fetchImpl: YubicoFetch,
    options: { nonce?: string; signal?: AbortSignal } = {},
): Promise<YubicoValidationResult> {
    const parsedOtp = parseYubiKeyOtp(otp);
    if (!parsedOtp) return failure('invalid_otp');

    const request = await buildYubicoValidationRequest(parsedOtp.otp, config, options.nonce);
    if (!request) return failure('configuration_error');

    const timeoutMs = Number.isFinite(config.timeoutMs)
        ? Math.max(1, Math.trunc(config.timeoutMs as number))
        : DEFAULT_TIMEOUT_MS;
    if (options.signal?.aborted) return failure('timeout');
    const controller = new AbortController();
    const externalAbort = () => controller.abort();
    options.signal?.addEventListener('abort', externalAbort, { once: true });

    let timeoutId: ReturnType<typeof setTimeout> | undefined;
    try {
        const timeout = new Promise<never>((_, reject) => {
            timeoutId = setTimeout(() => {
                controller.abort();
                reject(new DOMException('Yubico validation timed out.', 'TimeoutError'));
            }, timeoutMs);
        });
        const response = await Promise.race([
            fetchImpl(request.url, { method: 'GET', redirect: 'manual', signal: controller.signal }),
            timeout,
        ]);
        if (!response.ok) return failure('provider_rejected', `HTTP_${response.status}`);

        const responseText = await readLimitedText(response);
        const fields = responseText === null ? null : parseYubicoResponse(responseText);
        if (!fields) return failure('invalid_response');

        const expectedSignature = await signFields(fields, config.secret);
        if (!expectedSignature || !constantTimeEqual(expectedSignature, fields.h)) {
            return failure('invalid_response');
        }
        if (fields.nonce !== request.nonce || fields.otp !== parsedOtp.otp) {
            return failure('invalid_response');
        }

        const kind = classifyStatus(fields.status);
        return {
            valid: kind === 'ok',
            kind,
            status: fields.status,
            publicId: parsedOtp.publicId,
            replayed: kind === 'replayed_otp' || kind === 'replayed_request',
            sessionCounter: optionalInteger(fields.sessioncounter),
            sessionUse: optionalInteger(fields.sessionuse),
            tokenTimestamp: optionalInteger(fields.timestamp),
        };
    } catch (error) {
        if (error instanceof DOMException && (error.name === 'TimeoutError' || error.name === 'AbortError')) {
            return failure('timeout');
        }
        return failure('network_error');
    } finally {
        if (timeoutId !== undefined) clearTimeout(timeoutId);
        options.signal?.removeEventListener('abort', externalAbort);
    }
}
