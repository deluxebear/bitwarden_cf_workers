const DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS = 5 * 60;

type AttachmentTokenPayload = {
    cipherId: string;
    attachmentId: string;
    exp: number;
};

export async function signAttachmentDownloadToken(
    cipherId: string,
    attachmentId: string,
    secret: string,
    ttlSeconds = DEFAULT_ATTACHMENT_TOKEN_TTL_SECONDS,
): Promise<string> {
    const payload: AttachmentTokenPayload = {
        cipherId,
        attachmentId,
        exp: Math.floor(Date.now() / 1000) + ttlSeconds,
    };
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signature = await hmacSign(encodedPayload, secret);
    return `${encodedPayload}.${signature}`;
}

export async function verifyAttachmentDownloadToken(
    token: string,
    secret: string,
): Promise<{ cipherId: string; attachmentId: string } | null> {
    const parts = token.split('.');
    if (parts.length !== 2) return null;

    const [encodedPayload, signature] = parts;
    if (!await hmacVerify(encodedPayload, signature, secret)) return null;

    try {
        const payload = JSON.parse(base64UrlDecode(encodedPayload)) as AttachmentTokenPayload;
        if (!payload.cipherId || !payload.attachmentId) return null;
        if (payload.exp < Math.floor(Date.now() / 1000)) return null;
        return { cipherId: payload.cipherId, attachmentId: payload.attachmentId };
    } catch {
        return null;
    }
}

export async function buildAttachmentDownloadUrl(
    baseUrl: string,
    cipherId: string,
    attachmentId: string,
    secret: string,
): Promise<string> {
    const token = await signAttachmentDownloadToken(cipherId, attachmentId, secret);
    return `${baseUrl}/api/ciphers/attachment/download?token=${encodeURIComponent(token)}`;
}

async function hmacSign(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    return base64UrlEncodeBytes(new Uint8Array(signature));
}

async function hmacVerify(data: string, encodedSignature: string, secret: string): Promise<boolean> {
    try {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify'],
        );
        return await crypto.subtle.verify(
            'HMAC',
            key,
            base64UrlDecodeBytes(encodedSignature),
            encoder.encode(data),
        );
    } catch {
        return false;
    }
}

function base64UrlEncode(input: string): string {
    return base64UrlEncodeBytes(new TextEncoder().encode(input));
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(input: string): string {
    return new TextDecoder().decode(base64UrlDecodeBytes(input));
}

function base64UrlDecodeBytes(input: string): Uint8Array<ArrayBuffer> {
    const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - input.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}
