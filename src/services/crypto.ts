/**
 * Bitwarden Workers - 加密服务
 * 使用 Web Crypto API（Workers 原生支持）
 * 对应原始项目 Core/Services 中的密码哈希逻辑
 */

/**
 * 使用 PBKDF2-SHA256 派生密钥
 * 对应 Bitwarden 客户端的 master password hashing 流程
 */
export async function hashPassword(
    password: string,
    salt: string,
    iterations: number
): Promise<string> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: encoder.encode(salt),
            iterations,
            hash: 'SHA-256',
        },
        keyMaterial,
        256
    );

    // Bitwarden 对 derived key 再做一次 PBKDF2 得到 server-side hash
    const derivedKey = await crypto.subtle.importKey(
        'raw',
        derivedBits,
        'PBKDF2',
        false,
        ['deriveBits']
    );

    const serverHash = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: encoder.encode(password),
            iterations: 1,
            hash: 'SHA-256',
        },
        derivedKey,
        256
    );

    return uint8ArrayToBase64(new Uint8Array(serverHash));
}

/**
 * 验证 master password hash
 * 客户端发送的是 base64(PBKDF2(masterKey, password, 1))
 * 服务端存储的也是相同格式
 */
export async function verifyPassword(
    submittedHash: string,
    storedHash: string
): Promise<boolean> {
    return constantTimeEqual(submittedHash, storedHash);
}

/**
 * Hash Send 密码 - 使用 PBKDF2-SHA256
 * Send 密码与 master password 不同，客户端直接发送原始密码
 */
export async function hashSendPassword(password: string): Promise<string> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']
    );
    const hash = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: encoder.encode('bitwarden-send'),
        iterations: 100000,
        hash: 'SHA-256',
    }, keyMaterial, 256);
    return uint8ArrayToBase64(new Uint8Array(hash));
}

export async function verifySendPassword(password: string, storedHash: string): Promise<boolean> {
    const hash = await hashSendPassword(password);
    return constantTimeEqual(hash, storedHash);
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

/**
 * 生成安全的随机 UUID v4
 */
export function generateUuid(): string {
    return crypto.randomUUID();
}

/**
 * 生成安全的随机字符串（用于 security stamp, api key 等）
 */
export function generateSecureRandomString(length: number = 32): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const randomValues = new Uint8Array(length);
    crypto.getRandomValues(randomValues);
    return Array.from(randomValues, (v) => chars[v % chars.length]).join('');
}

/**
 * 生成 refresh token
 */
export function generateRefreshToken(): string {
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    return uint8ArrayToBase64(bytes);
}

/**
 * SHA-256 哈希
 */
export async function sha256(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoder.encode(data));
    return uint8ArrayToBase64(new Uint8Array(hashBuffer));
}

// ---- 组织邀请 Token（5 天有效，与官方 OrgUserInviteTokenable 行为一致） ----

const INVITE_TOKEN_LIFETIME_SEC = 5 * 24 * 3600; // 5 days

function base64urlEncode(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(str: string): Uint8Array {
    let s = str.replace(/-/g, '+').replace(/_/g, '/');
    const pad = s.length % 4;
    if (pad) s += '='.repeat(4 - pad);
    const binary = atob(s);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

/**
 * 生成组织邀请 Token（HMAC-SHA256 签名，payload 含 orgUserId, email, orgId, exp）
 */
export async function createInviteToken(
    orgUserId: string,
    email: string,
    orgId: string,
    secret: string
): Promise<string> {
    const exp = Math.floor(Date.now() / 1000) + INVITE_TOKEN_LIFETIME_SEC;
    const payload = JSON.stringify({ o: orgUserId, e: email.toLowerCase(), r: orgId, exp });
    const payloadBytes = new TextEncoder().encode(payload);
    const payloadB64 = base64urlEncode(new Uint8Array(payloadBytes));

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const sig = await crypto.subtle.sign(
        'HMAC',
        key,
        new TextEncoder().encode(payloadB64)
    );
    const sigB64 = base64urlEncode(new Uint8Array(sig));
    return `${payloadB64}.${sigB64}`;
}

/**
 * 校验组织邀请 Token，成功返回 { orgUserId, email, orgId }，失败返回 null
 */
export async function verifyInviteToken(
    token: string,
    secret: string
): Promise<{ orgUserId: string; email: string; orgId: string } | null> {
    const dot = token.indexOf('.');
    if (dot <= 0) return null;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);

    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
    );
    const sig = base64urlDecode(sigB64);
    const valid = await crypto.subtle.verify(
        'HMAC',
        key,
        sig,
        new TextEncoder().encode(payloadB64)
    );
    if (!valid) return null;

    try {
        const payloadBytes = base64urlDecode(payloadB64);
        const payload = JSON.parse(new TextDecoder().decode(payloadBytes)) as { o?: string; e?: string; r?: string; exp?: number };
        if (!payload.o || !payload.e || !payload.r || typeof payload.exp !== 'number') return null;
        if (payload.exp < Math.floor(Date.now() / 1000)) return null; // expired
        return { orgUserId: payload.o, email: payload.e, orgId: payload.r };
    } catch {
        return null;
    }
}

// ---- 工具函数 ----

function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}
