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
    return submittedHash === storedHash;
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

// ---- 工具函数 ----

function uint8ArrayToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary);
}
