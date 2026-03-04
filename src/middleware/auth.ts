/**
 * Bitwarden Workers - JWT 认证中间件
 * 对应原始项目 Identity 模块的 OAuth2 Token 签发和验证
 */

import { Context, MiddlewareHandler } from 'hono';
import type { Bindings, Variables, JwtPayload } from '../types';

type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;

/**
 * JWT 签发 - 使用 HMAC-SHA256
 */
export async function signJwt(
    payload: Omit<JwtPayload, 'iat' | 'exp' | 'nbf' | 'iss'>,
    secret: string,
    expiresInSeconds: number
): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const fullPayload: JwtPayload = {
        ...payload,
        iss: 'bitwarden-workers',
        iat: now,
        nbf: now,
        exp: now + expiresInSeconds,
    };

    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(fullPayload));

    const data = `${encodedHeader}.${encodedPayload}`;
    const signature = await hmacSign(data, secret);

    return `${data}.${signature}`;
}

/**
 * JWT 验证
 */
export async function verifyJwt(
    token: string,
    secret: string
): Promise<JwtPayload | null> {
    try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;

        const [encodedHeader, encodedPayload, signature] = parts;
        const data = `${encodedHeader}.${encodedPayload}`;

        // 验证签名
        const expectedSignature = await hmacSign(data, secret);
        if (signature !== expectedSignature) return null;

        // 解码 payload
        const payload: JwtPayload = JSON.parse(base64UrlDecode(encodedPayload));

        // 检查过期
        const now = Math.floor(Date.now() / 1000);
        if (payload.exp && payload.exp < now) return null;
        if (payload.nbf && payload.nbf > now) return null;

        return payload;
    } catch {
        return null;
    }
}

/**
 * Hono 认证中间件 - 对应原始项目的 [Authorize("Application")]
 */
export const authMiddleware: MiddlewareHandler<{
    Bindings: Bindings;
    Variables: Variables;
}> = async (c, next) => {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
        return c.json({ message: 'Unauthorized' }, 401);
    }

    const token = authHeader.slice(7);
    const payload = await verifyJwt(token, c.env.JWT_SECRET);

    if (!payload) {
        return c.json({ message: 'Unauthorized' }, 401);
    }

    c.set('userId', payload.sub);
    c.set('email', payload.email);
    c.set('jwtPayload', payload);

    await next();
};

// ---- 内部工具函数 ----

async function hmacSign(data: string, secret: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
    return base64UrlEncodeBytes(new Uint8Array(signature));
}

function base64UrlEncode(str: string): string {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    return atob(padded);
}
