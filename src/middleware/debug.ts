/**
 * Bitwarden Workers - 调试日志中间件
 * 记录客户端 API 调用详情
 */

import { Context, MiddlewareHandler } from 'hono';
import type { Bindings, Variables } from '../types';

type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;

/**
 * 调试日志中间件
 * 记录每个请求的方法、路径、时间、客户端信息
 */
export const debugMiddleware: MiddlewareHandler<{
    Bindings: Bindings;
    Variables: Variables;
}> = async (c, next) => {
    const startTime = Date.now();
    const method = c.req.method;
    const path = c.req.path;

    // 提取客户端信息
    const deviceType = c.req.header('Device-Type') || 'unknown';
    const clientName = c.req.header('Bitwarden-Client-Name') || 'unknown';
    const clientVersion = c.req.header('Bitwarden-Client-Version') || 'unknown';
    const userAgent = c.req.header('User-Agent') || 'unknown';

    // 请求 ID（用于追踪）
    const requestId = crypto.randomUUID().slice(0, 8);
    c.set('requestId', requestId);

    // 记录请求开始
    console.log(`[REQ ${requestId}] ${method} ${path}`);
    console.log(`  Client: ${clientName}/${clientVersion} (${deviceType})`);

    // 记录关键 header（脱敏）
    const authHeader = c.req.header('Authorization');
    if (authHeader) {
        const tokenPreview = authHeader.slice(7, 20) + '...';
        console.log(`  Auth: Bearer ${tokenPreview}`);
    }

    // 如果是 POST/PUT，记录请求体摘要
    if (['POST', 'PUT'].includes(method)) {
        const contentType = c.req.header('content-type') || '';

        if (contentType.includes('multipart/form-data')) {
            // multipart/form-data（文件上传）：不解析 body，避免干扰文件流
            console.log(`  Body: <multipart/form-data, skipped>`);
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
            // 使用 clone() 避免消耗原始请求体
            try {
                const clone = c.req.raw.clone();
                const text = await clone.text();
                const params = new URLSearchParams(text);
                const formObj: Record<string, string> = {};
                for (const [key, value] of params.entries()) {
                    formObj[key] = sensitiveFields.includes(key) ? value.slice(0, 10) + '***' : value;
                }
                console.log(`  Body (form): ${JSON.stringify(formObj).slice(0, 300)}`);
            } catch (e) {
                console.log(`  Body (form): <parse error: ${e}>`);
            }
        } else {
            // JSON body
            try {
                const clone = c.req.raw.clone();
                const body = await clone.json().catch(() => null);
                if (body) {
                    const sanitized = sanitizeBody(body);
                    console.log(`  Body: ${JSON.stringify(sanitized).slice(0, 200)}`);
                }
            } catch {
                // 忽略无法解析的 body
            }
        }
    }

    await next();

    // 记录响应
    const duration = Date.now() - startTime;
    const status = c.res.status;
    console.log(`[RES ${requestId}] ${status} - ${duration}ms`);
};

/**
 * 脱敏请求体中的敏感字段
 */
const sensitiveFields = [
    'masterPasswordHash',
    'masterPassword',
    'password',
    'key',
    'privateKey',
    'encryptedPrivateKey',
    'token',
    'accessToken',
    'refreshToken',
    'code',
];

function sanitizeBody(body: any): any {
    if (typeof body !== 'object' || body === null) return body;

    const sanitized: any = { ...body };
    for (const field of sensitiveFields) {
        if (sanitized[field]) {
            sanitized[field] = sanitized[field].slice(0, 10) + '***';
        }
    }
    return sanitized;
}
