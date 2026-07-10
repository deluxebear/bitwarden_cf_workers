/**
 * 请求级结构化日志。
 *
 * 不记录 header、query、body 或用户标识，避免认证凭据和个人信息进入日志。
 */

import type { MiddlewareHandler } from 'hono';
import type { Bindings, Variables } from '../types';
import { INTERNAL_ERROR_CODE_HEADER } from './error';

function normalizeRequestId(value: string | undefined): string {
    if (value && /^[A-Za-z0-9_-]{8,64}$/.test(value)) return value;
    return crypto.randomUUID();
}

export const debugMiddleware: MiddlewareHandler<{
    Bindings: Bindings;
    Variables: Variables;
}> = async (c, next) => {
    const startedAt = performance.now();
    const requestId = normalizeRequestId(c.req.header('X-Request-Id'));
    c.set('requestId', requestId);

    await next();

    const errorCode = c.res.headers.get(INTERNAL_ERROR_CODE_HEADER)
        ?? (c.res.status >= 500 ? 'INTERNAL_ERROR' : null);
    c.res.headers.delete(INTERNAL_ERROR_CODE_HEADER);
    c.res.headers.set('X-Request-Id', requestId);

    console.log(JSON.stringify({
        requestId,
        method: c.req.method,
        route: c.req.routePath || 'unmatched',
        status: c.res.status,
        duration: Math.max(0, Math.round(performance.now() - startedAt)),
        errorCode,
    }));
};
