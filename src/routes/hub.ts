/**
 * Bitwarden Workers - Notification Hub 路由
 *
 * 对应官方 Notifications/Startup.cs 的端点映射：
 *   /hub          - NotificationsHub (认证 WebSocket)
 *   /anonymous-hub - AnonymousNotificationsHub (匿名 WebSocket)
 *
 * 客户端使用 skipNegotiation: true，直接发起 WebSocket 连接，
 * 不调用 /hub/negotiate 端点。
 */

import { Hono } from 'hono';
import type { Bindings, Variables } from '../types';
import { verifyJwt } from '../middleware/auth';
import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';
import { organizationUsers } from '../db/schema';

type HubBindings = Bindings & {
    NOTIFICATION_HUB: DurableObjectNamespace;
};

const hub = new Hono<{ Bindings: HubBindings; Variables: Variables }>();

// DO 的固定 ID（全局单实例）
const DO_ID_NAME = 'global-notification-hub';

/**
 * GET /hub - 认证 WebSocket 连接
 *
 * 客户端通过 query string 传递 access_token（SignalR WebSocket 标准做法）
 * 服务端验证 JWT，获取 userId 和 orgIds，然后转发到 DO
 */
hub.get('/hub', async (c) => {
    const upgradeHeader = c.req.header('Upgrade');
    if (upgradeHeader !== 'websocket') {
        return c.json({ message: 'Expected WebSocket upgrade' }, 426);
    }

    // 从 query string 获取 access_token（SignalR 标准做法）
    const accessToken = c.req.query('access_token');
    if (!accessToken) {
        return c.json({ message: 'Unauthorized' }, 401);
    }

    // 验证 JWT
    const payload = await verifyJwt(accessToken, c.env.JWT_SECRET);
    if (!payload) {
        return c.json({ message: 'Unauthorized' }, 401);
    }

    const userId = payload.sub;
    const deviceId = payload.device || null;

    // 查询用户所属组织
    let orgIds: string[] = [];
    try {
        const db = drizzle(c.env.DB);
        const orgMemberships = await db
            .select({ organizationId: organizationUsers.organizationId })
            .from(organizationUsers)
            .where(eq(organizationUsers.userId, userId));
        orgIds = orgMemberships.map(m => m.organizationId);
    } catch {
        // DB 查询失败不阻止连接
    }

    // 构建 DO 请求 URL，携带用户信息
    const doUrl = new URL('https://do/hub');
    doUrl.searchParams.set('userId', userId);
    doUrl.searchParams.set('deviceId', deviceId || '');
    if (orgIds.length > 0) {
        doUrl.searchParams.set('orgIds', orgIds.join(','));
    }

    // 转发 WebSocket 升级到 DO
    const id = c.env.NOTIFICATION_HUB.idFromName(DO_ID_NAME);
    const stub = c.env.NOTIFICATION_HUB.get(id);

    return stub.fetch(new Request(doUrl.toString(), {
        headers: c.req.raw.headers,
    }));
});

/**
 * GET /anonymous-hub - 匿名 WebSocket 连接
 *
 * 用于 Auth Request 无密码登录流程。
 * 客户端通过 query string 传递 Token 参数。
 */
hub.get('/anonymous-hub', async (c) => {
    const upgradeHeader = c.req.header('Upgrade');
    if (upgradeHeader !== 'websocket') {
        return c.json({ message: 'Expected WebSocket upgrade' }, 426);
    }

    const token = c.req.query('Token') || c.req.query('token');
    if (!token) {
        return c.json({ message: 'Token is required' }, 400);
    }

    // 构建 DO 请求 URL
    const doUrl = new URL('https://do/anonymous-hub');
    doUrl.searchParams.set('Token', token);

    // 转发到 DO
    const id = c.env.NOTIFICATION_HUB.idFromName(DO_ID_NAME);
    const stub = c.env.NOTIFICATION_HUB.get(id);

    return stub.fetch(new Request(doUrl.toString(), {
        headers: c.req.raw.headers,
    }));
});

/**
 * POST /hub/negotiate - SignalR Negotiate 端点
 *
 * 客户端使用 skipNegotiation: true，不会调用此端点。
 * 但保留以防某些客户端不跳过。
 */
hub.post('/hub/negotiate', (c) => {
    // 返回空响应，提示使用 WebSocket
    return c.json({
        connectionId: crypto.randomUUID(),
        connectionToken: crypto.randomUUID(),
        negotiateVersion: 1,
        availableTransports: [
            {
                transport: 'WebSockets',
                transferFormats: ['Binary'],
            },
        ],
    });
});

export default hub;
