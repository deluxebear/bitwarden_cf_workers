/**
 * Bitwarden Workers - Auth Requests 路由
 * 对应原始项目 Api/Auth/Controllers/AuthRequestsController.cs
 * 处理：Passwordless Login（使用其他设备登录/审批）
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and } from 'drizzle-orm';
import { users, devices, authRequests } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables, AuthRequestCreateRequest, AuthRequestUpdateRequest } from '../types';
import { AuthRequestType } from '../types';
import { pushAuthRequest, pushAuthRequestResponse } from '../services/push-notification';

const authRequestsRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// ---- 辅助函数 ----

/**
 * 构建 AuthRequest 响应对象
 * 对应 AuthRequestResponseModel.cs
 */
function buildAuthRequestResponse(authRequest: {
    id: string;
    publicKey: string | null;
    requestDeviceIdentifier: string;
    requestDeviceType: number;
    requestIpAddress: string | null;
    key?: string | null;
    masterPasswordHash?: string | null;
    creationDate: string;
    responseDate: string | null;
    authenticationDate?: string | null;
    responseDeviceId?: string | null;
    approved: boolean | null;
}) {
    return {
        id: authRequest.id,
        publicKey: authRequest.publicKey,
        requestDeviceIdentifier: authRequest.requestDeviceIdentifier,
        requestDeviceType: getDeviceTypeName(authRequest.requestDeviceType),
        requestDeviceTypeValue: authRequest.requestDeviceType,
        requestIpAddress: authRequest.requestIpAddress || '',
        requestCountryName: null as string | null,
        key: authRequest.key,
        masterPasswordHash: authRequest.masterPasswordHash,
        creationDate: authRequest.creationDate,
        responseDate: authRequest.responseDate,
        requestApproved: authRequest.approved ?? false,
        origin: 'bitwarden-workers',
        object: 'auth-request',
    };
}

/**
 * DeviceType 数值转显示名
 * 对应 DeviceType enum 的 Display 属性
 */
function getDeviceTypeName(type: number): string {
    const names: Record<number, string> = {
        0: 'Android', 1: 'iOS', 2: 'Chrome Extension', 3: 'Firefox Extension',
        4: 'Opera Extension', 5: 'Edge Extension', 6: 'Windows', 7: 'macOS',
        8: 'Linux', 9: 'Chrome', 10: 'Firefox', 11: 'Opera', 12: 'Edge',
        13: 'Internet Explorer', 14: 'Unknown Browser', 15: 'Android',
        16: 'UWP', 17: 'Safari', 18: 'Vivaldi', 19: 'Vivaldi Extension',
        20: 'Safari Extension', 21: 'SDK', 22: 'Server',
        23: 'Windows CLI', 24: 'macOS CLI', 25: 'Linux CLI',
    };
    return names[type] || 'Unknown';
}

/**
 * 检查 AuthRequest 是否过期（15 分钟）
 * 对应 AuthRequest.GetExpirationDate()
 */
function isExpired(creationDate: string): boolean {
    const created = new Date(creationDate).getTime();
    const now = Date.now();
    return now - created > 15 * 60 * 1000; // 15 分钟
}

// ---- 匿名端点 ----

/**
 * POST /api/auth-requests
 * 对应 AuthRequestsController.Post [AllowAnonymous]
 * 发起新的登录请求
 */
authRequestsRoute.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    let body: AuthRequestCreateRequest;
    try {
        body = await c.req.json();
    } catch {
        return c.json({ message: 'Invalid JSON.', object: 'error' }, 400);
    }

    if (!body.email || !body.publicKey || !body.deviceIdentifier || !body.accessCode) {
        return c.json({ message: 'Missing required fields.', object: 'error' }, 400);
    }

    // AdminApproval 类型需要认证（对应官方逻辑）
    if (body.type === AuthRequestType.AdminApproval) {
        return c.json({ message: 'You must be authenticated to create a request of that type.', object: 'error' }, 400);
    }

    // 查找用户
    const user = await db.select({ id: users.id })
        .from(users)
        .where(eq(users.email, body.email.toLowerCase().trim()))
        .get();

    // 匿名端点不应泄露用户是否存在
    if (!user) {
        return c.json({ message: 'User or known device not found.', object: 'error' }, 400);
    }

    // 获取请求方设备类型（从 Device-Type 请求头）
    const deviceTypeHeader = c.req.header('Device-Type');
    const requestDeviceType = deviceTypeHeader ? parseInt(deviceTypeHeader, 10) : 14; // 默认 UnknownBrowser

    const now = new Date().toISOString();
    const id = crypto.randomUUID();

    const newAuthRequest = {
        id,
        userId: user.id,
        type: body.type ?? AuthRequestType.AuthenticateAndUnlock,
        requestDeviceIdentifier: body.deviceIdentifier,
        requestDeviceType: requestDeviceType,
        requestIpAddress: c.req.header('CF-Connecting-IP') || c.req.header('X-Forwarded-For') || '',
        accessCode: body.accessCode,
        publicKey: body.publicKey,
        creationDate: now,
    };

    await db.insert(authRequests).values(newAuthRequest).execute();

    // 推送 AuthRequest 通知到用户的设备
    c.executionCtx.waitUntil(pushAuthRequest(c.env, id, user.id, null));

    return c.json(buildAuthRequestResponse({
        ...newAuthRequest,
        key: null,
        masterPasswordHash: null,
        approved: null,
        responseDate: null,
        authenticationDate: null,
        responseDeviceId: null,
    }));
});

/**
 * GET /api/auth-requests/:id/response
 * 对应 AuthRequestsController.GetResponse [AllowAnonymous]
 * 请求方轮询审批结果，需要 code query 参数
 */
authRequestsRoute.get('/:id/response', async (c) => {
    const db = drizzle(c.env.DB);
    const id = c.req.param('id');
    const code = c.req.query('code');

    if (!code) {
        return c.json({ message: 'Access code is required.', object: 'error' }, 400);
    }

    const authRequest = await db.select()
        .from(authRequests)
        .where(eq(authRequests.id, id))
        .get();

    // 验证 accessCode（对应 GetValidatedAuthRequestAsync）
    if (!authRequest || authRequest.accessCode !== code) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    // 检查是否已消费或过期（对应 IsAuthRequestValid / IsSpent）
    if (authRequest.responseDate || authRequest.authenticationDate || isExpired(authRequest.creationDate)) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    return c.json(buildAuthRequestResponse(authRequest));
});

// ---- 认证端点（每个路由单独挂 authMiddleware，避免影响上面的匿名端点） ----

/**
 * GET /api/auth-requests
 * 对应 AuthRequestsController.GetAll
 * 获取当前用户所有登录请求
 */
authRequestsRoute.get('/', authMiddleware, async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const requests = await db.select()
        .from(authRequests)
        .where(eq(authRequests.userId, userId))
        .all();

    const data = requests.map(r => buildAuthRequestResponse(r));

    return c.json({
        data,
        continuationToken: null,
        object: 'list',
    });
});

/**
 * GET /api/auth-requests/pending
 * 对应 AuthRequestsController.GetPendingAuthRequestsAsync
 * 获取当前用户所有「待处理」的登录请求（每个设备只返回最新一条）。
 */
authRequestsRoute.get('/pending', authMiddleware, async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const requests = await db.select()
        .from(authRequests)
        .where(eq(authRequests.userId, userId))
        .all();

    const pending = requests.filter((r) => {
        if (!r) {
            return false;
        }
        if (r.responseDate || r.authenticationDate) {
            return false;
        }
        if (!r.creationDate) {
            return false;
        }
        return !isExpired(r.creationDate);
    });

    const latestByDevice = new Map<string, (typeof pending)[number]>();
    for (const req of pending) {
        const key = req.requestDeviceIdentifier || '';
        const existing = latestByDevice.get(key);
        if (!existing) {
            latestByDevice.set(key, req);
            continue;
        }
        const existingTime = new Date(existing.creationDate).getTime();
        const currentTime = new Date(req.creationDate).getTime();
        if (currentTime > existingTime) {
            latestByDevice.set(key, req);
        }
    }

    const data = Array.from(latestByDevice.values()).map((r) => buildAuthRequestResponse(r));

    return c.json({
        data,
        continuationToken: null,
        object: 'list',
    });
});

/**
 * GET /api/auth-requests/:id
 * 对应 AuthRequestsController.Get
 * 获取指定的登录请求
 */
authRequestsRoute.get('/:id', authMiddleware, async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');

    const authRequest = await db.select()
        .from(authRequests)
        .where(and(eq(authRequests.id, id), eq(authRequests.userId, userId)))
        .get();

    if (!authRequest) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    return c.json(buildAuthRequestResponse(authRequest));
});

/**
 * PUT /api/auth-requests/:id
 * 对应 AuthRequestsController.Put
 * 批准或拒绝登录请求
 */
authRequestsRoute.put('/:id', authMiddleware, async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');

    let body: AuthRequestUpdateRequest;
    try {
        body = await c.req.json();
    } catch {
        return c.json({ message: 'Invalid JSON.', object: 'error' }, 400);
    }

    if (!body.deviceIdentifier) {
        return c.json({ message: 'Device identifier is required.', object: 'error' }, 400);
    }

    const authRequest = await db.select()
        .from(authRequests)
        .where(eq(authRequests.id, id))
        .get();

    if (!authRequest) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    if (authRequest.approved !== null) {
        return c.json({ message: 'Auth request has already been processed.', object: 'error' }, 400);
    }

    if (isExpired(authRequest.creationDate)) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    if (authRequest.userId !== userId) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    const device = await db.select({ id: devices.id })
        .from(devices)
        .where(and(eq(devices.identifier, body.deviceIdentifier), eq(devices.userId, userId)))
        .get();

    if (!device) {
        return c.json({ message: 'Invalid device.', object: 'error' }, 400);
    }

    const now = new Date().toISOString();

    const updateData: {
        responseDate: string;
        approved: boolean | null;
        responseDeviceId: string;
        key?: string | null;
        masterPasswordHash?: string | null;
    } = {
        responseDate: now,
        approved: body.requestApproved,
        responseDeviceId: device.id,
    };

    if (body.requestApproved) {
        updateData.key = body.key || null;
        updateData.masterPasswordHash = body.masterPasswordHash || null;
    }

    await db.update(authRequests)
        .set(updateData)
        .where(eq(authRequests.id, id))
        .execute();

    const updated = await db.select()
        .from(authRequests)
        .where(eq(authRequests.id, id))
        .get();

    if (!updated) {
        return c.json({ message: 'Auth request not found.', object: 'error' }, 404);
    }

    if (body.requestApproved) {
        c.executionCtx.waitUntil(pushAuthRequestResponse(c.env, id, authRequest.userId));
    }

    return c.json(buildAuthRequestResponse(updated));
});

export default authRequestsRoute;
