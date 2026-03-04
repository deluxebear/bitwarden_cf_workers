/**
 * Bitwarden Workers - Devices 路由
 * 对应原始项目 Api/Controllers/DevicesController.cs
 * 处理：已知设备检查、设备列表
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and } from 'drizzle-orm';
import { users, devices } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables } from '../types';

const devicesRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * GET /api/devices/knowndevice
 * 对应 DevicesController.GetByIdentifierQuery
 * 检查设备是否为已知设备（用于新设备登录通知）
 * 此端点在登录之前调用，无需认证。
 * 客户端通过 email 查询参数 + X-Device-Identifier 请求头传递信息。
 */
devicesRoute.get('/knowndevice', async (c) => {
    const db = drizzle(c.env.DB);

    // email 可能在 query param 或 header 中
    // iOS 客户端将 email 以 base64(email).urlEncoded() 的格式放在 X-Request-Email 头中
    let email = (c.req.query('email') || '').toLowerCase().trim();
    if (!email) {
        const rawEmailHeader = c.req.header('X-Request-Email') || '';
        if (rawEmailHeader) {
            try {
                email = atob(decodeURIComponent(rawEmailHeader)).toLowerCase().trim();
            } catch {
                email = rawEmailHeader.toLowerCase().trim();
            }
        }
    }
    const deviceIdentifier = c.req.header('X-Device-Identifier') || c.req.query('identifier') || '';

    if (!email || !deviceIdentifier) {
        // 无法确定时，保守返回 false（让客户端走正常流程）
        return c.json(false);
    }

    const user = await db.select({ id: users.id })
        .from(users).where(eq(users.email, email)).get();

    if (!user) {
        return c.json(false);
    }

    const device = await db.select({ id: devices.id })
        .from(devices)
        .where(and(eq(devices.userId, user.id), eq(devices.identifier, deviceIdentifier)))
        .get();

    return c.json(!!device);
});

// 以下端点需要认证
devicesRoute.use('/identifier/*', authMiddleware);
devicesRoute.use('/current', authMiddleware);

/**
 * GET /api/devices/identifier/:identifier
 * 获取指定 identifier 的设备信息
 */
devicesRoute.get('/identifier/:identifier', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');

    const device = await db.select()
        .from(devices)
        .where(and(eq(devices.userId, userId), eq(devices.identifier, identifier)))
        .get();

    if (!device) {
        return c.json({ message: 'Device not found.', object: 'error' }, 404);
    }

    return c.json({
        id: device.id,
        name: device.name,
        type: device.type,
        identifier: device.identifier,
        creationDate: device.creationDate,
        revisionDate: device.revisionDate,
        object: 'device',
    });
});

/**
 * PUT /api/devices/identifier/:identifier/token
 * 更新设备 Push Token
 */
devicesRoute.put('/identifier/:identifier/token', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');

    let pushToken: string;
    try {
        const body = await c.req.json();
        pushToken = body.pushToken;
    } catch {
        return c.json({ message: 'Invalid JSON.', object: 'error' }, 400);
    }

    if (!pushToken) {
        return c.json({ message: 'Push token is required.', object: 'error' }, 400);
    }

    const device = await db.select({ id: devices.id })
        .from(devices)
        .where(and(eq(devices.userId, userId), eq(devices.identifier, identifier)))
        .get();

    if (!device) {
        return c.json({ message: 'Device not found.', object: 'error' }, 404);
    }

    await db.update(devices)
        .set({ pushToken, revisionDate: new Date().toISOString() })
        .where(eq(devices.id, device.id))
        .execute();

    return c.json({});
});

/**
 * PUT /api/devices/identifier/:identifier/clear-token
 * 清除设备 Push Token
 */
devicesRoute.put('/identifier/:identifier/clear-token', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');

    const device = await db.select({ id: devices.id })
        .from(devices)
        .where(and(eq(devices.userId, userId), eq(devices.identifier, identifier)))
        .get();

    if (!device) {
        return c.json({ message: 'Device not found.', object: 'error' }, 404);
    }

    await db.update(devices)
        .set({ pushToken: null, revisionDate: new Date().toISOString() })
        .where(eq(devices.id, device.id))
        .execute();

    return c.json({});
});

export default devicesRoute;
