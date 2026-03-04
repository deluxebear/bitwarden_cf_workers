import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, desc } from 'drizzle-orm';
import { events, organizationUsers, ciphers } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import type { Bindings, Variables } from '../types';

const evRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();
evRoutes.use('/*', authMiddleware);

/**
 * 格式化 Event 模型以符合原始 API 响应
 */
export function toEventResponse(ev: any) {
    return {
        type: ev.type,
        userId: ev.userId,
        organizationId: ev.organizationId,
        cipherId: ev.cipherId,
        collectionId: ev.collectionId,
        actingUserId: ev.actingUserId,
        deviceType: ev.deviceType,
        ipAddress: ev.ipAddress,
        systemUser: ev.systemUser,
        date: ev.date,
        object: 'event',
    };
}

/**
 * GET /api/events
 * 获取当前用户的审计事件
 */
evRoutes.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const userEvents = await db.select().from(events)
        .where(eq(events.userId, userId))
        .orderBy(desc(events.date))
        .limit(50)
        .all();

    return c.json({
        data: userEvents.map(toEventResponse),
        object: 'list',
        continuationToken: null,
    });
});

// 其它部分迁移至 ciphers.ts 和 organizations.ts

export default evRoutes;
