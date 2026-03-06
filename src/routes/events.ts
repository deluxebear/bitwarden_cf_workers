import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, desc, and, sql, inArray } from 'drizzle-orm';
import { events, ciphers, organizationUsers, organizations } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError } from '../middleware/error';
import { logEvent } from '../services/events';
import type { Bindings, Variables } from '../types';
import { batchedInArrayQuery } from '../services/db';

/** 客户端 POST /collect 请求体中的单条事件（对应官方 EventModel） */
interface CollectEventModel {
    type: number;
    cipherId?: string | null;
    date?: string | null;
    organizationId?: string | null;
}

/** DeviceType 枚举值与官方 clients 一致（iOS=1, Android=0 等），用于从 User-Agent 回退推断 */
const DEVICE_TYPE = { Android: 0, iOS: 1 } as const;

/**
 * 从请求头解析 Device-Type（客户端类型），用于事件日志「客户端」列。
 * 官方 iOS/Android 会发 Device-Type；若缺失则根据 Bitwarden-Client-Name 与 User-Agent 推断（如官方 iOS 可能未带该头时仍能识别为「移动端 - iOS」）。
 */
export function getDeviceTypeFromRequest(c: { req: { header: (name: string) => string | undefined } }): number | undefined {
    const raw = c.req.header('Device-Type') ?? c.req.header('device-type');
    if (raw !== undefined && raw !== '') {
        const n = parseInt(raw, 10);
        if (!Number.isNaN(n)) return n;
    }
    const clientName = (c.req.header('Bitwarden-Client-Name') ?? c.req.header('bitwarden-client-name') ?? '').toLowerCase();
    const userAgent = (c.req.header('User-Agent') ?? c.req.header('user-agent') ?? '').toLowerCase();
    if (clientName === 'mobile' || userAgent.includes('bitwarden_mobile')) {
        if (userAgent.includes('android')) return DEVICE_TYPE.Android;
        return DEVICE_TYPE.iOS;
    }
    return undefined;
}

const evRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();

evRoutes.use('/*', authMiddleware);

/** 与官方 ApiHelpers.GetDateRange 一致：默认最近 30 天，最大 367 天 */
export function getDateRange(start?: string | null, end?: string | null): { start: string; end: string } {
    const now = new Date();
    if (!start || !end) {
        const endDate = new Date(now);
        endDate.setUTCDate(endDate.getUTCDate() + 1);
        endDate.setUTCMilliseconds(endDate.getUTCMilliseconds() - 1);
        const startDate = new Date(now);
        startDate.setUTCDate(startDate.getUTCDate() - 30);
        return { start: startDate.toISOString(), end: endDate.toISOString() };
    }
    let startDt = new Date(start);
    let endDt = new Date(end);
    if (startDt.getTime() > endDt.getTime()) {
        [startDt, endDt] = [endDt, startDt];
    }
    const days = (endDt.getTime() - startDt.getTime()) / (24 * 60 * 60 * 1000);
    if (days > 367) {
        throw new BadRequestError('Range too large.');
    }
    return { start: startDt.toISOString(), end: endDt.toISOString() };
}

/**
 * 格式化 Event 模型以符合官方 EventResponseModel（Api/Dirt/Models/Response/EventResponseModel.cs）
 */
export function toEventResponse(ev: any) {
    return {
        type: ev.type,
        userId: ev.userId ?? null,
        organizationId: ev.organizationId ?? null,
        cipherId: ev.cipherId ?? null,
        collectionId: ev.collectionId ?? null,
        groupId: ev.groupId ?? null,
        organizationUserId: ev.organizationUserId ?? null,
        actingUserId: ev.actingUserId ?? null,
        deviceType: ev.deviceType ?? null,
        ipAddress: ev.ipAddress ?? null,
        systemUser: ev.systemUser ?? null,
        date: ev.date,
        object: 'event',
    };
}

const EVENTS_PAGE_SIZE = 100;

/**
 * GET /api/events
 * 获取当前用户的审计事件；支持 start, end, continuationToken（与官方一致）
 */
evRoutes.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const start = c.req.query('start') ?? null;
    const end = c.req.query('end') ?? null;
    const continuationToken = c.req.query('continuationToken') ?? null;

    const { start: startStr, end: endStr } = getDateRange(start, end);

    let conditions = and(
        eq(events.userId, userId),
        sql`${events.date} >= ${startStr}`,
        sql`${events.date} <= ${endStr}`,
    );
    if (continuationToken) {
        try {
            const [tokenDate, tokenId] = Buffer.from(continuationToken, 'base64url').toString('utf8').split('|');
            if (tokenDate && tokenId) {
                conditions = and(
                    conditions,
                    sql`(${events.date} < ${tokenDate} OR (${events.date} = ${tokenDate} AND ${events.id} < ${tokenId}))`,
                );
            }
        } catch {
            /* ignore invalid token */
        }
    }

    const userEvents = await db.select().from(events)
        .where(conditions)
        .orderBy(desc(events.date), desc(events.id))
        .limit(EVENTS_PAGE_SIZE + 1)
        .all();

    const hasMore = userEvents.length > EVENTS_PAGE_SIZE;
    const page = hasMore ? userEvents.slice(0, EVENTS_PAGE_SIZE) : userEvents;
    const nextToken = hasMore && page.length
        ? Buffer.from(`${page[page.length - 1].date}|${page[page.length - 1].id}`).toString('base64url')
        : null;

    return c.json({
        data: page.map(toEventResponse),
        object: 'list',
        continuationToken: nextToken,
    });
});

/**
 * POST /api/events/collect
 * 客户端上报审计事件（对应官方 Events/CollectController）
 * Body: EventModel[] = [{ type, cipherId?, date?, organizationId? }]
 */
evRoutes.post('/collect', async (c) => {
    const body = await c.req.json<CollectEventModel[] | null>().catch(() => null);
    if (!body || !Array.isArray(body) || body.length === 0) {
        return c.json({}, 400);
    }

    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const deviceType = getDeviceTypeFromRequest(c);

    const cipherEventTypes = new Set([
        1107, 1108, 1109, 1110, 1111, 1112, 1113, 1114, 1117, // Cipher_Client*
    ]);

    const cipherEvents: { cipherId: string; type: number; date: string; organizationId?: string | null }[] = [];
    const cipherIdsToLoad = new Set<string>();

    for (const eventModel of body) {
        const eventType = Number(eventModel.type);
        const eventDate = eventModel.date || new Date().toISOString();

        switch (eventType) {
            case 1007: // User_ClientExportedVault
                await logEvent(c.env.DB, 1007, { userId, deviceType }, eventDate);
                break;

            case 1618: // Organization_ItemOrganization_Accepted
            case 1619: { // Organization_ItemOrganization_Declined
                if (!eventModel.organizationId) continue;
                const orgUser = await db.select().from(organizationUsers)
                    .where(and(
                        eq(organizationUsers.organizationId, eventModel.organizationId),
                        eq(organizationUsers.userId, userId),
                    )).get();
                if (!orgUser) continue;
                await logEvent(c.env.DB, eventType, {
                    userId,
                    organizationId: eventModel.organizationId,
                    organizationUserId: orgUser.id,
                    actingUserId: userId,
                    deviceType,
                }, eventDate);
                break;
            }

            case 1602: // Organization_ClientExportedVault
            case 1620: case 1621: case 1622: case 1623: { // Organization_AutoConfirm*
                if (!eventModel.organizationId) continue;
                const org = await db.select().from(organizations)
                    .where(eq(organizations.id, eventModel.organizationId)).get();
                if (!org) continue;
                await logEvent(c.env.DB, eventType, {
                    userId,
                    organizationId: eventModel.organizationId,
                    actingUserId: userId,
                    deviceType,
                }, eventDate);
                break;
            }

            default:
                if (cipherEventTypes.has(eventType) && eventModel.cipherId) {
                    cipherIdsToLoad.add(eventModel.cipherId);
                    cipherEvents.push({
                        cipherId: eventModel.cipherId,
                        type: eventType,
                        date: eventDate,
                        organizationId: eventModel.organizationId,
                    });
                }
                break;
        }
    }

    if (cipherEvents.length > 0 && cipherIdsToLoad.size > 0) {
        const cipherList = await batchedInArrayQuery<typeof ciphers.$inferSelect>(
            db, ciphers, ciphers.id, [...cipherIdsToLoad]);
        const cipherMap = new Map(cipherList.map((row) => [row.id, row]));

        for (const ev of cipherEvents) {
            const cipher = cipherMap.get(ev.cipherId);
            if (!cipher) continue;
            const canAccess = cipher.userId === userId ||
                (cipher.organizationId && ev.organizationId != null && ev.organizationId === cipher.organizationId);
            if (!canAccess) continue;
            await logEvent(c.env.DB, ev.type, {
                userId: cipher.userId ?? undefined,
                organizationId: cipher.organizationId ?? undefined,
                cipherId: ev.cipherId,
                actingUserId: userId,
                deviceType,
            }, ev.date);
        }
    }

    return c.body(null, 200);
});

export default evRoutes;
