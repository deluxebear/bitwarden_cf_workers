/**
 * Bitwarden Workers - Notification Center 路由
 * 对应 Api/NotificationCenter/Controllers/NotificationsController.cs。
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, inArray } from 'drizzle-orm';
import { notifications, organizationUsers, users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError, UnauthorizedError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import { pushNotification } from '../services/push-notification';
import { PushType } from '../types/push-notification';
import type { Bindings, Variables } from '../types';

const notificationsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();
export const notificationSendRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type NotificationRow = typeof notifications.$inferSelect;

type SendNotificationRequest = {
    userId?: string;
    userIds?: string[];
    organizationId?: string;
    global?: boolean;
    priority?: number;
    clientType?: number;
    title?: string | null;
    body?: string | null;
    taskId?: string | null;
    payload?: unknown;
};

notificationsRoutes.use('/*', authMiddleware);

function toNotificationResponse(row: NotificationRow) {
    return {
        id: row.id,
        priority: row.priority,
        title: row.title,
        body: row.body,
        date: row.revisionDate,
        taskId: row.taskId,
        readDate: row.readDate,
        deletedDate: row.deletedDate,
        object: 'notification',
    };
}

function toPushPayload(row: NotificationRow) {
    return {
        Id: row.id,
        Priority: row.priority,
        Global: row.global,
        ClientType: row.clientType,
        UserId: row.userId,
        OrganizationId: row.organizationId,
        InstallationId: null,
        TaskId: row.taskId,
        Title: row.title,
        Body: row.body,
        CreationDate: row.creationDate,
        RevisionDate: row.revisionDate,
        ReadDate: row.readDate,
        DeletedDate: row.deletedDate,
    };
}

function parseBooleanFilter(value: string | undefined): boolean | null {
    if (value === undefined || value === '') return null;
    const normalized = value.toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
    return null;
}

function positiveInteger(value: string | undefined, fallback: number): number {
    const parsed = Number.parseInt(value || '', 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function truncate(value: string | null | undefined, max: number): string | null {
    if (value === undefined || value === null) return null;
    return value.length > max ? value.slice(0, max) : value;
}

function clampNumber(value: unknown, fallback: number, min: number, max: number): number {
    const parsed = typeof value === 'number' ? value : Number(value);
    if (!Number.isFinite(parsed)) return fallback;
    return Math.min(Math.max(parsed, min), max);
}

function getInternalSendToken(c: { env: Bindings; req: { header(name: string): string | undefined } }) {
    const configured = c.env.NOTIFICATIONS_SEND_TOKEN;
    if (!configured) throw new NotFoundError('Not Found');

    const authorization = c.req.header('Authorization') || '';
    const bearer = authorization.toLowerCase().startsWith('bearer ')
        ? authorization.slice(7).trim()
        : '';
    const headerToken = c.req.header('X-Notification-Token') || '';
    if (bearer !== configured && headerToken !== configured) {
        throw new UnauthorizedError('Invalid notification send token.');
    }
}

async function getNotificationForUser(db: ReturnType<typeof drizzle>, userId: string, notificationId: string) {
    const row = await db.select().from(notifications)
        .where(and(eq(notifications.id, notificationId), eq(notifications.userId, userId)))
        .get();
    if (!row) throw new NotFoundError('Notification not found.');
    return row;
}

/**
 * GET /api/notifications
 */
notificationsRoutes.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const readFilter = parseBooleanFilter(c.req.query('readStatusFilter') ?? c.req.query('ReadStatusFilter'));
    const deletedFilter = parseBooleanFilter(c.req.query('deletedStatusFilter') ?? c.req.query('DeletedStatusFilter'));
    const pageSize = Math.min(Math.max(positiveInteger(c.req.query('pageSize') ?? c.req.query('PageSize'), 10), 10), 1000);
    const pageNumber = positiveInteger(c.req.query('continuationToken') ?? c.req.query('ContinuationToken'), 1);

    const rows = await db.select().from(notifications)
        .where(eq(notifications.userId, userId))
        .all();

    const filtered = rows.filter((row) => {
        if (readFilter === true && !row.readDate) return false;
        if (readFilter === false && row.readDate) return false;
        if (deletedFilter === true) return !!row.deletedDate;
        if (deletedFilter === false) return !row.deletedDate;
        return !row.deletedDate;
    }).sort((a, b) => b.revisionDate.localeCompare(a.revisionDate));

    const start = (pageNumber - 1) * pageSize;
    const page = filtered.slice(start, start + pageSize);
    const hasMore = start + pageSize < filtered.length;

    return c.json({
        data: page.map(toNotificationResponse),
        continuationToken: hasMore ? String(pageNumber + 1) : null,
        object: 'list',
    });
});

/**
 * PATCH /api/notifications/:id/read
 */
notificationsRoutes.patch('/:id/read', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');
    await getNotificationForUser(db, userId, id);

    const now = new Date().toISOString();
    await db.update(notifications).set({
        readDate: now,
        revisionDate: now,
    }).where(and(eq(notifications.id, id), eq(notifications.userId, userId)));

    const updated = await getNotificationForUser(db, userId, id);
    c.executionCtx.waitUntil(pushNotification(c.env, 'user', userId, PushType.NotificationStatus, toPushPayload(updated), null));
    return c.body(null, 200);
});

/**
 * PATCH /api/notifications/:id/delete
 */
notificationsRoutes.patch('/:id/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');
    await getNotificationForUser(db, userId, id);

    const now = new Date().toISOString();
    await db.update(notifications).set({
        deletedDate: now,
        revisionDate: now,
    }).where(and(eq(notifications.id, id), eq(notifications.userId, userId)));

    const updated = await getNotificationForUser(db, userId, id);
    c.executionCtx.waitUntil(pushNotification(c.env, 'user', userId, PushType.NotificationStatus, toPushPayload(updated), null));
    return c.body(null, 200);
});

/**
 * POST /send
 *
 * Notifications 服务内部投递入口。只有配置 NOTIFICATIONS_SEND_TOKEN 后才启用。
 */
notificationSendRoutes.post('/send', async (c) => {
    getInternalSendToken(c);

    const db = drizzle(c.env.DB);
    const body = await c.req.json().catch(() => ({})) as SendNotificationRequest;
    const payloadObject = body.payload && typeof body.payload === 'object'
        ? body.payload as Record<string, unknown>
        : {};

    let targetUserIds: string[] = [];
    if (body.global) {
        const allUsers = await db.select({ id: users.id }).from(users).all();
        targetUserIds = allUsers.map((user) => user.id);
    } else if (Array.isArray(body.userIds) && body.userIds.length > 0) {
        const requested = [...new Set(body.userIds.filter(Boolean))];
        if (requested.length > 0) {
            const existing = await db.select({ id: users.id }).from(users)
                .where(inArray(users.id, requested))
                .all();
            targetUserIds = existing.map((user) => user.id);
        }
    } else if (body.userId) {
        const existing = await db.select({ id: users.id }).from(users)
            .where(eq(users.id, body.userId))
            .get();
        targetUserIds = existing ? [existing.id] : [];
    } else if (body.organizationId) {
        const members = await db.select({ userId: organizationUsers.userId }).from(organizationUsers)
            .where(eq(organizationUsers.organizationId, body.organizationId))
            .all();
        targetUserIds = members.map((member) => member.userId).filter(Boolean) as string[];
    }

    if (targetUserIds.length === 0) {
        throw new BadRequestError('A user, organization, or global target is required.');
    }

    const now = new Date().toISOString();
    const priority = clampNumber(body.priority ?? payloadObject.priority, 0, 0, 4);
    const clientType = clampNumber(body.clientType ?? payloadObject.clientType, 0, 0, 5);
    const title = truncate(body.title ?? (typeof payloadObject.title === 'string' ? payloadObject.title : null), 256);
    const messageBody = truncate(body.body ?? (typeof payloadObject.body === 'string' ? payloadObject.body : null), 3000);
    const taskId = body.taskId ?? (typeof payloadObject.taskId === 'string' ? payloadObject.taskId : null);
    const data = body.payload === undefined ? null : JSON.stringify(body.payload);
    const created: NotificationRow[] = [];

    for (const targetUserId of targetUserIds) {
        const id = generateUuid();
        await db.insert(notifications).values({
            id,
            userId: targetUserId,
            organizationId: body.organizationId ?? null,
            priority,
            global: !!body.global,
            clientType,
            title,
            body: messageBody,
            taskId,
            data,
            creationDate: now,
            revisionDate: now,
        });

        const row = await db.select().from(notifications).where(eq(notifications.id, id)).get();
        if (row) created.push(row);
    }

    c.executionCtx.waitUntil(Promise.all(created.map((row) => (
        pushNotification(c.env, 'user', row.userId, PushType.Notification, toPushPayload(row), null)
    ))).then(() => undefined));

    return c.json({
        id: created[0]?.id ?? null,
        count: created.length,
        object: 'notificationSend',
    });
});

export default notificationsRoutes;
