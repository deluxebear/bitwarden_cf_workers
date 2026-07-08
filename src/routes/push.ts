/**
 * Bitwarden Workers - Push relay 路由
 * 对应 Api/Platform/Push/Controllers/PushController.cs 的本地化实现。
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, inArray } from 'drizzle-orm';
import { devices, organizationUsers } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { pushNotification } from '../services/push-notification';
import { PushType } from '../types/push-notification';
import type { Bindings, Variables } from '../types';

const pushRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type DeviceRow = typeof devices.$inferSelect;

type PushRegistrationRequest = {
    deviceId?: string;
    id?: string;
    pushToken?: string;
    userId?: string;
    type?: number;
    identifier?: string;
    organizationIds?: string[];
};

type PushDeviceRequest = {
    id?: string;
    deviceId?: string;
    identifier?: string;
};

type PushUpdateRequest = {
    devices?: Array<{ id?: string; deviceId?: string; identifier?: string }>;
    organizationId?: string;
};

type PushSendRequest = {
    userId?: string;
    organizationId?: string;
    deviceId?: string;
    identifier?: string;
    type?: number;
    payload?: unknown;
    clientType?: number | null;
};

type WebPushAuth = {
    endpoint?: string;
    p256dh?: string;
    auth?: string;
    organizationIds?: string[];
};

pushRoutes.use('/*', authMiddleware);

function parseWebPushAuth(raw: string | null): WebPushAuth {
    if (!raw) return { organizationIds: [] };
    try {
        const parsed = JSON.parse(raw) as WebPushAuth;
        return {
            ...parsed,
            organizationIds: Array.isArray(parsed.organizationIds) ? parsed.organizationIds : [],
        };
    } catch {
        return { organizationIds: [] };
    }
}

function deviceKey(input: { id?: string; deviceId?: string; identifier?: string } | null | undefined) {
    return input?.id || input?.deviceId || input?.identifier || '';
}

async function getDeviceForCurrentUser(
    db: ReturnType<typeof drizzle>,
    userId: string,
    key: string,
): Promise<DeviceRow> {
    if (!key) throw new BadRequestError('Device id is required.');

    const byId = await db.select().from(devices)
        .where(and(eq(devices.id, key), eq(devices.userId, userId)))
        .get();
    if (byId) return byId;

    const byIdentifier = await db.select().from(devices)
        .where(and(eq(devices.identifier, key), eq(devices.userId, userId)))
        .get();
    if (byIdentifier) return byIdentifier;

    throw new NotFoundError('Device not found.');
}

async function assertOrganizationMembership(
    db: ReturnType<typeof drizzle>,
    userId: string,
    organizationId: string,
) {
    const member = await db.select({ id: organizationUsers.id }).from(organizationUsers)
        .where(and(
            eq(organizationUsers.userId, userId),
            eq(organizationUsers.organizationId, organizationId),
        ))
        .get();
    if (!member) throw new BadRequestError('User is not a member of the organization.');
}

async function updateDeviceOrganizations(
    db: ReturnType<typeof drizzle>,
    userId: string,
    body: PushUpdateRequest,
    mode: 'add' | 'delete',
) {
    const organizationId = body.organizationId;
    if (!organizationId) throw new BadRequestError('OrganizationId is required.');
    await assertOrganizationMembership(db, userId, organizationId);

    const requestedDevices = Array.isArray(body.devices) ? body.devices : [];
    if (requestedDevices.length === 0) throw new BadRequestError('Devices are required.');

    const now = new Date().toISOString();
    for (const requested of requestedDevices) {
        const device = await getDeviceForCurrentUser(db, userId, deviceKey(requested));
        const auth = parseWebPushAuth(device.webPushAuth);
        const ids = new Set(auth.organizationIds || []);
        if (mode === 'add') {
            ids.add(organizationId);
        } else {
            ids.delete(organizationId);
        }

        await db.update(devices).set({
            webPushAuth: JSON.stringify({ ...auth, organizationIds: [...ids] }),
            revisionDate: now,
        }).where(eq(devices.id, device.id));
    }
}

/**
 * POST /api/push/register
 */
pushRoutes.post('/register', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as PushRegistrationRequest;

    if (body.userId && body.userId !== userId) {
        throw new BadRequestError('UserId does not match current user.');
    }
    if (!body.pushToken) throw new BadRequestError('PushToken is required.');

    const key = body.deviceId || body.id || body.identifier || c.get('jwtPayload')?.device || '';
    const device = await getDeviceForCurrentUser(db, userId, key);
    const now = new Date().toISOString();
    const auth = parseWebPushAuth(device.webPushAuth);
    const organizationIds = Array.isArray(body.organizationIds) ? body.organizationIds : auth.organizationIds;

    await db.update(devices).set({
        pushToken: body.pushToken,
        type: body.type ?? device.type,
        webPushAuth: JSON.stringify({ ...auth, organizationIds }),
        revisionDate: now,
    }).where(eq(devices.id, device.id));

    return c.body(null, 200);
});

/**
 * POST /api/push/delete
 */
pushRoutes.post('/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as PushDeviceRequest;
    const key = body.id || body.deviceId || body.identifier || c.get('jwtPayload')?.device || '';
    const device = await getDeviceForCurrentUser(db, userId, key);

    await db.update(devices).set({
        pushToken: null,
        revisionDate: new Date().toISOString(),
    }).where(eq(devices.id, device.id));

    return c.body(null, 200);
});

/**
 * PUT /api/push/add-organization
 */
pushRoutes.put('/add-organization', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json().catch(() => ({})) as PushUpdateRequest;
    await updateDeviceOrganizations(db, c.get('userId'), body, 'add');
    return c.body(null, 200);
});

/**
 * PUT /api/push/delete-organization
 */
pushRoutes.put('/delete-organization', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json().catch(() => ({})) as PushUpdateRequest;
    await updateDeviceOrganizations(db, c.get('userId'), body, 'delete');
    return c.body(null, 200);
});

/**
 * POST /api/push/send
 */
pushRoutes.post('/send', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as PushSendRequest;
    const type = body.type ?? PushType.Notification;
    const contextId = body.deviceId || body.identifier || c.get('jwtPayload')?.device || null;

    if (body.userId) {
        if (body.userId !== userId) {
            throw new BadRequestError('Cannot send push notifications for another user.');
        }
        c.executionCtx.waitUntil(pushNotification(
            c.env,
            'user',
            userId,
            type,
            body.payload ?? {},
            contextId,
        ));
        return c.body(null, 200);
    }

    if (body.organizationId) {
        await assertOrganizationMembership(db, userId, body.organizationId);
        c.executionCtx.waitUntil(pushNotification(
            c.env,
            'organization',
            body.organizationId,
            type,
            body.payload ?? {},
            contextId,
        ));
        return c.body(null, 200);
    }

    const deviceIds = body.deviceId ? [body.deviceId] : [c.get('jwtPayload')?.device].filter(Boolean) as string[];
    if (deviceIds.length === 0) throw new BadRequestError('UserId or OrganizationId is required.');

    const owned = await db.select({ userId: devices.userId }).from(devices)
        .where(and(inArray(devices.id, deviceIds), eq(devices.userId, userId)))
        .all();
    if (owned.length === 0) throw new NotFoundError('Device not found.');

    c.executionCtx.waitUntil(pushNotification(c.env, 'user', userId, type, body.payload ?? {}, contextId));
    return c.body(null, 200);
});

export default pushRoutes;
