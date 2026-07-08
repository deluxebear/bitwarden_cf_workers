/**
 * Bitwarden Workers - Devices 路由
 * 对应原始项目 Api/Controllers/DevicesController.cs
 * 处理：设备 CRUD、trusted-device key、push token、Web Push auth。
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, inArray } from 'drizzle-orm';
import { users, devices, refreshTokens } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid, verifyPassword } from '../services/crypto';
import type { Bindings, Variables } from '../types';

const devicesRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type DeviceRow = typeof devices.$inferSelect;

type DeviceRequestBody = {
    type?: number;
    name?: string;
    identifier?: string;
    pushToken?: string | null;
};

type DeviceKeysRequestBody = {
    encryptedUserKey?: string | null;
    encryptedPublicKey?: string | null;
    encryptedPrivateKey?: string | null;
};

type UpdateDevicesTrustRequestBody = {
    masterPasswordHash?: string | null;
    secret?: string | null;
    currentDevice?: DeviceKeysRequestBody | null;
    otherDevices?: Array<DeviceKeysRequestBody & { deviceId?: string | null }> | null;
};

type WebPushAuthRequestBody = {
    endpoint?: string;
    p256dh?: string;
    auth?: string;
};

function toDeviceResponse(device: DeviceRow) {
    const isTrusted = !!device.encryptedUserKey && !!device.encryptedPublicKey && !!device.encryptedPrivateKey;
    return {
        id: device.id,
        userId: device.userId,
        name: device.name,
        type: device.type,
        identifier: device.identifier,
        creationDate: device.creationDate,
        revisionDate: device.revisionDate,
        lastActivityDate: device.revisionDate,
        isTrusted,
        encryptedUserKey: device.encryptedUserKey,
        encryptedPublicKey: device.encryptedPublicKey,
        devicePendingAuthRequest: null,
        object: 'device',
    };
}

function toProtectedDeviceResponse(device: DeviceRow) {
    return {
        id: device.id,
        name: device.name,
        type: device.type,
        identifier: device.identifier,
        creationDate: device.creationDate,
        encryptedUserKey: device.encryptedUserKey,
        encryptedPublicKey: device.encryptedPublicKey,
        object: 'protectedDevice',
    };
}

async function getDeviceByIdForUser(db: ReturnType<typeof drizzle>, userId: string, id: string) {
    const device = await db.select().from(devices)
        .where(and(eq(devices.id, id), eq(devices.userId, userId)))
        .get();
    if (!device) throw new NotFoundError('Device not found.');
    return device;
}

async function getDeviceByIdentifierForUser(db: ReturnType<typeof drizzle>, userId: string, identifier: string) {
    const device = await db.select().from(devices)
        .where(and(eq(devices.identifier, identifier), eq(devices.userId, userId)))
        .get();
    if (!device) throw new NotFoundError('Device not found.');
    return device;
}

function decodeKnownDeviceEmail(raw: string) {
    if (!raw) return '';
    try {
        const base64 = decodeURIComponent(raw).replace(/-/g, '+').replace(/_/g, '/');
        return atob(base64 + '='.repeat((4 - base64.length % 4) % 4)).toLowerCase().trim();
    } catch {
        try {
            return atob(decodeURIComponent(raw)).toLowerCase().trim();
        } catch {
            return raw.toLowerCase().trim();
        }
    }
}

async function assertSecretIfProvided(c: any, userId: string, body: UpdateDevicesTrustRequestBody) {
    const masterPasswordHash = body.masterPasswordHash || body.secret;
    if (!masterPasswordHash) return;

    const db = drizzle(c.env.DB);
    const user = await db.select({ masterPassword: users.masterPassword })
        .from(users)
        .where(eq(users.id, userId))
        .get();
    if (!user || !await verifyPassword(masterPasswordHash, user.masterPassword || '')) {
        throw new BadRequestError('User verification failed.');
    }
}

/**
 * GET /api/devices/knowndevice
 * 匿名检查设备 identifier 是否属于指定 email。
 */
devicesRoute.get('/knowndevice', async (c) => {
    const db = drizzle(c.env.DB);

    let email = (c.req.query('email') || '').toLowerCase().trim();
    if (!email) {
        email = decodeKnownDeviceEmail(c.req.header('X-Request-Email') || '');
    }
    const deviceIdentifier = c.req.header('X-Device-Identifier') || c.req.query('identifier') || '';
    if (!email || !deviceIdentifier) return c.json(false);

    const user = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (!user) return c.json(false);

    const device = await db.select({ id: devices.id }).from(devices)
        .where(and(
            eq(devices.userId, user.id),
            eq(devices.identifier, deviceIdentifier),
            eq(devices.active, true),
        ))
        .get();

    return c.json(!!device);
});

/**
 * GET /api/devices/knowndevice/:email/:identifier
 * 旧路径兼容。
 */
devicesRoute.get('/knowndevice/:email/:identifier', async (c) => {
    const db = drizzle(c.env.DB);
    const email = decodeKnownDeviceEmail(c.req.param('email'));
    const identifier = c.req.param('identifier');
    if (!email || !identifier) throw new BadRequestError('Please provide an email and device identifier');

    const user = await db.select({ id: users.id }).from(users).where(eq(users.email, email)).get();
    if (!user) return c.json(false);

    const device = await db.select({ id: devices.id }).from(devices)
        .where(and(eq(devices.userId, user.id), eq(devices.identifier, identifier), eq(devices.active, true)))
        .get();
    return c.json(!!device);
});

/**
 * PUT/POST /api/devices/identifier/:identifier/clear-token
 * 上游允许匿名清除 token，用于 push token 失效回调。
 */
async function clearTokenByIdentifier(c: any) {
    const db = drizzle(c.env.DB);
    const identifier = c.req.param('identifier');
    const existing = await db.select({ id: devices.id }).from(devices)
        .where(eq(devices.identifier, identifier))
        .get();
    if (!existing) throw new NotFoundError('Device not found.');

    await db.update(devices)
        .set({ pushToken: null, revisionDate: new Date().toISOString() })
        .where(eq(devices.identifier, identifier));
    return c.json({});
}

devicesRoute.put('/identifier/:identifier/clear-token', clearTokenByIdentifier);
devicesRoute.post('/identifier/:identifier/clear-token', clearTokenByIdentifier);

devicesRoute.use('/*', authMiddleware);

/**
 * GET /api/devices
 */
devicesRoute.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const list = await db.select().from(devices).where(eq(devices.userId, userId)).all();
    return c.json({
        data: list.filter((device) => device.active).map(toDeviceResponse),
        continuationToken: null,
        object: 'list',
    });
});

/**
 * POST /api/devices
 */
devicesRoute.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as DeviceRequestBody;
    if (body.type === undefined || !body.name || !body.identifier) {
        throw new BadRequestError('Type, name, and identifier are required.');
    }

    const now = new Date().toISOString();
    const id = generateUuid();
    await db.insert(devices).values({
        id,
        userId,
        name: body.name,
        type: body.type,
        identifier: body.identifier,
        pushToken: body.pushToken ?? null,
        active: true,
        creationDate: now,
        revisionDate: now,
    });

    const created = await db.select().from(devices).where(eq(devices.id, id)).get();
    return c.json(toDeviceResponse(created!));
});

/**
 * GET /api/devices/identifier/:identifier
 */
devicesRoute.get('/identifier/:identifier', async (c) => {
    const db = drizzle(c.env.DB);
    const device = await getDeviceByIdentifierForUser(db, c.get('userId'), c.req.param('identifier'));
    return c.json(toDeviceResponse(device));
});

/**
 * PUT/POST /api/devices/:identifier/keys
 */
async function updateDeviceKeys(c: any) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');
    const body = await c.req.json().catch(() => ({})) as DeviceKeysRequestBody;
    if (!body.encryptedUserKey || !body.encryptedPublicKey || !body.encryptedPrivateKey) {
        throw new BadRequestError('Encrypted device keys are required.');
    }

    const device = await getDeviceByIdentifierForUser(db, userId, identifier);
    await db.update(devices).set({
        encryptedUserKey: body.encryptedUserKey,
        encryptedPublicKey: body.encryptedPublicKey,
        encryptedPrivateKey: body.encryptedPrivateKey,
        revisionDate: new Date().toISOString(),
    }).where(eq(devices.id, device.id));

    const updated = await db.select().from(devices).where(eq(devices.id, device.id)).get();
    return c.json(toDeviceResponse(updated!));
}

devicesRoute.put('/:identifier/keys', updateDeviceKeys);
devicesRoute.post('/:identifier/keys', updateDeviceKeys);

/**
 * POST /api/devices/:identifier/retrieve-keys
 */
devicesRoute.post('/:identifier/retrieve-keys', async (c) => {
    const db = drizzle(c.env.DB);
    const device = await getDeviceByIdentifierForUser(db, c.get('userId'), c.req.param('identifier'));
    return c.json(toProtectedDeviceResponse(device));
});

/**
 * POST /api/devices/update-trust
 */
devicesRoute.post('/update-trust', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as UpdateDevicesTrustRequestBody;
    await assertSecretIfProvided(c, userId, body);

    const now = new Date().toISOString();
    const currentIdentifier = c.req.header('Device-Identifier') ||
        c.req.header('X-Device-Identifier') ||
        c.get('jwtPayload')?.device;

    if (body.currentDevice && currentIdentifier) {
        const current = await db.select().from(devices)
            .where(and(eq(devices.userId, userId), eq(devices.identifier, currentIdentifier)))
            .get();
        if (current) {
            await db.update(devices).set({
                encryptedUserKey: body.currentDevice.encryptedUserKey ?? current.encryptedUserKey,
                encryptedPublicKey: body.currentDevice.encryptedPublicKey ?? current.encryptedPublicKey,
                revisionDate: now,
            }).where(eq(devices.id, current.id));
        }
    }

    for (const other of body.otherDevices ?? []) {
        if (!other.deviceId) continue;
        await db.update(devices).set({
            encryptedUserKey: other.encryptedUserKey ?? null,
            encryptedPublicKey: other.encryptedPublicKey ?? null,
            revisionDate: now,
        }).where(and(eq(devices.id, other.deviceId), eq(devices.userId, userId)));
    }

    return c.body(null, 200);
});

/**
 * POST /api/devices/untrust
 */
devicesRoute.post('/untrust', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as { devices?: string[] };
    const ids = Array.isArray(body.devices) ? body.devices : [];
    if (ids.length === 0) return c.body(null, 200);

    await db.update(devices).set({
        encryptedUserKey: null,
        encryptedPublicKey: null,
        encryptedPrivateKey: null,
        revisionDate: new Date().toISOString(),
    }).where(and(eq(devices.userId, userId), inArray(devices.id, ids)));

    return c.body(null, 200);
});

/**
 * POST /api/devices/lost-trust
 */
devicesRoute.post('/lost-trust', (c) => {
    console.error('[devices] trusted device lost local keys', {
        userId: c.get('userId'),
        deviceIdentifier: c.req.header('Device-Identifier') || c.req.header('X-Device-Identifier') || null,
        deviceType: c.req.header('Device-Type') || null,
    });
    return c.body(null, 200);
});

/**
 * PUT/POST /api/devices/identifier/:identifier/token
 */
async function updateToken(c: any) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');
    const body = await c.req.json().catch(() => ({})) as { pushToken?: string | null };
    if (!body.pushToken) throw new BadRequestError('Push token is required.');

    const device = await getDeviceByIdentifierForUser(db, userId, identifier);
    await db.update(devices)
        .set({ pushToken: body.pushToken, revisionDate: new Date().toISOString() })
        .where(eq(devices.id, device.id));
    return c.json({});
}

devicesRoute.put('/identifier/:identifier/token', updateToken);
devicesRoute.post('/identifier/:identifier/token', updateToken);

/**
 * PUT/POST /api/devices/identifier/:identifier/web-push-auth
 */
async function updateWebPushAuth(c: any) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const identifier = c.req.param('identifier');
    const body = await c.req.json().catch(() => ({})) as WebPushAuthRequestBody;
    if (!body.endpoint || !body.p256dh || !body.auth) {
        throw new BadRequestError('Web Push endpoint, p256dh, and auth are required.');
    }

    const device = await getDeviceByIdentifierForUser(db, userId, identifier);
    await db.update(devices).set({
        webPushAuth: JSON.stringify({
            endpoint: body.endpoint,
            p256dh: body.p256dh,
            auth: body.auth,
            organizationIds: [],
        }),
        revisionDate: new Date().toISOString(),
    }).where(eq(devices.id, device.id));

    return c.body(null, 200);
}

devicesRoute.put('/identifier/:identifier/web-push-auth', updateWebPushAuth);
devicesRoute.post('/identifier/:identifier/web-push-auth', updateWebPushAuth);

/**
 * GET /api/devices/:id
 */
devicesRoute.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const device = await getDeviceByIdForUser(db, c.get('userId'), c.req.param('id'));
    return c.json(toDeviceResponse(device));
});

/**
 * PUT/POST /api/devices/:id
 */
async function updateDeviceById(c: any) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const id = c.req.param('id');
    const body = await c.req.json().catch(() => ({})) as DeviceRequestBody;
    const device = await getDeviceByIdForUser(db, userId, id);

    await db.update(devices).set({
        name: body.name ?? device.name,
        type: body.type ?? device.type,
        identifier: body.identifier ?? device.identifier,
        pushToken: body.pushToken !== undefined ? body.pushToken : device.pushToken,
        active: true,
        revisionDate: new Date().toISOString(),
    }).where(eq(devices.id, id));

    const updated = await db.select().from(devices).where(eq(devices.id, id)).get();
    return c.json(toDeviceResponse(updated!));
}

devicesRoute.put('/:id', updateDeviceById);
devicesRoute.post('/:id', updateDeviceById);

/**
 * DELETE /api/devices/:id and POST /api/devices/:id/deactivate
 */
async function deactivateDevice(c: any) {
    const db = drizzle(c.env.DB);
    const device = await getDeviceByIdForUser(db, c.get('userId'), c.req.param('id'));
    await db.update(devices).set({
        active: false,
        pushToken: null,
        revisionDate: new Date().toISOString(),
    }).where(eq(devices.id, device.id));
    await db.delete(refreshTokens).where(eq(refreshTokens.deviceId, device.id));
    return c.body(null, 204);
}

devicesRoute.delete('/:id', deactivateDevice);
devicesRoute.post('/:id/deactivate', deactivateDevice);

export default devicesRoute;
