/**
 * Organization Auth Requests routes.
 * 对应 OrganizationAuthRequestsController：管理员审批受信任设备请求。
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, sql } from 'drizzle-orm';
import { authRequests, organizationUsers, users } from '../db/schema';
import type { OrganizationUserRow } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { logEvent } from '../services/events';
import { pushAuthRequestResponse } from '../services/push-notification';
import { AuthRequestType, type Bindings, type Variables } from '../types';
import { getDeviceTypeFromRequest } from './events';

const organizationAuthRequests = new Hono<{ Bindings: Bindings; Variables: Variables }>();
organizationAuthRequests.use('/*', authMiddleware);

type D1Db = ReturnType<typeof drizzle>;
type OrganizationAuthContext = Context<{ Bindings: Bindings; Variables: Variables }>;

function parsePermissions(permissions: string | null): { manageResetPassword?: boolean } | null {
    if (!permissions) return null;
    try {
        return JSON.parse(permissions) as { manageResetPassword?: boolean };
    } catch {
        return null;
    }
}

function canManageResetPassword(orgUser: OrganizationUserRow): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true;
    return parsePermissions(orgUser.permissions)?.manageResetPassword === true;
}

async function requireManageResetPassword(db: D1Db, orgId: string, userId: string): Promise<OrganizationUserRow> {
    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
        .get();
    if (!orgUser || orgUser.status !== 2 || !canManageResetPassword(orgUser)) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    return orgUser;
}

function isAdminApprovalExpired(creationDate: string): boolean {
    return Date.now() - new Date(creationDate).getTime() > 7 * 24 * 60 * 60 * 1000;
}

function toPendingOrganizationAuthRequestResponse(row: {
    id: string;
    userId: string;
    organizationUserId: string;
    email: string;
    publicKey: string | null;
    requestDeviceIdentifier: string;
    requestDeviceType: number;
    requestIpAddress: string | null;
    creationDate: string;
}) {
    return {
        id: row.id,
        userId: row.userId,
        organizationUserId: row.organizationUserId,
        email: row.email,
        publicKey: row.publicKey,
        requestDeviceIdentifier: row.requestDeviceIdentifier,
        requestDeviceType: getDeviceTypeName(row.requestDeviceType),
        requestDeviceTypeValue: row.requestDeviceType,
        requestIpAddress: row.requestIpAddress ?? '',
        requestCountryName: null,
        creationDate: row.creationDate,
        object: 'pending-org-auth-request',
    };
}

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

async function getOrganizationAdminAuthRequest(db: D1Db, orgId: string, requestId: string) {
    return await db.select({
        id: authRequests.id,
        userId: authRequests.userId,
        organizationId: authRequests.organizationId,
        type: authRequests.type,
        publicKey: authRequests.publicKey,
        requestDeviceIdentifier: authRequests.requestDeviceIdentifier,
        requestDeviceType: authRequests.requestDeviceType,
        requestIpAddress: authRequests.requestIpAddress,
        approved: authRequests.approved,
        creationDate: authRequests.creationDate,
        responseDate: authRequests.responseDate,
        authenticationDate: authRequests.authenticationDate,
        organizationUserId: organizationUsers.id,
        email: users.email,
    })
        .from(authRequests)
        .innerJoin(organizationUsers, and(
            eq(organizationUsers.userId, authRequests.userId),
            eq(organizationUsers.organizationId, orgId),
        ))
        .innerJoin(users, eq(users.id, authRequests.userId))
        .where(and(
            eq(authRequests.id, requestId),
            eq(authRequests.organizationId, orgId),
            eq(authRequests.type, AuthRequestType.AdminApproval),
        ))
        .get();
}

async function updateOrganizationAuthRequest(
    c: OrganizationAuthContext,
    orgId: string,
    requestId: string,
    approved: boolean,
    key?: string | null,
) {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    await requireManageResetPassword(db, orgId, userId);

    const request = await getOrganizationAdminAuthRequest(db, orgId, requestId);
    if (!request) throw new NotFoundError('Auth request not found.');
    if (request.responseDate || request.authenticationDate || request.approved !== null) {
        throw new BadRequestError('Auth request has already been processed.');
    }
    if (isAdminApprovalExpired(request.creationDate)) {
        throw new NotFoundError('Auth request not found.');
    }
    if (approved && !key) {
        throw new BadRequestError('Encrypted user key is required when approving an auth request.');
    }

    const now = new Date().toISOString();
    await db.update(authRequests).set({
        approved,
        key: approved ? key ?? null : null,
        responseDate: now,
    }).where(eq(authRequests.id, requestId));

    await logEvent(c.env.DB, approved ? 1513 : 1514, {
        userId: request.userId,
        organizationId: orgId,
        organizationUserId: request.organizationUserId,
        actingUserId: userId,
        deviceType: getDeviceTypeFromRequest(c),
    }, now);

    if (approved) {
        c.executionCtx.waitUntil(pushAuthRequestResponse(c.env, requestId, request.userId));
    }
}

/**
 * GET /api/organizations/:id/auth-requests
 */
organizationAuthRequests.get('/:id/auth-requests', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await requireManageResetPassword(db, orgId, userId);

    const rows = await db.select({
        id: authRequests.id,
        userId: authRequests.userId,
        organizationUserId: organizationUsers.id,
        email: users.email,
        publicKey: authRequests.publicKey,
        requestDeviceIdentifier: authRequests.requestDeviceIdentifier,
        requestDeviceType: authRequests.requestDeviceType,
        requestIpAddress: authRequests.requestIpAddress,
        creationDate: authRequests.creationDate,
    })
        .from(authRequests)
        .innerJoin(organizationUsers, and(
            eq(organizationUsers.userId, authRequests.userId),
            eq(organizationUsers.organizationId, orgId),
        ))
        .innerJoin(users, eq(users.id, authRequests.userId))
        .where(and(
            eq(authRequests.organizationId, orgId),
            eq(authRequests.type, AuthRequestType.AdminApproval),
            sql`${authRequests.approved} IS NULL`,
            sql`${authRequests.responseDate} IS NULL`,
        ))
        .all();

    return c.json({
        data: rows
            .filter((row) => !isAdminApprovalExpired(row.creationDate))
            .map(toPendingOrganizationAuthRequestResponse),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/organizations/:id/auth-requests/:requestId
 */
organizationAuthRequests.post('/:id/auth-requests/:requestId', async (c) => {
    const orgId = c.req.param('id');
    const requestId = c.req.param('requestId');
    const body = await c.req.json<{
        requestApproved?: boolean;
        RequestApproved?: boolean;
        encryptedUserKey?: string;
        EncryptedUserKey?: string;
    }>();
    const approved = body.requestApproved ?? body.RequestApproved;
    if (approved == null) throw new BadRequestError('RequestApproved is required.');

    await updateOrganizationAuthRequest(
        c,
        orgId,
        requestId,
        approved,
        body.encryptedUserKey ?? body.EncryptedUserKey ?? null,
    );

    return c.body(null, 200);
});

/**
 * POST /api/organizations/:id/auth-requests
 * 批量 approve/deny。
 */
organizationAuthRequests.post('/:id/auth-requests', async (c) => {
    const orgId = c.req.param('id');
    const body = await c.req.json<Array<{ id?: string; Id?: string; key?: string; Key?: string; approved?: boolean; Approved?: boolean }>>();
    if (!Array.isArray(body)) throw new BadRequestError('Request body must be an array.');

    for (const item of body) {
        const requestId = item.id ?? item.Id;
        const approved = item.approved ?? item.Approved;
        if (!requestId || approved == null) {
            throw new BadRequestError('Each auth request update requires id and approved.');
        }
        await updateOrganizationAuthRequest(c, orgId, requestId, approved, item.key ?? item.Key ?? null);
    }

    return c.body(null, 200);
});

/**
 * POST /api/organizations/:id/auth-requests/deny
 */
organizationAuthRequests.post('/:id/auth-requests/deny', async (c) => {
    const orgId = c.req.param('id');
    const body = await c.req.json<{ ids?: string[]; Ids?: string[] }>();
    const ids = body.ids ?? body.Ids ?? [];
    if (!Array.isArray(ids) || ids.length === 0) {
        throw new BadRequestError('Ids are required.');
    }

    for (const requestId of ids) {
        await updateOrganizationAuthRequest(c, orgId, requestId, false, null);
    }

    return c.body(null, 200);
});

export default organizationAuthRequests;
