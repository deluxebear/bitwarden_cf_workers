/**
 * 自部署系统管理员入口。
 *
 * 对齐官方 self-hosted System Administrator Portal 的服务器级账号管理语义：
 * 组织成员列表只管理组织 membership；这里管理服务器上的注册账号。
 */

import { Hono, type Context } from 'hono';
import { and, asc, eq, inArray, or } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';

import { organizations, organizationUsers, users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import { deleteUserAccountData } from '../services/claimed-accounts';
import { validateUserCanJoinOrganization } from '../services/policy-requirements';
import { pushLogOut, pushSyncUser } from '../services/push-notification';
import type { Bindings, Variables } from '../types';
import { PushType } from '../types/push-notification';

type D1Db = ReturnType<typeof drizzle>;
type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;
type SystemAdminEnv = Pick<Bindings, 'SYSTEM_ADMIN_EMAILS' | 'ADMIN_EMAILS'>;

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;
const ORG_USER_STATUS_ACCEPTED = 1;
const ORG_USER_STATUS_CONFIRMED = 2;
const ORG_USER_STATUS_REVOKED = -1;
const ORG_USER_STATUS_REVOKED_LEGACY = 3;
const ORG_USER_TYPE_USER = 2;

const adminRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();
adminRoutes.use('/*', authMiddleware);
adminRoutes.use('/*', async (c, next) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const email = c.get('email');

    if (!await isSystemAdmin(db, c.env, userId, email)) {
        return c.json({ message: 'Forbidden', object: 'error' }, 403);
    }

    await next();
});

export function parseSystemAdminEmails(value: string | null | undefined): Set<string> {
    return new Set((value ?? '')
        .split(',')
        .map((email) => email.trim().toLowerCase())
        .filter(Boolean));
}

function getConfiguredSystemAdminEmails(env: SystemAdminEnv): Set<string> {
    const configured = parseSystemAdminEmails(env.SYSTEM_ADMIN_EMAILS);
    for (const email of parseSystemAdminEmails(env.ADMIN_EMAILS)) {
        configured.add(email);
    }
    return configured;
}

export async function isSystemAdmin(
    db: D1Db,
    env: SystemAdminEnv,
    userId: string,
    email: string,
): Promise<boolean> {
    const configuredEmails = getConfiguredSystemAdminEmails(env);
    if (configuredEmails.size > 0) {
        return configuredEmails.has(email.trim().toLowerCase());
    }

    const firstUser = await db.select({ id: users.id })
        .from(users)
        .orderBy(asc(users.creationDate), asc(users.id))
        .limit(1)
        .get();

    return firstUser?.id === userId;
}

function parseLimit(value: string | undefined): number {
    if (!value) return DEFAULT_LIMIT;
    const parsed = Number.parseInt(value, 10);
    if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_LIMIT;
    return Math.min(parsed, MAX_LIMIT);
}

function hasTwoFactorEnabled(twoFactorProviders: string | null): boolean {
    if (!twoFactorProviders) return false;
    try {
        const parsed = JSON.parse(twoFactorProviders);
        return parsed != null && typeof parsed === 'object' && Object.keys(parsed).length > 0;
    } catch {
        return false;
    }
}

type ListedUser = {
    id: string;
    name: string | null;
    email: string;
    emailVerified: boolean;
    premium: boolean;
    forcePasswordReset: boolean;
    twoFactorEnabled: boolean;
    creationDate: string;
    revisionDate: string;
    lastEmailChangeDate: string | null;
    organizationCount: number;
    organizations: {
        id: string;
        name: string | null;
        organizationUserId: string;
        email: string;
        status: number;
        type: number;
    }[];
};

async function listRegisteredUsers(db: D1Db, query: string, limit: number): Promise<ListedUser[]> {
    const normalizedQuery = query.trim().toLowerCase();
    const rows = await db.select({
        id: users.id,
        name: users.name,
        email: users.email,
        emailVerified: users.emailVerified,
        premium: users.premium,
        forcePasswordReset: users.forcePasswordReset,
        twoFactorProviders: users.twoFactorProviders,
        creationDate: users.creationDate,
        revisionDate: users.revisionDate,
        lastEmailChangeDate: users.lastEmailChangeDate,
    })
        .from(users)
        .orderBy(asc(users.creationDate), asc(users.email))
        .all();

    const filteredRows = rows
        .filter((row) => {
            if (!normalizedQuery) return true;
            return row.id.toLowerCase().includes(normalizedQuery) ||
                row.email.toLowerCase().includes(normalizedQuery) ||
                (row.name?.toLowerCase().includes(normalizedQuery) ?? false);
        })
        .slice(0, limit);

    if (filteredRows.length === 0) return [];

    const userIds = filteredRows.map((row) => row.id);
    const membershipRows = await db.select({
        userId: organizationUsers.userId,
        organizationId: organizationUsers.organizationId,
        organizationName: organizations.name,
        organizationUserId: organizationUsers.id,
        email: organizationUsers.email,
        status: organizationUsers.status,
        type: organizationUsers.type,
    })
        .from(organizationUsers)
        .leftJoin(organizations, eq(organizations.id, organizationUsers.organizationId))
        .where(and(
            inArray(organizationUsers.userId, userIds),
        ))
        .all();

    const membershipsByUser = new Map<string, ListedUser['organizations']>();
    for (const membership of membershipRows) {
        if (!membership.userId) continue;
        const list = membershipsByUser.get(membership.userId) ?? [];
        list.push({
            id: membership.organizationId,
            name: membership.organizationName,
            organizationUserId: membership.organizationUserId,
            email: membership.email,
            status: membership.status,
            type: membership.type,
        });
        membershipsByUser.set(membership.userId, list);
    }

    return filteredRows.map((row) => {
        const orgs = membershipsByUser.get(row.id) ?? [];
        return {
            id: row.id,
            name: row.name,
            email: row.email,
            emailVerified: row.emailVerified,
            premium: row.premium,
            forcePasswordReset: row.forcePasswordReset,
            twoFactorEnabled: hasTwoFactorEnabled(row.twoFactorProviders),
            creationDate: row.creationDate,
            revisionDate: row.revisionDate,
            lastEmailChangeDate: row.lastEmailChangeDate,
            organizationCount: orgs.length,
            organizations: orgs,
        };
    });
}

async function getRegisteredUserById(db: D1Db, userId: string): Promise<ListedUser | null> {
    const data = await listRegisteredUsers(db, userId, MAX_LIMIT);
    return data.find((candidate) => candidate.id === userId) ?? null;
}

async function deleteRegisteredUser(c: AppContext) {
    const db = drizzle(c.env.DB);
    const actingUserId = c.get('userId');
    const targetUserId = c.req.param('id');

    if (targetUserId === actingUserId) {
        throw new BadRequestError('System administrators cannot delete their own account from this endpoint.');
    }

    const target = await db.select({ id: users.id })
        .from(users)
        .where(eq(users.id, targetUserId))
        .get();
    if (!target) throw new NotFoundError('User not found.');

    await deleteUserAccountData(db, c.env, target.id);
    c.executionCtx.waitUntil(pushLogOut(c.env, target.id, null));

    return c.body(null, 204);
}

async function bumpUserRevisionDate(db: D1Db, userId: string, now?: string): Promise<void> {
    await db.update(users)
        .set({ accountRevisionDate: now ?? new Date().toISOString() })
        .where(eq(users.id, userId));
}

async function getTargetUserAndOrganization(db: D1Db, userId: string, orgId: string) {
    const targetUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!targetUser) throw new NotFoundError('User not found.');

    const organization = await db.select({ id: organizations.id })
        .from(organizations)
        .where(eq(organizations.id, orgId))
        .get();
    if (!organization) throw new NotFoundError('Organization not found.');

    return { targetUser, organization };
}

async function findOrganizationMembership(db: D1Db, userId: string, orgId: string, email: string) {
    return db.select()
        .from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            or(
                eq(organizationUsers.userId, userId),
                eq(organizationUsers.email, email.trim().toLowerCase()),
            ),
        ))
        .get();
}

function isRevokedOrganizationUserStatus(status: number): boolean {
    return status === ORG_USER_STATUS_REVOKED || status === ORG_USER_STATUS_REVOKED_LEGACY;
}

async function addRegisteredUserToOrganization(c: AppContext) {
    const db = drizzle(c.env.DB);
    const targetUserId = c.req.param('id');
    const orgId = c.req.param('orgId');
    const { targetUser } = await getTargetUserAndOrganization(db, targetUserId, orgId);

    await validateUserCanJoinOrganization(db, targetUser, orgId);

    const now = new Date().toISOString();
    const existingMembership = await findOrganizationMembership(db, targetUser.id, orgId, targetUser.email);

    if (existingMembership) {
        const restoreStatus = existingMembership.key ? ORG_USER_STATUS_CONFIRMED : ORG_USER_STATUS_ACCEPTED;
        await db.update(organizationUsers).set({
            userId: targetUser.id,
            email: targetUser.email.trim().toLowerCase(),
            status: isRevokedOrganizationUserStatus(existingMembership.status)
                ? restoreStatus
                : existingMembership.status,
            revisionDate: now,
        }).where(eq(organizationUsers.id, existingMembership.id));
    } else {
        await db.insert(organizationUsers).values({
            id: generateUuid(),
            organizationId: orgId,
            userId: targetUser.id,
            email: targetUser.email.trim().toLowerCase(),
            status: ORG_USER_STATUS_ACCEPTED,
            type: ORG_USER_TYPE_USER,
            creationDate: now,
            revisionDate: now,
        });
    }

    await bumpUserRevisionDate(db, targetUser.id, now);
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, targetUser.id, null));

    const user = await getRegisteredUserById(db, targetUser.id);
    return c.json({ ...user, object: 'systemUser' });
}

async function revokeRegisteredUserOrganizationAccess(c: AppContext) {
    const db = drizzle(c.env.DB);
    const actingUserId = c.get('userId');
    const targetUserId = c.req.param('id');
    const orgId = c.req.param('orgId');

    if (targetUserId === actingUserId) {
        throw new BadRequestError('System administrators cannot revoke their own organization access from this endpoint.');
    }

    const { targetUser } = await getTargetUserAndOrganization(db, targetUserId, orgId);
    const membership = await findOrganizationMembership(db, targetUser.id, orgId, targetUser.email);
    if (!membership) throw new NotFoundError('Member not found.');

    if (!isRevokedOrganizationUserStatus(membership.status)) {
        const now = new Date().toISOString();
        await db.update(organizationUsers).set({
            status: ORG_USER_STATUS_REVOKED,
            revisionDate: now,
        }).where(eq(organizationUsers.id, membership.id));

        await bumpUserRevisionDate(db, targetUser.id, now);
        c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, targetUser.id, null));
    }

    const user = await getRegisteredUserById(db, targetUser.id);
    return c.json({ ...user, object: 'systemUser' });
}

/**
 * GET /admin/status
 * 返回当前登录用户是否具备服务器级系统管理员权限。
 */
adminRoutes.get('/status', async (c) => {
    return c.json({
        object: 'systemAdminStatus',
        enabled: true,
        userId: c.get('userId'),
        email: c.get('email'),
    });
});

/**
 * GET /admin/users?q=&limit=
 * 列出服务器上已注册账号，包括已经不属于任何组织的账号。
 */
adminRoutes.get('/users', async (c) => {
    const db = drizzle(c.env.DB);
    const limit = parseLimit(c.req.query('limit'));
    const query = c.req.query('q') ?? '';
    const data = await listRegisteredUsers(db, query, limit);

    return c.json({
        object: 'list',
        data,
        continuationToken: null,
    });
});

/**
 * GET /admin/users/:id
 */
adminRoutes.get('/users/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.req.param('id');
    const user = await getRegisteredUserById(db, userId);
    if (!user) throw new NotFoundError('User not found.');

    return c.json({ ...user, object: 'systemUser' });
});

/**
 * DELETE /admin/users/:id
 * 完整删除服务器注册账号。
 */
adminRoutes.delete('/users/:id', async (c) => {
    return deleteRegisteredUser(c);
});

/**
 * POST /admin/users/:id/delete
 * 兼容无法发 DELETE 的客户端。
 */
adminRoutes.post('/users/:id/delete', async (c) => {
    return deleteRegisteredUser(c);
});

/**
 * POST /admin/users/:id/organizations/:orgId
 * 将服务器上已注册账号加入指定组织。由于服务器没有明文组织密钥，新建 membership
 * 使用 Accepted 状态，让组织成员页的既有确认流程负责生成用户专属组织密钥。
 */
adminRoutes.post('/users/:id/organizations/:orgId', async (c) => {
    return addRegisteredUserToOrganization(c);
});

/**
 * PUT /admin/users/:id/organizations/:orgId/revoke
 * 撤销服务器用户在指定组织中的访问权限，但保留服务器账号。
 */
adminRoutes.put('/users/:id/organizations/:orgId/revoke', async (c) => {
    return revokeRegisteredUserOrganizationAccess(c);
});

adminRoutes.post('/users/:id/organizations/:orgId/revoke', async (c) => {
    return revokeRegisteredUserOrganizationAccess(c);
});

export default adminRoutes;
