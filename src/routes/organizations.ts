/**
 * Bitwarden Workers - Organizations 路由
 * 处理组织的创建、更新、查询及成员管理
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, desc } from 'drizzle-orm';
import { organizations, organizationUsers, users, events, collections } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { logEvent } from '../services/events';
import { toEventResponse } from './events';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import type { Bindings, Variables } from '../types';

const orgs = new Hono<{ Bindings: Bindings; Variables: Variables }>();
orgs.use('/*', authMiddleware);

/**
 * 辅助：验证组织权限
 */
async function getOrgUser(db: any, orgId: string, userId: string) {
    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId))).get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    return orgUser;
}

/**
 * POST /api/organizations
 * 创建新组织
 */
orgs.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ name: string; billingEmail: string; key: string; planType: number }>();

    if (!body.name || !body.billingEmail || !body.key) {
        throw new BadRequestError('Name, billingEmail, and key are required.');
    }

    const orgId = generateUuid();
    const now = new Date().toISOString();

    // 创建组织
    await db.insert(organizations).values({
        id: orgId,
        name: body.name,
        billingEmail: body.billingEmail,
        email: body.billingEmail,
        key: null, // 实际应用中，这里可能是可选的，或者是不同的 key
        planType: body.planType || 0,
        useTotp: false,
        useWebAuthn: false,
        enabled: true,
        creationDate: now,
        revisionDate: now,
    });

    // 将自己作为 Owner 加入
    const orgUserId = generateUuid();
    const currentUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!currentUser) throw new NotFoundError('Current user not found.');

    await db.insert(organizationUsers).values({
        id: orgUserId,
        organizationId: orgId,
        userId: userId,
        email: currentUser.email,
        key: body.key, // Owner 的组织密钥
        status: 2, // Confirmed
        type: 0, // Owner
        creationDate: now,
        revisionDate: now,
    });

    await logEvent(c.env.DB, 1600, { userId, organizationId: orgId });

    return c.json({
        id: orgId,
        name: body.name,
        billingEmail: body.billingEmail,
        planType: body.planType,
        enabled: true,
        useTotp: false,
        useWebAuthn: false,
        object: 'organization',
    });
});

/**
 * GET /api/organizations/:id
 * 获取组织详情
 */
orgs.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json({
        id: org.id,
        name: org.name,
        billingEmail: org.billingEmail,
        planType: org.planType,
        seats: org.seats,
        maxStorageGb: org.maxStorageGb,
        enabled: org.enabled,
        useTotp: org.useTotp,
        useWebAuthn: org.useWebAuthn,
        creationDate: org.creationDate,
        revisionDate: org.revisionDate,
        object: 'organization',
    });
});

/**
 * GET /api/organizations/:id/events
 * 获取组织的审计事件
 */
orgs.get('/:id/events', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const orgId = c.req.param('id');

    const orgUser = await db.select().from(organizationUsers).where(
        and(eq(organizationUsers.userId, userId), eq(organizationUsers.organizationId, orgId))
    ).get();

    if (!orgUser || (orgUser.type !== 0 && orgUser.type !== 1)) { // 0=Owner, 1=Admin
        throw new BadRequestError('Requires Owner or Admin privileges.');
    }

    const orgEvents = await db.select().from(events)
        .where(eq(events.organizationId, orgId))
        .orderBy(desc(events.date))
        .limit(50)
        .all();

    return c.json({
        data: orgEvents.map(toEventResponse),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/users
 * 获取组织成员列表
 */
orgs.get('/:id/users', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const usersList = await db.select().from(organizationUsers).where(eq(organizationUsers.organizationId, orgId)).all();

    return c.json({
        data: usersList.map(u => ({
            id: u.id,
            organizationId: u.organizationId,
            userId: u.userId,
            email: u.email,
            type: u.type,
            status: u.status,
            creationDate: u.creationDate,
            revisionDate: u.revisionDate,
            object: 'organizationUser',
        })),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/organizations/:id/users/invite
 * 邀请/添加组织成员
 */
orgs.post('/:id/users/invite', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    // 只有 Admin/Owner 才能邀请。简单起见，这里假设只要是组织成员即可，或者进一步检查 type。
    const inviter = await getOrgUser(db, orgId, userId);
    if (inviter.type !== 0 && inviter.type !== 1 && inviter.type !== 3) {
        throw new BadRequestError('Only owners, admins, or managers can invite users.');
    }

    const body = await c.req.json<{ emails: string[]; type: number }>();
    if (!body.emails || !body.emails.length) {
        throw new BadRequestError('Emails are required.');
    }

    const now = new Date().toISOString();

    for (const email of body.emails) {
        const targetEmail = email.toLowerCase().trim();
        const existingAppUser = await db.select().from(users).where(eq(users.email, targetEmail)).get();

        await db.insert(organizationUsers).values({
            id: generateUuid(),
            organizationId: orgId,
            userId: existingAppUser ? existingAppUser.id : null,
            email: targetEmail,
            status: existingAppUser ? 2 : 0, // 如果已注册，直接确认(简化)。正式需 0=Invited, 1=Accepted, 2=Confirmed
            type: body.type || 2,
            creationDate: now,
            revisionDate: now,
        });

        await logEvent(c.env.DB, 1500, {
            userId: existingAppUser ? existingAppUser.id : undefined,
            actingUserId: userId,
            organizationId: orgId
        });
    }

    return c.json({});
});

/**
 * DELETE /api/organizations/:id/users/:orgUserId
 * 移除组织成员
 */
orgs.delete('/:id/users/:orgUserId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const inviter = await getOrgUser(db, orgId, userId);
    if (inviter.type !== 0 && inviter.type !== 1) {
        throw new BadRequestError('Only owners and admins can remove users.');
    }

    const targetUser = await db.select().from(organizationUsers).where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();
    if (targetUser) {
        await db.delete(organizationUsers).where(eq(organizationUsers.id, orgUserId)).run();
        await logEvent(c.env.DB, 1503, {
            userId: targetUser.userId || undefined,
            actingUserId: userId,
            organizationId: orgId
        });
    }
    return c.json({});
});

// ==================== Collections 管理端点 ====================

/**
 * POST /api/organizations/:id/collections
 */
orgs.post('/:id/collections', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');
    const body = await c.req.json<{ name: string; externalId?: string }>();

    if (!body.name) {
        throw new BadRequestError('Name is required.');
    }

    await getOrgUser(db, orgId, userId); // 验证权限

    const collectionId = generateUuid();
    const now = new Date().toISOString();

    await db.insert(collections).values({
        id: collectionId,
        organizationId: orgId,
        name: body.name,
        externalId: body.externalId || null,
        creationDate: now,
        revisionDate: now,
    });

    return c.json({
        id: collectionId,
        organizationId: orgId,
        name: body.name,
        externalId: body.externalId || null,
        object: 'collectionDetails',
    });
});

/**
 * PUT /api/organizations/:id/collections/:collectionId
 */
orgs.put('/:id/collections/:collectionId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const collectionId = c.req.param('collectionId');
    const userId = c.get('userId');
    const body = await c.req.json<{ name: string; externalId?: string }>();

    if (!body.name) {
        throw new BadRequestError('Name is required.');
    }

    await getOrgUser(db, orgId, userId); // 验证权限

    const col = await db.select().from(collections).where(and(eq(collections.id, collectionId), eq(collections.organizationId, orgId))).get();
    if (!col) throw new NotFoundError('Collection not found.');

    const now = new Date().toISOString();

    await db.update(collections).set({
        name: body.name,
        externalId: body.externalId || col.externalId,
        revisionDate: now,
    }).where(eq(collections.id, collectionId));

    return c.json({
        id: collectionId,
        organizationId: orgId,
        name: body.name,
        externalId: body.externalId || col.externalId,
        object: 'collectionDetails',
    });
});

/**
 * DELETE /api/organizations/:id/collections/:collectionId
 */
orgs.delete('/:id/collections/:collectionId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const collectionId = c.req.param('collectionId');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const col = await db.select().from(collections).where(and(eq(collections.id, collectionId), eq(collections.organizationId, orgId))).get();
    if (!col) throw new NotFoundError('Collection not found.');

    await db.delete(collections).where(eq(collections.id, collectionId));

    return c.json({});
});

/**
 * GET /api/organizations/:id/collections
 */
orgs.get('/:id/collections', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const cols = await db.select().from(collections).where(eq(collections.organizationId, orgId)).all();

    return c.json({
        data: cols.map(col => ({
            id: col.id,
            organizationId: col.organizationId,
            name: col.name,
            externalId: col.externalId,
            object: 'collectionDetails'
        })),
        object: 'list',
        continuationToken: null
    });
});

/**
 * GET /api/organizations/:id/collections/details
 */
orgs.get('/:id/collections/details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const cols = await db.select().from(collections).where(eq(collections.organizationId, orgId)).all();

    return c.json({
        data: cols.map(col => ({
            id: col.id,
            organizationId: col.organizationId,
            name: col.name,
            externalId: col.externalId,
            object: 'collectionDetails'
        })),
        object: 'list',
        continuationToken: null
    });
});

export default orgs;
