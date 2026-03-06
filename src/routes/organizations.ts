/**
 * Bitwarden Workers - Organizations 路由
 * 对应官方 OrganizationsController + OrganizationUsersController
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, desc, inArray, sql } from 'drizzle-orm';
import {
    organizations,
    organizationUsers,
    users,
    events,
    collections,
    collectionUsers,
    groups,
    groupUsers,
    collectionGroups,
    collectionCiphers,
} from '../db/schema';
import type { OrganizationUserRow, OrganizationRow, UserRow } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { logEvent } from '../services/events';
import { toEventResponse, getDateRange, getDeviceTypeFromRequest } from './events';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid, createInviteToken, verifyInviteToken } from '../services/crypto';
import { toOrganizationResponse, toOrganizationSubscriptionResponse, toOrganizationUserResponse } from '../models/organization-responses';
import type { Bindings, Variables } from '../types';
import { batchedInArrayQuery, D1_BATCH_SIZE } from '../services/db';
import { pushSyncUser, pushSyncOrganizationStatus } from '../services/push-notification';
import { PushType } from '../types/push-notification';

const orgs = new Hono<{ Bindings: Bindings; Variables: Variables }>();
orgs.use('/*', authMiddleware);

type HubEnv = { NOTIFICATION_HUB: DurableObjectNamespace };
type D1DbType = ReturnType<typeof drizzle>;

/** 向组织所有已确认成员推送 SyncVault 通知 */
async function pushSyncVaultToOrgMembers(env: HubEnv, db: D1DbType, orgId: string): Promise<void> {
    const members = await db.select({ userId: organizationUsers.userId })
        .from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.status, 2)))
        .all();
    await Promise.all(
        members
            .filter(m => m.userId)
            .map(m => pushSyncUser(env as any, PushType.SyncVault, m.userId!, null))
    );
}

// ==================== 类型定义 ====================

/** 组织成员权限 JSON（camelCase，与官方 Permissions 一致） */
interface OrganizationUserPermissions {
    manageGroups?: boolean;
    manageUsers?: boolean;
    createNewCollections?: boolean;
    editAnyCollection?: boolean;
    deleteAnyCollection?: boolean;
    accessEventLogs?: boolean;
    /** 对应官方 AccessImportExport，用于组织导入/导出及向已有集合导入条目 */
    accessImportExport?: boolean;
}

/** Drizzle D1 实例（用于 getOrgUser 等，避免 any） */
type D1Db = ReturnType<typeof drizzle>;

// ==================== 辅助函数 ====================

/**
 * 验证组织用户权限，返回 orgUser 记录
 */
async function getOrgUser(db: D1Db, orgId: string, userId: string): Promise<OrganizationUserRow> {
    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId))).get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    return orgUser;
}

/**
 * 根据 organizationId 批量刷新该组织内所有已确认成员的 AccountRevisionDate
 * 对应官方 UserBumpAccountRevisionDateByOrganizationId
 */
async function bumpAccountRevisionDateByOrganizationId(db: D1Db, orgId: string, now?: string): Promise<void> {
    const orgUsersRows = await db
        .select({ userId: organizationUsers.userId })
        .from(organizationUsers)
        .where(
            and(
                eq(organizationUsers.organizationId, orgId),
                eq(organizationUsers.status, 2), // Confirmed
            ),
        )
        .all();

    const userIds = Array.from(
        new Set(
            orgUsersRows
                .map((r) => r.userId)
                .filter((id): id is string => !!id),
        ),
    );
    if (userIds.length === 0) return;

    const timestamp = now ?? new Date().toISOString();
    for (let i = 0; i < userIds.length; i += D1_BATCH_SIZE) {
        const batch = userIds.slice(i, i + D1_BATCH_SIZE);
        await db.update(users).set({ accountRevisionDate: timestamp }).where(inArray(users.id, batch));
    }
}

/**
 * 根据 organizationUserId 刷新对应已确认成员的 AccountRevisionDate
 * 对应官方 UserBumpAccountRevisionDateByOrganizationUserId
 */
async function bumpAccountRevisionDateByOrganizationUserId(db: D1Db, orgUserId: string, now?: string): Promise<void> {
    const row = await db
        .select({
            userId: organizationUsers.userId,
            status: organizationUsers.status,
        })
        .from(organizationUsers)
        .where(eq(organizationUsers.id, orgUserId))
        .get();

    // 仅对已绑定用户且状态为 Confirmed 的成员生效
    if (!row?.userId || row.status !== 2) return;

    const timestamp = now ?? new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: timestamp }).where(eq(users.id, row.userId));
}

/**
 * 验证是否为 Owner 或 Admin
 */
function requireOwnerOrAdmin(orgUser: OrganizationUserRow): void {
    if (orgUser.type !== 0 && orgUser.type !== 1) {
        throw new BadRequestError('Requires Owner or Admin privileges.');
    }
}

/**
 * 验证是否为 Owner
 */
function requireOwner(orgUser: OrganizationUserRow): void {
    if (orgUser.type !== 0) {
        throw new BadRequestError('Requires Owner privileges.');
    }
}

function parseOrgUserPermissions(permissions: string | null): OrganizationUserPermissions | null {
    if (!permissions) return null;
    try {
        return JSON.parse(permissions) as OrganizationUserPermissions;
    } catch {
        return null;
    }
}

/** 是否有权查看群组详情（列表）：Owner/Admin 或 permissions.manageGroups 或 permissions.manageUsers */
function canViewGroupDetails(orgUser: OrganizationUserRow): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true; // Owner, Admin
    const perms = parseOrgUserPermissions(orgUser.permissions);
    return !!(perms && (perms.manageGroups === true || perms.manageUsers === true));
}

/** 是否有权创建集合：Owner/Admin 或 permissions.createNewCollections（与官方 BulkCollectionOperations.Create 一致） */
function canCreateCollection(orgUser: OrganizationUserRow): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true; // Owner, Admin
    const perms = parseOrgUserPermissions(orgUser.permissions);
    return !!(perms && perms.createNewCollections === true);
}

/** 是否有权导入/导出：Owner/Admin 或 permissions.accessImportExport（与官方 CheckOrgImportPermission 一致） */
function canAccessImportExport(orgUser: OrganizationUserRow): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true; // Owner, Admin
    const perms = parseOrgUserPermissions(orgUser.permissions);
    return !!(perms && perms.accessImportExport === true);
}

/** 是否有权编辑集合：Owner/Admin（且组织允许管理员访问全部）或 permissions.editAnyCollection */
function canEditCollection(orgUser: OrganizationUserRow, org: OrganizationRow | null | undefined): boolean {
    const perms = parseOrgUserPermissions(orgUser.permissions);
    if (perms?.editAnyCollection === true) return true;
    const allowAdminAll = org?.allowAdminAccessToAllCollectionItems === true;
    return (orgUser.type === 0 || orgUser.type === 1) && !!allowAdminAll;
}

/** 是否有权删除集合：Owner/Admin（且组织允许管理员访问全部）或 permissions.deleteAnyCollection */
function canDeleteCollection(orgUser: OrganizationUserRow, org: OrganizationRow | null | undefined): boolean {
    const perms = parseOrgUserPermissions(orgUser.permissions);
    if (perms?.deleteAnyCollection === true) return true;
    const allowAdminAll = org?.allowAdminAccessToAllCollectionItems === true;
    return (orgUser.type === 0 || orgUser.type === 1) && !!allowAdminAll;
}

/** 是否有权查看事件日志：组织开启 useEvents 且 (Owner/Admin 或 permissions.accessEventLogs) */
function canAccessEventLogs(org: OrganizationRow | null | undefined, orgUser: OrganizationUserRow): boolean {
    if (!org?.useEvents) return false;
    if (orgUser.type === 0 || orgUser.type === 1) return true; // Owner, Admin
    const perms = parseOrgUserPermissions(orgUser.permissions);
    return !!(perms?.accessEventLogs);
}

/**
 * 构建新组织的默认字段值
 */
function buildOrgDefaults(planType: number) {
    const isEnterprise = [4, 5, 10, 11, 15, 16].includes(planType);
    const isTeams = [2, 3, 8, 9, 12, 13, 14].includes(planType);
    const isFamilies = [1, 7].includes(planType);
    const isPaid = planType > 0;

    return {
        usePolicies: isEnterprise,
        useSso: isEnterprise,
        useKeyConnector: isEnterprise,
        useScim: isEnterprise,
        useGroups: isEnterprise || isTeams,
        useDirectory: isEnterprise || isTeams,
        useEvents: isPaid,
        useTotp: true,
        use2fa: isPaid,
        useApi: isPaid,
        useResetPassword: isEnterprise,
        useSecretsManager: false,
        selfHost: true,
        usersGetPremium: isPaid || isFamilies,
        useCustomPermissions: isEnterprise,
        usePasswordManager: true,
        useRiskInsights: isEnterprise,
        useOrganizationDomains: isEnterprise,
        useAdminSponsoredFamilies: isEnterprise,
        useAutomaticUserConfirmation: false,
        useDisableSmAdsForUsers: false,
        usePhishingBlocker: false,
        useMyItems: true,
        limitCollectionCreation: false,
        limitCollectionDeletion: false,
        limitItemDeletion: false,
        allowAdminAccessToAllCollectionItems: true,
    };
}

// ==================== Organization Connections（与云端通信） ====================
// 对应官方 Api/AdminConsole/Controllers/OrganizationConnectionsController.cs

/**
 * GET /api/organizations/connections/enabled
 * 是否启用组织连接（SelfHosted && EnableCloudCommunication）；Workers 自建默认 false，可通过 env 开启
 */
orgs.get('/connections/enabled', async (c) => {
    const enabled = (c.env as { ENABLE_CLOUD_COMMUNICATION?: string }).ENABLE_CLOUD_COMMUNICATION === 'true';
    return c.json(enabled);
});

// ==================== 组织 CRUD ====================

/**
 * POST /api/organizations
 * 创建新组织
 */
orgs.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        name: string;
        billingEmail: string;
        key: string;
        planType?: number;
        keys?: { publicKey: string; encryptedPrivateKey: string };
        collectionName?: string;
    }>();

    if (!body.name || !body.billingEmail || !body.key) {
        throw new BadRequestError('Name, billingEmail, and key are required.');
    }

    const orgId = generateUuid();
    const now = new Date().toISOString();
    const planType = body.planType || 0;
    const defaults = buildOrgDefaults(planType);

    await db.insert(organizations).values({
        id: orgId,
        name: body.name,
        billingEmail: body.billingEmail,
        email: body.billingEmail,
        planType,
        publicKey: body.keys?.publicKey ?? null,
        privateKey: body.keys?.encryptedPrivateKey ?? null,
        ...defaults,
        creationDate: now,
        revisionDate: now,
    });

    const currentUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!currentUser) throw new NotFoundError('Current user not found.');

    const orgUserId = generateUuid();
    await db.insert(organizationUsers).values({
        id: orgUserId,
        organizationId: orgId,
        userId: userId,
        email: currentUser.email,
        key: body.key,
        status: 2, // Confirmed
        type: 0, // Owner
        creationDate: now,
        revisionDate: now,
    });

    // 创建默认 collection（如果提供了 collectionName）
    if (body.collectionName) {
        const collectionId = generateUuid();
        await db.insert(collections).values({
            id: collectionId,
            organizationId: orgId,
            name: body.collectionName,
            creationDate: now,
            revisionDate: now,
        });
        await db.insert(collectionUsers).values({
            collectionId,
            organizationUserId: orgUserId,
            readOnly: false,
            hidePasswords: false,
            manage: true,
        });
    }

    await logEvent(c.env.DB, 1600, { userId, organizationId: orgId, deviceType: getDeviceTypeFromRequest(c) });

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    return c.json(toOrganizationResponse(org));
});

/**
 * GET /api/organizations/:id
 * 获取组织详情（仅 Owner）
 */
orgs.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json(toOrganizationResponse(org));
});

/**
 * PUT /api/organizations/:id
 * 更新组织信息
 */
orgs.put('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    const body = await c.req.json<{
        name?: string;
        billingEmail?: string;
        keys?: { publicKey: string; encryptedPrivateKey: string };
    }>();

    const now = new Date().toISOString();
    const updateData: Partial<OrganizationRow> = { revisionDate: now };

    if (body.name !== undefined) updateData.name = body.name;
    if (body.billingEmail !== undefined) {
        updateData.billingEmail = body.billingEmail;
        updateData.email = body.billingEmail;
    }
    if (body.keys) {
        updateData.publicKey = body.keys.publicKey;
        updateData.privateKey = body.keys.encryptedPrivateKey;
    }

    await db.update(organizations).set(updateData).where(eq(organizations.id, orgId));

    const updated = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    return c.json(toOrganizationResponse(updated));
});

/**
 * POST /api/organizations/:id (deprecated, 同 PUT)
 */
orgs.post('/:id', async (c) => {
    // 排除已有的子路由
    const path = c.req.path;
    if (path.includes('/keys') || path.includes('/leave') || path.includes('/delete') ||
        path.includes('/storage') || path.includes('/api-key') || path.includes('/users') ||
        path.includes('/collections') || path.includes('/events')) {
        return;
    }

    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    const body = await c.req.json<{
        name?: string;
        billingEmail?: string;
        keys?: { publicKey: string; encryptedPrivateKey: string };
    }>();

    const now = new Date().toISOString();
    const updateData: Partial<OrganizationRow> = { revisionDate: now };
    if (body.name !== undefined) updateData.name = body.name;
    if (body.billingEmail !== undefined) {
        updateData.billingEmail = body.billingEmail;
        updateData.email = body.billingEmail;
    }
    if (body.keys) {
        updateData.publicKey = body.keys.publicKey;
        updateData.privateKey = body.keys.encryptedPrivateKey;
    }

    await db.update(organizations).set(updateData).where(eq(organizations.id, orgId));
    const updated = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    return c.json(toOrganizationResponse(updated));
});

/**
 * DELETE /api/organizations/:id
 * 删除组织
 */
orgs.delete('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    // 检查是否是子路由 (users/:orgUserId, collections/:collectionId)
    // Hono 会先匹配更具体的路由，所以这里只处理 DELETE /organizations/:id
    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    // 删除组织前，按组织维度刷新所有已确认成员的 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    // 获取所有确认成员，用于推送通知
    const confirmedMembers = await db.select({ userId: organizationUsers.userId })
        .from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.status, 2)))
        .all();

    // 官方需要密码验证，这里简化（自建环境信任 Owner）
    // body 中可能有 masterPasswordHash，但我们暂不验证
    await db.delete(organizations).where(eq(organizations.id, orgId));

    await logEvent(c.env.DB, 1601, { userId, organizationId: orgId, deviceType: getDeviceTypeFromRequest(c) });

    // 推送组织删除通知到所有已确认成员
    for (const member of confirmedMembers) {
        if (member.userId) {
            c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, member.userId, null));
        }
    }

    return c.json({});
});

/**
 * POST /api/organizations/:id/delete (deprecated, 同 DELETE)
 */
orgs.post('/:id/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    // 获取所有确认成员
    const confirmedMembers = await db.select({ userId: organizationUsers.userId })
        .from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.status, 2)))
        .all();

    // 删除组织前，按组织维度刷新所有已确认成员的 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    await db.delete(organizations).where(eq(organizations.id, orgId));
    await logEvent(c.env.DB, 1601, { userId, organizationId: orgId, deviceType: getDeviceTypeFromRequest(c) });

    for (const member of confirmedMembers) {
        if (member.userId) {
            c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, member.userId, null));
        }
    }

    return c.json({});
});

/**
 * POST /api/organizations/:id/leave
 * 用户离开组织
 */
orgs.post('/:id/leave', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId))).get();

    if (!orgUser) throw new NotFoundError('Organization not found.');

    // Owner 不能直接离开（如果是唯一 Owner）
    if (orgUser.type === 0) {
        const owners = await db.select().from(organizationUsers)
            .where(and(
                eq(organizationUsers.organizationId, orgId),
                eq(organizationUsers.type, 0),
                eq(organizationUsers.status, 2),
            )).all();
        if (owners.length <= 1) {
            throw new BadRequestError('Organization must have at least one confirmed owner.');
        }
    }

    const now = new Date().toISOString();

    await db.delete(organizationUsers).where(eq(organizationUsers.id, orgUser.id));
    await logEvent(c.env.DB, 1504, { userId, organizationId: orgId, deviceType: getDeviceTypeFromRequest(c) });

    // 当前用户离开组织后，需要刷新自己的 AccountRevisionDate 以触发客户端重新同步
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, userId, contextId));

    return c.body(null, 200);
});

// ==================== 组织密钥 ====================

/**
 * POST /api/organizations/:id/keys
 * 保存组织公钥/私钥
 */
orgs.post('/:id/keys', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const body = await c.req.json<{ publicKey: string; encryptedPrivateKey: string }>();
    if (!body.publicKey || !body.encryptedPrivateKey) {
        throw new BadRequestError('PublicKey and EncryptedPrivateKey are required.');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    const now = new Date().toISOString();
    await db.update(organizations).set({
        publicKey: body.publicKey,
        privateKey: body.encryptedPrivateKey,
        revisionDate: now,
    }).where(eq(organizations.id, orgId));

    return c.json({
        publicKey: body.publicKey,
        privateKey: body.encryptedPrivateKey,
        object: 'organizationKeys',
    });
});

/**
 * GET /api/organizations/:id/public-key
 * 获取组织公钥
 */
orgs.get('/:id/public-key', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json({
        publicKey: org.publicKey,
        object: 'organizationPublicKey',
    });
});

/**
 * GET /api/organizations/:id/keys (deprecated, 同 public-key)
 */
orgs.get('/:id/keys', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json({
        publicKey: org.publicKey,
        object: 'organizationPublicKey',
    });
});

// ==================== 组织事件 ====================

const EVENTS_PAGE_SIZE = 100;

/**
 * GET /api/organizations/:id/events
 * 组织事件日志；支持 start, end, continuationToken（与官方 EventsController.GetOrganization 一致）
 * 权限：组织 useEvents 开启且 (Owner/Admin 或 accessEventLogs)
 */
orgs.get('/:id/events', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const orgId = c.req.param('id');
    const start = c.req.query('start') ?? null;
    const end = c.req.query('end') ?? null;
    const continuationToken = c.req.query('continuationToken') ?? null;

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!canAccessEventLogs(org, orgUser)) {
        throw new NotFoundError('Organization not found.');
    }

    const { start: startStr, end: endStr } = getDateRange(start, end);

    let conditions = and(
        eq(events.organizationId, orgId),
        sql`${events.date} >= ${startStr}`,
        sql`${events.date} <= ${endStr}`,
    );
    if (continuationToken) {
        try {
            const decoded = Buffer.from(continuationToken, 'base64url').toString('utf8');
            const [tokenDate, tokenId] = decoded.split('|');
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

    const orgEvents = await db.select().from(events)
        .where(conditions)
        .orderBy(desc(events.date), desc(events.id))
        .limit(EVENTS_PAGE_SIZE + 1)
        .all();

    const hasMore = orgEvents.length > EVENTS_PAGE_SIZE;
    const page = hasMore ? orgEvents.slice(0, EVENTS_PAGE_SIZE) : orgEvents;
    const nextToken = hasMore && page.length
        ? Buffer.from(`${page[page.length - 1].date}|${page[page.length - 1].id}`).toString('base64url')
        : null;

    return c.json({
        data: page.map(toEventResponse),
        object: 'list',
        continuationToken: nextToken,
    });
});

// ==================== 组织成员管理 ====================

/**
 * GET /api/organizations/:id/users
 * 获取组织成员列表；?includeGroups=true 时每个成员带 groups（群组 ID 列表）
 */
orgs.get('/:id/users', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const usersList = await db.select().from(organizationUsers)
        .where(eq(organizationUsers.organizationId, orgId)).all();

    const userIds = usersList.filter((u): u is OrganizationUserRow & { userId: string } => u.userId != null).map(u => u.userId);
    const usersMap: Record<string, UserRow> = {};
    if (userIds.length > 0) {
        const userRecords = await batchedInArrayQuery<UserRow>(db, users, users.id, userIds);
        for (const u of userRecords) {
            usersMap[u.id] = u;
        }
    }

    const orgUserGroupsMap: Record<string, string[]> = {};
    const includeGroups = c.req.query('includeGroups')?.toLowerCase() === 'true';
    if (includeGroups && usersList.length > 0) {
        try {
            const orgUserIds = usersList.map(u => u.id);
            const guRows = await batchedInArrayQuery<{ organizationUserId: string; groupId: string }>(
                db, groupUsers, groupUsers.organizationUserId, orgUserIds);
            for (const row of guRows) {
                if (!orgUserGroupsMap[row.organizationUserId]) orgUserGroupsMap[row.organizationUserId] = [];
                orgUserGroupsMap[row.organizationUserId].push(row.groupId);
            }
        } catch (e) {
            if (!isNoSuchTable(e)) throw e;
        }
    }

    const data = usersList.map(u => {
        const resp = toOrganizationUserResponse(u, u.userId ? usersMap[u.userId] : undefined);
        if (includeGroups && orgUserGroupsMap[u.id]) resp.groups = orgUserGroupsMap[u.id];
        return resp;
    });

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/users/mini-details
 * 获取组织成员简要列表
 */
orgs.get('/:id/users/mini-details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const usersList = await db.select().from(organizationUsers)
        .where(eq(organizationUsers.organizationId, orgId)).all();

    const userIds = usersList.filter((u): u is OrganizationUserRow & { userId: string } => u.userId != null).map(u => u.userId);
    const usersMap: Record<string, UserRow> = {};
    if (userIds.length > 0) {
        const userRecords = await batchedInArrayQuery<UserRow>(db, users, users.id, userIds);
        for (const u of userRecords) {
            usersMap[u.id] = u;
        }
    }

    return c.json({
        data: usersList.map(u => {
            const user = u.userId ? usersMap[u.userId] : undefined;
            return {
                id: u.id,
                userId: u.userId ?? null,
                type: u.type,
                status: u.status,
                name: user?.name ?? null,
                email: u.email ?? user?.email ?? null,
                object: 'organizationUserUserMiniDetails',
            };
        }),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/users/:orgUserId
 * 获取组织成员详情
 */
orgs.get('/:id/users/:orgUserId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();
    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');

    let user: UserRow | undefined;
    if (targetOrgUser.userId) {
        user = await db.select().from(users).where(eq(users.id, targetOrgUser.userId)).get();
    }

    // 获取用户的 collection 访问权限
    const userCollections = await db.select().from(collectionUsers)
        .where(eq(collectionUsers.organizationUserId, orgUserId)).all();

    const resp = toOrganizationUserResponse(targetOrgUser, user);
    resp.collections = userCollections.map(cu => ({
        id: cu.collectionId,
        readOnly: cu.readOnly ?? false,
        hidePasswords: cu.hidePasswords ?? false,
        manage: cu.manage ?? false,
    }));
    resp.object = 'organizationUserDetails';

    // 用户维度：该成员所属的群组 ID 列表（编辑成员弹窗「群组」Tab 用）
    const includeGroups = c.req.query('includeGroups')?.toLowerCase() === 'true';
    if (includeGroups) {
        try {
            const userGroupRows = await db.select({ groupId: groupUsers.groupId }).from(groupUsers)
                .where(eq(groupUsers.organizationUserId, orgUserId)).all();
            resp.groups = userGroupRows.map(r => r.groupId);
        } catch (e) {
            if (!isNoSuchTable(e)) throw e;
        }
    }

    return c.json(resp);
});

/**
 * POST /api/organizations/:id/users/invite
 * 邀请组织成员；返回邀请链接并在控制台打印，便于管理员手动发给被邀请人（后续可接邮件）
 */
orgs.post('/:id/users/invite', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const inviter = await getOrgUser(db, orgId, userId);
    if (inviter.type !== 0 && inviter.type !== 1 && inviter.type !== 3) {
        throw new BadRequestError('Only owners, admins, or managers can invite users.');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    const orgName = org.name || 'Organization';

    const body = await c.req.json<{
        emails?: string[];
        type?: number;
        collections?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
        accessSecretsManager?: boolean;
    }>();

    if (!body.emails || !body.emails.length) {
        throw new BadRequestError('Emails are required.');
    }

    const vaultBase = ((c.env as { VAULT_BASE_URL?: string }).VAULT_BASE_URL || 'https://vault.example.com').replace(/#\/?$/, '').replace(/\/$/, '');
    const now = new Date().toISOString();
    const inviteLinks: { email: string; link: string }[] = [];

    for (const email of body.emails) {
        const targetEmail = email.toLowerCase().trim();

        const existing = await db.select().from(organizationUsers)
            .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.email, targetEmail))).get();
        if (existing) continue;

        const existingAppUser = await db.select().from(users).where(eq(users.email, targetEmail)).get();

        const newOrgUserId = generateUuid();
        await db.insert(organizationUsers).values({
            id: newOrgUserId,
            organizationId: orgId,
            userId: existingAppUser ? existingAppUser.id : null,
            email: targetEmail,
            status: 0, // Invited
            type: body.type ?? 2,
            accessSecretsManager: body.accessSecretsManager ?? false,
            creationDate: now,
            revisionDate: now,
        });

        if (body.collections?.length) {
            for (const col of body.collections) {
                await db.insert(collectionUsers).values({
                    collectionId: col.id,
                    organizationUserId: newOrgUserId,
                    readOnly: col.readOnly ?? false,
                    hidePasswords: col.hidePasswords ?? false,
                    manage: col.manage ?? false,
                });
            }
        }

        await logEvent(c.env.DB, 1500, {
            userId: existingAppUser ? existingAppUser.id : undefined,
            actingUserId: userId,
            organizationId: orgId,
            organizationUserId: newOrgUserId,
            deviceType: getDeviceTypeFromRequest(c),
        });

        const token = await createInviteToken(newOrgUserId, targetEmail, orgId, c.env.JWT_SECRET);
        const forceRegister = (c.env as { FORCE_INVITE_REGISTER?: string }).FORCE_INVITE_REGISTER === 'true';
        const params = new URLSearchParams({
            organizationId: orgId,
            organizationUserId: newOrgUserId,
            email: targetEmail,
            organizationName: orgName,
            token,
            initOrganization: 'false',
            orgUserHasExistingUser: forceRegister ? 'false' : (existingAppUser ? 'true' : 'false'),
        });
        const link = `${vaultBase}#/accept-organization?${params.toString()}`;
        inviteLinks.push({ email: targetEmail, link });
        console.log(`[INVITE] ${targetEmail} -> ${link}`);
    }

    return c.json({ inviteLinks });
});

/**
 * POST /api/organizations/:orgId/users/:orgUserId/accept
 * 接受邀请；请求体可带 { token: string }，与邀请链接中的 token 一致时校验通过
 */
orgs.post('/:id/users/:orgUserId/accept', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');

    const currentUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!currentUser) throw new NotFoundError('User not found.');

    let tokenValid = false;
    try {
        const body = await c.req.json<{ token?: string; resetPasswordKey?: string }>().catch((): { token?: string; resetPasswordKey?: string } => ({}));
        if (body?.token) {
            const payload = await verifyInviteToken(body.token, c.env.JWT_SECRET);
            tokenValid = !!payload &&
                payload.orgUserId === orgUserId &&
                payload.orgId === orgId &&
                payload.email.toLowerCase() === targetOrgUser.email.toLowerCase();
        }
    } catch {
        /* ignore */
    }

    if (!tokenValid) {
        if (targetOrgUser.userId && targetOrgUser.userId !== userId) {
            throw new BadRequestError('This invitation belongs to a different user.');
        }
        if (targetOrgUser.email.toLowerCase() !== currentUser.email.toLowerCase() && !targetOrgUser.userId) {
            throw new BadRequestError('This invitation belongs to a different user.');
        }
    }

    if (targetOrgUser.status !== 0) {
        throw new BadRequestError('User is not in an invited state.');
    }

    const now = new Date().toISOString();
    await db.update(organizationUsers).set({
        userId: userId,
        status: 1, // Accepted
        revisionDate: now,
    }).where(eq(organizationUsers.id, orgUserId));

    await logEvent(c.env.DB, 1501, {
        userId,
        organizationId: orgId,
        organizationUserId: orgUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    return c.body(null, 200);
});

/**
 * POST /api/organizations/:orgId/users/:orgUserId/confirm
 * 确认组织成员
 */
orgs.post('/:id/users/:orgUserId/confirm', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const confirmer = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(confirmer);

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');

    if (targetOrgUser.status !== 1) { // Not Accepted
        throw new BadRequestError('User is not in an accepted state.');
    }

    const body = await c.req.json<{ key: string }>();
    if (!body.key) {
        throw new BadRequestError('Key is required.');
    }

    const now = new Date().toISOString();
    await db.update(organizationUsers).set({
        key: body.key,
        status: 2, // Confirmed
        revisionDate: now,
    }).where(eq(organizationUsers.id, orgUserId));

    await logEvent(c.env.DB, 1501, {
        userId: targetOrgUser.userId || undefined,
        actingUserId: userId,
        organizationId: orgId,
        organizationUserId: orgUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    // 用户从 Accepted -> Confirmed，正式获得组织保险库访问权限，需刷新其 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationUserId(db, orgUserId, now);

    // 推送 SyncOrgKeys 通知到被确认的用户
    if (targetOrgUser.userId) {
        c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrgKeys, targetOrgUser.userId, null));
    }

    return c.body(null, 200);
});

/**
 * POST /api/organizations/:orgId/users/confirm (批量确认)
 */
orgs.post('/:id/users/confirm', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const confirmer = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(confirmer);

    const body = await c.req.json<{ keys: Record<string, string> }>();
    if (!body.keys) {
        throw new BadRequestError('Keys are required.');
    }

    const now = new Date().toISOString();
    const results: Array<{ id: string; error: string }> = [];

    for (const [ouId, key] of Object.entries(body.keys)) {
        const targetOrgUser = await db.select().from(organizationUsers)
            .where(and(eq(organizationUsers.id, ouId), eq(organizationUsers.organizationId, orgId))).get();

        if (!targetOrgUser || targetOrgUser.status !== 1) {
            results.push({ id: ouId, error: 'User not found or not in accepted state.' });
            continue;
        }

        await db.update(organizationUsers).set({
            key,
            status: 2,
            revisionDate: now,
        }).where(eq(organizationUsers.id, ouId));

        await logEvent(c.env.DB, 1501, {
            organizationId: orgId,
            actingUserId: userId,
            organizationUserId: ouId,
            deviceType: getDeviceTypeFromRequest(c),
        });

        // 批量确认成员时，同样需要为每个成员刷新 AccountRevisionDate
        await bumpAccountRevisionDateByOrganizationUserId(db, ouId, now);

        // 推送 SyncOrgKeys 通知到被确认的用户
        if (targetOrgUser.userId) {
            c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrgKeys, targetOrgUser.userId, null));
        }

        results.push({ id: ouId, error: '' });
    }

    return c.json({
        data: results.map(r => ({
            id: r.id,
            error: r.error || null,
            object: 'organizationUserBulkResponseModel',
        })),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/organizations/:orgId/users/public-keys
 * 批量获取成员公钥（用于确认成员时加密 org key）
 */
orgs.post('/:id/users/public-keys', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const body = await c.req.json<{ ids: string[] }>();
    if (!body.ids?.length) {
        throw new BadRequestError('Ids are required.');
    }

    const orgUsersList = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.id, body.ids),
        )).all();

    const userIds = orgUsersList.filter((ou): ou is OrganizationUserRow & { userId: string } => ou.userId != null).map(ou => ou.userId);
    const usersMap: Record<string, UserRow> = {};
    if (userIds.length > 0) {
        const userRecords = await batchedInArrayQuery<UserRow>(db, users, users.id, userIds);
        for (const u of userRecords) {
            usersMap[u.id] = u;
        }
    }

    return c.json({
        data: orgUsersList.map(ou => ({
            id: ou.id,
            userId: ou.userId,
            key: ou.userId && usersMap[ou.userId] ? usersMap[ou.userId].publicKey : null,
            object: 'organizationUserPublicKeyResponseModel',
        })),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * PUT /api/organizations/:orgId/users/:orgUserId
 * 更新组织成员
 */
orgs.put('/:id/users/:orgUserId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const updater = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(updater);

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();
    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');

    const body = await c.req.json<{
        type?: number;
        accessAll?: boolean;
        permissions?: OrganizationUserPermissions;
        collections?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
        groups?: string[];
        accessSecretsManager?: boolean;
    }>();

    // Admin 不能修改 Owner
    if (targetOrgUser.type === 0 && updater.type !== 0) {
        throw new BadRequestError('Only owners can modify other owners.');
    }

    // Admin 不能设置为 Owner
    if (body.type === 0 && updater.type !== 0) {
        throw new BadRequestError('Only owners can grant owner permissions.');
    }

    const now = new Date().toISOString();
    const updateData: Partial<OrganizationUserRow> = { revisionDate: now };
    if (body.type !== undefined) updateData.type = body.type;
    if (body.permissions !== undefined) updateData.permissions = JSON.stringify(body.permissions);
    if (body.accessSecretsManager !== undefined) updateData.accessSecretsManager = body.accessSecretsManager;

    await db.update(organizationUsers).set(updateData).where(eq(organizationUsers.id, orgUserId));

    await logEvent(c.env.DB, 1502, {
        userId: targetOrgUser.userId ?? undefined,
        actingUserId: userId,
        organizationId: orgId,
        organizationUserId: orgUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    // 更新 collection 权限
    if (body.collections) {
        // 删除旧权限并重建
        await db.delete(collectionUsers).where(eq(collectionUsers.organizationUserId, orgUserId));
        for (const col of body.collections) {
            await db.insert(collectionUsers).values({
                collectionId: col.id,
                organizationUserId: orgUserId,
                readOnly: col.readOnly ?? false,
                hidePasswords: col.hidePasswords ?? false,
                manage: col.manage ?? false,
            });
        }
    }

    // 成员角色 / 权限 / 集合访问权限变化，会改变其能看到的组织条目，需刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationUserId(db, orgUserId, now);

    // 推送 SyncOrganizations 通知到被修改的用户
    if (targetOrgUser.userId) {
        c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, targetOrgUser.userId, null));
    }

    return c.body(null, 200);
});

/**
 * POST /api/organizations/:orgId/users/:orgUserId/reinvite
 * 重新发送邀请；生成新 token 与邀请链接，在控制台打印并返回（与 invite 一致，后续可接邮件）
 */
orgs.post('/:id/users/:orgUserId/reinvite', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const inviter = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(inviter);

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');
    if (targetOrgUser.status !== 0) {
        throw new BadRequestError('User is not in an invited state.');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    const orgName = org?.name || 'Organization';
    const vaultBase = ((c.env as { VAULT_BASE_URL?: string }).VAULT_BASE_URL || 'https://vault.example.com').replace(/#\/?$/, '').replace(/\/$/, '');
    const forceRegister = (c.env as { FORCE_INVITE_REGISTER?: string }).FORCE_INVITE_REGISTER === 'true';
    const existingUser = await db.select().from(users).where(eq(users.email, targetOrgUser.email)).get();
    const token = await createInviteToken(orgUserId, targetOrgUser.email, orgId, c.env.JWT_SECRET);
    const params = new URLSearchParams({
        organizationId: orgId,
        organizationUserId: orgUserId,
        email: targetOrgUser.email,
        organizationName: orgName,
        token,
        initOrganization: 'false',
        orgUserHasExistingUser: forceRegister ? 'false' : (existingUser ? 'true' : 'false'),
    });
    const link = `${vaultBase}#/accept-organization?${params.toString()}`;
    console.log(`[REINVITE] ${targetOrgUser.email} -> ${link}`);
    return c.json({ email: targetOrgUser.email, link }, 200);
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

    const remover = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(remover);

    const targetUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetUser) throw new NotFoundError('Organization user not found.');

    // 不能移除自己（应该用 leave）
    if (targetUser.userId === userId) {
        throw new BadRequestError('Cannot remove yourself. Use leave instead.');
    }

    // Admin 不能移除 Owner
    if (targetUser.type === 0 && remover.type !== 0) {
        throw new BadRequestError('Only owners can remove other owners.');
    }

    const now = new Date().toISOString();

    await db.delete(organizationUsers).where(eq(organizationUsers.id, orgUserId));
    await logEvent(c.env.DB, 1503, {
        userId: targetUser.userId || undefined,
        actingUserId: userId,
        organizationId: orgId,
        organizationUserId: orgUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    // 被移除成员失去组织访问权限，刷新该成员的 AccountRevisionDate
    if (targetUser.userId) {
        await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, targetUser.userId));
        c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, targetUser.userId, null));
    }

    return c.json({});
});

/**
 * POST /api/organizations/:id/users/:orgUserId/remove (deprecated, 同 DELETE)
 */
orgs.post('/:id/users/:orgUserId/remove', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');
    const userId = c.get('userId');

    const remover = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(remover);

    const targetUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetUser) throw new NotFoundError('Organization user not found.');

    const now = new Date().toISOString();

    await db.delete(organizationUsers).where(eq(organizationUsers.id, orgUserId));
    await logEvent(c.env.DB, 1503, {
        userId: targetUser.userId || undefined,
        actingUserId: userId,
        organizationId: orgId,
        organizationUserId: orgUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    if (targetUser.userId) {
        await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, targetUser.userId));
        c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, targetUser.userId, null));
    }

    return c.json({});
});

/**
 * PUT /api/organizations/:id/users/:orgUserId/reset-password-enrollment
 * 密码重置注册
 */
orgs.put('/:id/users/:orgUserId/reset-password-enrollment', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const orgUserId = c.req.param('orgUserId');

    const body = await c.req.json<{ resetPasswordKey?: string; masterPasswordHash?: string }>();

    const targetOrgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.id, orgUserId), eq(organizationUsers.organizationId, orgId))).get();

    if (!targetOrgUser) throw new NotFoundError('Organization user not found.');

    const now = new Date().toISOString();
    await db.update(organizationUsers).set({
        resetPasswordKey: body.resetPasswordKey ?? null,
        revisionDate: now,
    }).where(eq(organizationUsers.id, orgUserId));

    return c.body(null, 200);
});

// ==================== 集合管理 ====================

/**
 * PUT /api/organizations/:id/collection-management
 */
orgs.put('/:id/collection-management', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwner(orgUser);

    const body = await c.req.json<{
        limitCollectionCreation?: boolean;
        limitCollectionDeletion?: boolean;
        limitItemDeletion?: boolean;
        allowAdminAccessToAllCollectionItems?: boolean;
    }>();

    const now = new Date().toISOString();
    const updateData: Partial<OrganizationRow> = { revisionDate: now };
    if (body.limitCollectionCreation !== undefined) updateData.limitCollectionCreation = body.limitCollectionCreation;
    if (body.limitCollectionDeletion !== undefined) updateData.limitCollectionDeletion = body.limitCollectionDeletion;
    if (body.limitItemDeletion !== undefined) updateData.limitItemDeletion = body.limitItemDeletion;
    if (body.allowAdminAccessToAllCollectionItems !== undefined) updateData.allowAdminAccessToAllCollectionItems = body.allowAdminAccessToAllCollectionItems;

    await db.update(organizations).set(updateData).where(eq(organizations.id, orgId));
    const updated = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();

    // 集合管理策略变化会影响组织成员的可见/可操作范围，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId, now);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json(toOrganizationResponse(updated));
});

/**
 * POST /api/organizations/:id/collections
 * 创建集合：需 Owner/Admin 或 createNewCollections 权限（与官方 BulkCollectionOperations.Create 一致）
 */
orgs.post('/:id/collections', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');
    const body = await c.req.json<{ name: string; externalId?: string }>();

    if (!body.name) {
        throw new BadRequestError('Name is required.');
    }

    const orgUser = await getOrgUser(db, orgId, userId);
    if (!canCreateCollection(orgUser)) {
        throw new BadRequestError('Requires Owner, Admin, or Create New Collections permission.');
    }

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

    // 新建集合会影响组织成员的集合列表，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId, now);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({
        id: collectionId,
        organizationId: orgId,
        name: body.name,
        externalId: body.externalId || null,
        object: 'collectionDetails',
    });
});

/** 集合更新请求体：与官方 UpdateCollectionRequestModel 一致，含 groups/users 权限 */
interface CollectionUpdateBody {
    name: string;
    externalId?: string;
    groups?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
    users?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
}

/**
 * PUT /api/organizations/:id/collections/:collectionId
 * 更新集合名称、externalId，并整体替换群组/成员访问权限（与官方 UpdateCollectionCommand 一致）
 * 需 editAnyCollection 或 (Owner/Admin 且 allowAdminAccessToAllCollectionItems)
 */
orgs.put('/:id/collections/:collectionId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const collectionId = c.req.param('collectionId');
    const userId = c.get('userId');
    const body = await c.req.json<CollectionUpdateBody>();

    if (!body.name) {
        throw new BadRequestError('Name is required.');
    }

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!canEditCollection(orgUser, org)) {
        throw new BadRequestError('Requires Edit Any Collection permission or Owner/Admin with access to all collections.');
    }

    const col = await db.select().from(collections)
        .where(and(eq(collections.id, collectionId), eq(collections.organizationId, orgId))).get();
    if (!col) throw new NotFoundError('Collection not found.');

    const groupsList = body.groups ?? [];
    const usersList = body.users ?? [];

    const invalidAssoc = [...groupsList, ...usersList].find(
        (x) => x.manage && (x.readOnly || x.hidePasswords)
    );
    if (invalidAssoc) {
        throw new BadRequestError(
            'The Manage property is mutually exclusive and cannot be true while the ReadOnly or HidePasswords properties are also true.'
        );
    }

    const groupHasManage = groupsList.some((g) => g.manage);
    const userHasManage = usersList.some((u) => u.manage);
    const allowAdminAll = org.allowAdminAccessToAllCollectionItems === true;
    if (!groupHasManage && !userHasManage && !allowAdminAll) {
        throw new BadRequestError('At least one member or group must have can manage permission.');
    }

    const now = new Date().toISOString();
    await db.update(collections).set({
        name: body.name,
        externalId: body.externalId ?? col.externalId ?? null,
        revisionDate: now,
    }).where(eq(collections.id, collectionId));

    await db.delete(collectionUsers).where(eq(collectionUsers.collectionId, collectionId));
    await db.delete(collectionGroups).where(eq(collectionGroups.collectionId, collectionId));

    if (usersList.length > 0) {
        await db.insert(collectionUsers).values(
            usersList.map((u) => ({
                collectionId,
                organizationUserId: u.id,
                readOnly: u.readOnly ?? false,
                hidePasswords: u.hidePasswords ?? false,
                manage: u.manage ?? false,
            }))
        );
    }
    if (org.useGroups && groupsList.length > 0) {
        await db.insert(collectionGroups).values(
            groupsList.map((g) => ({
                collectionId,
                groupId: g.id,
                readOnly: g.readOnly ?? false,
                hidePasswords: g.hidePasswords ?? false,
                manage: g.manage ?? false,
            }))
        );
    }

    const cuList = await db.select().from(collectionUsers).where(eq(collectionUsers.collectionId, collectionId)).all();
    const cgList = await db.select().from(collectionGroups).where(eq(collectionGroups.collectionId, collectionId)).all();

    // 集合的名称 / externalId / 访问权限发生变化，影响成员可访问内容，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId, now);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({
        id: collectionId,
        organizationId: orgId,
        name: body.name,
        externalId: body.externalId ?? col.externalId ?? null,
        object: 'collectionAccessDetails',
        groups: cgList.map((cg) => ({
            id: cg.groupId,
            readOnly: cg.readOnly ?? false,
            hidePasswords: cg.hidePasswords ?? false,
            manage: cg.manage ?? false,
        })),
        users: cuList.map((cu) => ({
            id: cu.organizationUserId,
            readOnly: cu.readOnly ?? false,
            hidePasswords: cu.hidePasswords ?? false,
            manage: cu.manage ?? false,
        })),
    });
});

/**
 * DELETE /api/organizations/:id/collections/:collectionId
 * 需 deleteAnyCollection 或 (Owner/Admin 且 allowAdminAccessToAllCollectionItems)
 */
orgs.delete('/:id/collections/:collectionId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const collectionId = c.req.param('collectionId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!canDeleteCollection(orgUser, org)) {
        throw new BadRequestError('Requires Delete Any Collection permission or Owner/Admin with access to all collections.');
    }

    const col = await db.select().from(collections)
        .where(and(eq(collections.id, collectionId), eq(collections.organizationId, orgId))).get();
    if (!col) throw new NotFoundError('Collection not found.');

    await db.delete(collectionUsers).where(eq(collectionUsers.collectionId, collectionId));
    await db.delete(collectionGroups).where(eq(collectionGroups.collectionId, collectionId));
    await db.delete(collectionCiphers).where(eq(collectionCiphers.collectionId, collectionId));
    await db.delete(collections).where(eq(collections.id, collectionId));

    // 删除单个集合，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({});
});

/**
 * DELETE /api/organizations/:id/collections
 * 对应 CollectionsController.DeleteMany（批量删除集合）
 */
orgs.delete('/:id/collections', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const body = await c.req.json<{ ids: string[] }>();
    if (!body.ids?.length) {
        throw new BadRequestError('No collection ids provided.');
    }

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!canDeleteCollection(orgUser, org)) {
        throw new BadRequestError('Requires Delete Any Collection permission or Owner/Admin with access to all collections.');
    }

    for (const colId of body.ids) {
        const col = await db.select().from(collections)
            .where(and(eq(collections.id, colId), eq(collections.organizationId, orgId))).get();
        if (!col) continue;

        await db.delete(collectionUsers).where(eq(collectionUsers.collectionId, colId));
        await db.delete(collectionGroups).where(eq(collectionGroups.collectionId, colId));
        await db.delete(collectionCiphers).where(eq(collectionCiphers.collectionId, colId));
        await db.delete(collections).where(eq(collections.id, colId));
    }

    // 批量删除集合，同样刷新组织内所有成员的 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({});
});

/**
 * POST /api/organizations/:id/collections/delete
 * 对应 CollectionsController.PostDeleteMany（POST alias）
 */
orgs.post('/:id/collections/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const body = await c.req.json<{ ids: string[] }>();
    if (!body.ids?.length) {
        throw new BadRequestError('No collection ids provided.');
    }

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!canDeleteCollection(orgUser, org)) {
        throw new BadRequestError('Requires Delete Any Collection permission or Owner/Admin with access to all collections.');
    }

    for (const colId of body.ids) {
        const col = await db.select().from(collections)
            .where(and(eq(collections.id, colId), eq(collections.organizationId, orgId))).get();
        if (!col) continue;

        await db.delete(collectionUsers).where(eq(collectionUsers.collectionId, colId));
        await db.delete(collectionGroups).where(eq(collectionGroups.collectionId, colId));
        await db.delete(collectionCiphers).where(eq(collectionCiphers.collectionId, colId));
        await db.delete(collections).where(eq(collections.id, colId));
    }

    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({});
});

// ==================== Groups（组织群组） ====================
// 对应官方 GroupsController
// 若未执行 0008_groups 迁移（groups 表不存在），GET 返回空列表避免 500

function isNoSuchTable(e: unknown): boolean {
    const msg: string = e instanceof Error
        ? e.message
        : e && typeof (e as { cause?: unknown }).cause === 'object' && (e as { cause: Error }).cause instanceof Error
            ? (e as { cause: Error }).cause.message
            : String(e);
    return /no such table:\s*groups/i.test(msg);
}

/**
 * GET /api/organizations/:id/groups
 * 列出组织的所有群组（GroupResponseModel 列表）
 */
orgs.get('/:id/groups', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId); // 官方 ReadAll：任意组织成员可列群组

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!org.useGroups) {
        return c.json({ data: [], object: 'list', continuationToken: null });
    }

    let list: { id: string; organizationId: string; name: string; externalId: string | null }[];
    try {
        list = await db.select().from(groups).where(eq(groups.organizationId, orgId)).all();
    } catch (e) {
        if (isNoSuchTable(e)) return c.json({ data: [], object: 'list', continuationToken: null });
        throw e;
    }
    return c.json({
        data: list.map(g => ({
            id: g.id,
            organizationId: g.organizationId,
            name: g.name,
            externalId: g.externalId ?? null,
            object: 'group',
        })),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/groups/details
 * 列出组织的所有群组（含 collection 权限的 GroupDetailsResponseModel 列表）
 */
orgs.get('/:id/groups/details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    if (!canViewGroupDetails(orgUser)) {
        throw new BadRequestError('Requires Owner, Admin, or Manage Groups/Users permission.');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!org.useGroups) {
        return c.json({ data: [], object: 'list', continuationToken: null });
    }

    let list: { id: string; organizationId: string; name: string; externalId: string | null }[];
    try {
        list = await db.select().from(groups).where(eq(groups.organizationId, orgId)).all();
    } catch (e) {
        if (isNoSuchTable(e)) return c.json({ data: [], object: 'list', continuationToken: null });
        throw e;
    }
    const details = await Promise.all(list.map(async (g) => {
        const cgList = await db.select().from(collectionGroups).where(eq(collectionGroups.groupId, g.id)).all();
        return {
            id: g.id,
            organizationId: g.organizationId,
            name: g.name,
            externalId: g.externalId ?? null,
            object: 'groupDetails',
            collections: cgList.map(cg => ({
                id: cg.collectionId,
                readOnly: cg.readOnly ?? false,
                hidePasswords: cg.hidePasswords ?? false,
                manage: cg.manage ?? false,
            })),
        };
    }));
    return c.json({
        data: details,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/organizations/:id/groups
 * 创建群组（对应官方 GroupsController.Post）
 */
orgs.post('/:id/groups', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!org.useGroups) {
        throw new BadRequestError('This organization cannot use groups.');
    }

    const body = await c.req.json<{
        name: string;
        collections?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
        users?: string[];
    }>();
    if (!body?.name || typeof body.name !== 'string' || body.name.length > 100) {
        throw new BadRequestError('Name is required and must be at most 100 characters.');
    }

    const collectionsList = body.collections ?? [];
    const invalidAssoc = collectionsList.find(c => c.manage && (c.readOnly || c.hidePasswords));
    if (invalidAssoc) {
        throw new BadRequestError('The Manage property is mutually exclusive with ReadOnly or HidePasswords.');
    }

    const groupId = generateUuid();
    const now = new Date().toISOString();

    await db.insert(groups).values({
        id: groupId,
        organizationId: orgId,
        name: body.name.trim(),
        externalId: null,
        creationDate: now,
        revisionDate: now,
    });

    if (collectionsList.length > 0) {
        const collectionIds = collectionsList.map(c => c.id);
        const orgCollections = await db.select().from(collections)
            .where(and(eq(collections.organizationId, orgId), inArray(collections.id, collectionIds)))
            .all();
        const orgCollectionIds = new Set(orgCollections.map(c => c.id));
        for (const col of collectionsList) {
            if (!orgCollectionIds.has(col.id)) continue;
            await db.insert(collectionGroups).values({
                collectionId: col.id,
                groupId,
                readOnly: col.readOnly ?? false,
                hidePasswords: col.hidePasswords ?? false,
                manage: col.manage ?? false,
            });
        }
    }

    const userIds = body.users ?? [];
    if (userIds.length > 0) {
        const orgUserIds = await db.select().from(organizationUsers)
            .where(and(eq(organizationUsers.organizationId, orgId), inArray(organizationUsers.id, userIds)))
            .all();
        for (const ou of orgUserIds) {
            await db.insert(groupUsers).values({ groupId, organizationUserId: ou.id });
        }
    }

    await logEvent(c.env.DB, 1400, {
        organizationId: orgId,
        actingUserId: userId,
        groupId,
        deviceType: getDeviceTypeFromRequest(c),
    }); // Group_Created

    // 新建群组（及其集合/成员关联）会影响成员可访问集合，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId, now);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({
        id: groupId,
        organizationId: orgId,
        name: body.name.trim(),
        externalId: null,
        object: 'group',
    }, 200);
});

/**
 * PUT /api/organizations/:id/groups/:groupId
 * 更新群组（对应官方 GroupsController.Put）
 */
orgs.put('/:id/groups/:groupId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const groupId = c.req.param('groupId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(orgUser);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    if (!org.useGroups) {
        throw new BadRequestError('This organization cannot use groups.');
    }

    const group = await db.select().from(groups)
        .where(and(eq(groups.id, groupId), eq(groups.organizationId, orgId)))
        .get();
    if (!group) throw new NotFoundError('Group not found.');

    const body = await c.req.json<{
        name: string;
        collections?: Array<{ id: string; readOnly?: boolean; hidePasswords?: boolean; manage?: boolean }>;
        users?: string[];
    }>();
    if (!body?.name || typeof body.name !== 'string' || body.name.length > 100) {
        throw new BadRequestError('Name is required and must be at most 100 characters.');
    }

    const collectionsList = body.collections ?? [];
    const invalidAssoc = collectionsList.find(c => c.manage && (c.readOnly || c.hidePasswords));
    if (invalidAssoc) {
        throw new BadRequestError('The Manage property is mutually exclusive with ReadOnly or HidePasswords.');
    }

    const now = new Date().toISOString();
    await db.update(groups).set({
        name: body.name.trim(),
        revisionDate: now,
    }).where(eq(groups.id, groupId));

    await db.delete(collectionGroups).where(eq(collectionGroups.groupId, groupId));
    if (collectionsList.length > 0) {
        const collectionIds = collectionsList.map(c => c.id);
        const orgCollections = await db.select().from(collections)
            .where(and(eq(collections.organizationId, orgId), inArray(collections.id, collectionIds)))
            .all();
        const orgCollectionIds = new Set(orgCollections.map(c => c.id));
        for (const col of collectionsList) {
            if (!orgCollectionIds.has(col.id)) continue;
            await db.insert(collectionGroups).values({
                collectionId: col.id,
                groupId,
                readOnly: col.readOnly ?? false,
                hidePasswords: col.hidePasswords ?? false,
                manage: col.manage ?? false,
            });
        }
    }

    await db.delete(groupUsers).where(eq(groupUsers.groupId, groupId));
    const userIds = body.users ?? [];
    if (userIds.length > 0) {
        const orgUserList = await db.select().from(organizationUsers)
            .where(and(eq(organizationUsers.organizationId, orgId), inArray(organizationUsers.id, userIds)))
            .all();
        for (const ou of orgUserList) {
            await db.insert(groupUsers).values({ groupId, organizationUserId: ou.id });
        }
    }

    await logEvent(c.env.DB, 1401, {
        organizationId: orgId,
        actingUserId: userId,
        groupId,
        deviceType: getDeviceTypeFromRequest(c),
    }); // Group_Updated

    // 群组的集合/成员变更会影响访问控制，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId, now);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({
        id: group.id,
        organizationId: group.organizationId,
        name: body.name.trim(),
        externalId: group.externalId ?? null,
        object: 'group',
    }, 200);
});

/**
 * GET /api/organizations/:id/groups/:groupId/details
 * 单个群组详情（含 collections 权限）
 */
orgs.get('/:id/groups/:groupId/details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const groupId = c.req.param('groupId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(orgUser);

    let group: { id: string; organizationId: string; name: string; externalId: string | null };
    try {
        const row = await db.select().from(groups)
            .where(and(eq(groups.id, groupId), eq(groups.organizationId, orgId)))
            .get();
        if (!row) throw new NotFoundError('Group not found.');
        group = row;
    } catch (e) {
        if (isNoSuchTable(e)) throw new NotFoundError('Group not found.');
        throw e;
    }

    const cgList = await db.select().from(collectionGroups).where(eq(collectionGroups.groupId, groupId)).all();
    return c.json({
        id: group.id,
        organizationId: group.organizationId,
        name: group.name,
        externalId: group.externalId ?? null,
        object: 'groupDetails',
        collections: cgList.map(cg => ({
            id: cg.collectionId,
            readOnly: cg.readOnly ?? false,
            hidePasswords: cg.hidePasswords ?? false,
            manage: cg.manage ?? false,
        })),
    });
});

/**
 * GET /api/organizations/:id/groups/:groupId/users
 * 群组内的组织用户 ID 列表
 */
orgs.get('/:id/groups/:groupId/users', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const groupId = c.req.param('groupId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(orgUser);

    try {
        const group = await db.select().from(groups)
            .where(and(eq(groups.id, groupId), eq(groups.organizationId, orgId)))
            .get();
        if (!group) throw new NotFoundError('Group not found.');

        const guList = await db.select().from(groupUsers).where(eq(groupUsers.groupId, groupId)).all();
        return c.json(guList.map(gu => gu.organizationUserId));
    } catch (e) {
        if (isNoSuchTable(e)) throw new NotFoundError('Group not found.');
        throw e;
    }
});

/**
 * DELETE /api/organizations/:id/groups/:groupId
 * 删除群组（对应官方 GroupsController.Delete）
 */
orgs.delete('/:id/groups/:groupId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const groupId = c.req.param('groupId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    requireOwnerOrAdmin(orgUser);

    const group = await db.select().from(groups)
        .where(and(eq(groups.id, groupId), eq(groups.organizationId, orgId)))
        .get();
    if (!group) throw new NotFoundError('Group not found.');

    await db.delete(groupUsers).where(eq(groupUsers.groupId, groupId));
    await db.delete(collectionGroups).where(eq(collectionGroups.groupId, groupId));
    await db.delete(groups).where(eq(groups.id, groupId));

    await logEvent(c.env.DB, 1402, {
        organizationId: orgId,
        actingUserId: userId,
        groupId,
        deviceType: getDeviceTypeFromRequest(c),
    }); // Group_Deleted

    // 删除群组影响集合访问关系，按组织维度刷新 AccountRevisionDate
    await bumpAccountRevisionDateByOrganizationId(db, orgId);

    c.executionCtx.waitUntil(pushSyncVaultToOrgMembers(c.env, db, orgId));

    return c.json({}, 200);
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
            object: 'collectionDetails',
        })),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/collections/details
 * 列表：每个集合带 groups、users，以及当前用户在该集合上的权限（assigned/manage/readOnly/hidePasswords/unmanaged），与官方 GetManyWithDetails 一致
 * 客户端根据 assigned/manage 显示「权限」列，缺省会显示「无访问权限」
 */
orgs.get('/:id/collections/details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    const orgUserId = orgUser.id;
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    const allowAdminAll = org?.allowAdminAccessToAllCollectionItems === true;
    const isOwnerOrAdmin = orgUser.type === 0 || orgUser.type === 1;

    const cols = await db.select().from(collections).where(eq(collections.organizationId, orgId)).all();
    const collectionIds = cols.map((col) => col.id);

    const cuAll = collectionIds.length > 0
        ? await batchedInArrayQuery<typeof collectionUsers.$inferSelect>(db, collectionUsers, collectionUsers.collectionId, collectionIds)
        : [];
    const cgAll = collectionIds.length > 0
        ? await batchedInArrayQuery<typeof collectionGroups.$inferSelect>(db, collectionGroups, collectionGroups.collectionId, collectionIds)
        : [];

    const cuByCol = new Map<string, typeof cuAll>();
    for (const cu of cuAll) {
        const arr = cuByCol.get(cu.collectionId) ?? [];
        arr.push(cu);
        cuByCol.set(cu.collectionId, arr);
    }
    const cgByCol = new Map<string, typeof cgAll>();
    for (const cg of cgAll) {
        const arr = cgByCol.get(cg.collectionId) ?? [];
        arr.push(cg);
        cgByCol.set(cg.collectionId, arr);
    }

    // 当前用户所属的 groupId 列表（用于判断通过群组获得的集合权限）
    let myGroupIds: string[] = [];
    try {
        const guRows = await db.select({ groupId: groupUsers.groupId }).from(groupUsers)
            .where(eq(groupUsers.organizationUserId, orgUserId)).all();
        myGroupIds = guRows.map((r) => r.groupId);
    } catch (e) {
        if (!isNoSuchTable(e)) throw e;
    }

    const data = cols.map((col) => {
        const colUsers = cuByCol.get(col.id) ?? [];
        const colGroups = cgByCol.get(col.id) ?? [];
        const directUser = colUsers.find((cu) => cu.organizationUserId === orgUserId);
        const myGroupAccess = colGroups.filter((cg) => myGroupIds.includes(cg.groupId));
        const assigned = !!(directUser || myGroupAccess.length > 0) || (allowAdminAll && isOwnerOrAdmin);
        let readOnly = false;
        let hidePasswords = false;
        let manage = false;
        if (allowAdminAll && isOwnerOrAdmin) {
            manage = true;
        } else if (directUser) {
            readOnly = directUser.readOnly ?? false;
            hidePasswords = directUser.hidePasswords ?? false;
            manage = directUser.manage ?? false;
        } else if (myGroupAccess.length > 0) {
            readOnly = myGroupAccess.every((cg) => cg.readOnly);
            hidePasswords = myGroupAccess.every((cg) => cg.hidePasswords);
            manage = myGroupAccess.some((cg) => cg.manage);
        }
        const hasAnyManage = colUsers.some((cu) => cu.manage) || colGroups.some((cg) => cg.manage);
        const unmanaged = !hasAnyManage;

        return {
            id: col.id,
            organizationId: col.organizationId,
            name: col.name,
            externalId: col.externalId,
            object: 'collectionAccessDetails',
            assigned,
            readOnly,
            hidePasswords,
            manage,
            unmanaged,
            groups: colGroups.map((cg) => ({
                id: cg.groupId,
                readOnly: cg.readOnly ?? false,
                hidePasswords: cg.hidePasswords ?? false,
                manage: cg.manage ?? false,
            })),
            users: colUsers.map((cu) => ({
                id: cu.organizationUserId,
                readOnly: cu.readOnly ?? false,
                hidePasswords: cu.hidePasswords ?? false,
                manage: cu.manage ?? false,
            })),
        };
    });

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/collections/:collectionId/details
 * 单条集合详情（含群组/成员权限及当前用户在该集合上的权限），编辑集合时客户端调用
 */
orgs.get('/:id/collections/:collectionId/details', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const collectionId = c.req.param('collectionId');
    const userId = c.get('userId');

    const orgUser = await getOrgUser(db, orgId, userId);
    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    const allowAdminAll = org?.allowAdminAccessToAllCollectionItems === true;
    const isOwnerOrAdmin = orgUser.type === 0 || orgUser.type === 1;

    const col = await db.select().from(collections)
        .where(and(eq(collections.id, collectionId), eq(collections.organizationId, orgId))).get();
    if (!col) throw new NotFoundError('Collection not found.');

    const cuList = await db.select().from(collectionUsers).where(eq(collectionUsers.collectionId, collectionId)).all();
    const cgList = await db.select().from(collectionGroups).where(eq(collectionGroups.collectionId, collectionId)).all();

    let myGroupIds: string[] = [];
    try {
        const guRows = await db.select({ groupId: groupUsers.groupId }).from(groupUsers)
            .where(eq(groupUsers.organizationUserId, orgUser.id)).all();
        myGroupIds = guRows.map((r) => r.groupId);
    } catch (e) {
        if (!isNoSuchTable(e)) throw e;
    }
    const directUser = cuList.find((cu) => cu.organizationUserId === orgUser.id);
    const myGroupAccess = cgList.filter((cg) => myGroupIds.includes(cg.groupId));
    const assigned = !!(directUser || myGroupAccess.length > 0) || (allowAdminAll && isOwnerOrAdmin);
    let readOnly = false;
    let hidePasswords = false;
    let manage = false;
    if (allowAdminAll && isOwnerOrAdmin) {
        manage = true;
    } else if (directUser) {
        readOnly = directUser.readOnly ?? false;
        hidePasswords = directUser.hidePasswords ?? false;
        manage = directUser.manage ?? false;
    } else if (myGroupAccess.length > 0) {
        readOnly = myGroupAccess.every((cg) => cg.readOnly);
        hidePasswords = myGroupAccess.every((cg) => cg.hidePasswords);
        manage = myGroupAccess.some((cg) => cg.manage);
    }
    const unmanaged = !cuList.some((cu) => cu.manage) && !cgList.some((cg) => cg.manage);

    return c.json({
        id: col.id,
        organizationId: col.organizationId,
        name: col.name,
        externalId: col.externalId,
        object: 'collectionAccessDetails',
        assigned,
        readOnly,
        hidePasswords,
        manage,
        unmanaged,
        groups: cgList.map((cg) => ({
            id: cg.groupId,
            readOnly: cg.readOnly ?? false,
            hidePasswords: cg.hidePasswords ?? false,
            manage: cg.manage ?? false,
        })),
        users: cuList.map((cu) => ({
            id: cu.organizationUserId,
            readOnly: cu.readOnly ?? false,
            hidePasswords: cu.hidePasswords ?? false,
            manage: cu.manage ?? false,
        })),
    });
});

// ==================== Billing（计费/订阅） ====================
// 对应官方 Billing/Controllers/OrganizationsController + SelfHostedOrganizationBillingVNextController

/**
 * GET /api/organizations/:id/subscription
 * 组织订阅信息（管理控制台「订阅」页）；自托管下基于组织数据返回，与官方 OrganizationSubscriptionResponseModel 兼容
 */
orgs.get('/:id/subscription', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json(toOrganizationSubscriptionResponse(org));
});

/**
 * GET /api/organizations/:id/billing/vnext/self-host/metadata
 * 自建组织计费元数据（客户端用于成员/席位等展示）
 */
orgs.get('/:id/billing/vnext/self-host/metadata', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getOrgUser(db, orgId, userId);

    const occupied = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.status, 2)))
        .all();

    return c.json({
        isOnSecretsManagerStandalone: false,
        organizationOccupiedSeats: occupied.length,
    });
});

// ==================== 其他辅助端点 ====================

/**
 * GET /api/organizations/:id/plan-type
 */
orgs.get('/:id/plan-type', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    return c.json(org.planType ?? 0);
});

/**
 * GET /api/organizations/:id/auto-enroll-status
 * 自动注册状态（简化）
 */
orgs.get('/:id/auto-enroll-status', async (c) => {
    const orgId = c.req.param('id');

    return c.json({
        id: orgId,
        resetPasswordEnabled: false,
        object: 'organizationAutoEnrollStatus',
    });
});

export { getOrgUser, canCreateCollection, canAccessImportExport };
export default orgs;
