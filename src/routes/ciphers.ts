/**
 * Bitwarden Workers - Ciphers 路由
 * 对应原始项目 Api/Vault/Controllers/CiphersController.cs
 * 处理：密码条目的 CRUD 操作
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, desc, isNull, isNotNull, inArray } from 'drizzle-orm';
import { users, ciphers, folders, collectionCiphers, collections, collectionUsers, collectionGroups, groupUsers, events, organizationUsers, organizations } from '../db/schema';
import { getOrgUser, canCreateCollection, canAccessImportExport } from './organizations';
import { authMiddleware } from '../middleware/auth';
import { logEvent } from '../services/events';
import { toEventResponse } from './events';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { batchedInArrayQuery } from '../services/db';
import { generateUuid } from '../services/crypto';
import { buildAttachmentDownloadUrl } from '../services/attachment-token';
import { putObjectThenPersist, removeMetadataThenDeleteObject } from '../services/storage-compensation';
import type { Bindings, Variables, CipherRequest, CipherResponse, CipherType, CipherRepromptType } from '../types';
import { pushSyncCipher, pushSyncUser } from '../services/push-notification';
import { PushType } from '../types/push-notification';
import { assertPersonalVaultWriteAllowed } from '../services/policy-requirements';
import { assertUserNotClaimedForAccountAction } from '../services/claimed-accounts';

const ciphersRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有端点都需要认证
ciphersRoute.use('/*', authMiddleware);

type CipherRow = typeof ciphers.$inferSelect;
type OrganizationUserRow = typeof organizationUsers.$inferSelect;
type OrganizationRow = typeof organizations.$inferSelect;

type CollectionAccess = {
    collectionId: string;
    readOnly: boolean;
    hidePasswords: boolean;
    manage: boolean;
};

type CipherAccess = {
    cipher: CipherRow;
    collectionIds: string[];
    edit: boolean;
    viewPassword: boolean;
    manage: boolean;
};

async function assertCipherPersonalVaultWriteAllowed(
    db: ReturnType<typeof drizzle>,
    userId: string,
    cipher: Pick<CipherRow, 'organizationId'>,
): Promise<void> {
    if (!cipher.organizationId) {
        await assertPersonalVaultWriteAllowed(db, userId);
    }
}

function buildCipherData(body: Partial<CipherRequest>): Record<string, unknown> {
    const data: Record<string, unknown> = {
        name: body.name ?? '',
        notes: body.notes ?? null,
        fields: body.fields ?? null,
        passwordHistory: body.passwordHistory ?? null,
    };
    if (body.type === 1) data.login = body.login;
    if (body.type === 2) data.secureNote = body.secureNote;
    if (body.type === 3) data.card = body.card;
    if (body.type === 4) data.identity = body.identity;
    if (body.type === 5 && body.sshKey) {
        data.privateKey = body.sshKey.privateKey;
        data.publicKey = body.sshKey.publicKey;
        data.keyFingerprint = body.sshKey.keyFingerprint;
    }
    return data;
}

function buildAttachmentsMap(attachments: any[] | null | undefined): string | null | undefined {
    if (!Array.isArray(attachments)) return undefined;
    const map: Record<string, { fileName: string | null; key: string | null; size: string; validated?: boolean }> = {};
    for (const attachment of attachments) {
        if (!attachment?.id) continue;
        map[attachment.id] = {
            fileName: attachment.fileName ?? null,
            key: attachment.key ?? null,
            size: String(attachment.size ?? '0'),
            validated: attachment.validated ?? true,
        };
    }
    return Object.keys(map).length > 0 ? JSON.stringify(map) : null;
}

function parseOrgPermissions(permissions: string | null): Record<string, unknown> {
    if (!permissions) return {};
    try {
        return JSON.parse(permissions) as Record<string, unknown>;
    } catch {
        return {};
    }
}

function canAccessAllOrgItems(orgUser: OrganizationUserRow, org: OrganizationRow | null | undefined): boolean {
    if (orgUser.type === 0) return true;
    if (orgUser.type === 1 && org?.allowAdminAccessToAllCollectionItems === true) return true;
    const permissions = parseOrgPermissions(orgUser.permissions);
    return permissions.editAnyCollection === true || permissions.deleteAnyCollection === true;
}

async function getCollectionAccessForOrgUser(
    db: ReturnType<typeof drizzle>,
    organizationUserId: string,
): Promise<CollectionAccess[]> {
    const directRows = await db.select().from(collectionUsers)
        .where(eq(collectionUsers.organizationUserId, organizationUserId))
        .all();

    const groupRows = await db.select({ groupId: groupUsers.groupId }).from(groupUsers)
        .where(eq(groupUsers.organizationUserId, organizationUserId))
        .all();
    const groupIds = groupRows.map((row) => row.groupId);
    const groupAccess = groupIds.length > 0
        ? await batchedInArrayQuery<typeof collectionGroups.$inferSelect>(
            db, collectionGroups, collectionGroups.groupId, groupIds)
        : [];

    const byCollection = new Map<string, CollectionAccess>();
    for (const row of directRows) {
        byCollection.set(row.collectionId, {
            collectionId: row.collectionId,
            readOnly: row.readOnly ?? false,
            hidePasswords: row.hidePasswords ?? false,
            manage: row.manage ?? false,
        });
    }

    for (const row of groupAccess) {
        const existing = byCollection.get(row.collectionId);
        if (!existing) {
            byCollection.set(row.collectionId, {
                collectionId: row.collectionId,
                readOnly: row.readOnly ?? false,
                hidePasswords: row.hidePasswords ?? false,
                manage: row.manage ?? false,
            });
            continue;
        }
        existing.readOnly = existing.readOnly && (row.readOnly ?? false);
        existing.hidePasswords = existing.hidePasswords && (row.hidePasswords ?? false);
        existing.manage = existing.manage || (row.manage ?? false);
    }

    return [...byCollection.values()];
}

async function getCipherAccess(db: ReturnType<typeof drizzle>, cipherId: string, userId: string): Promise<CipherAccess> {
    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found.');
    if (!cipher.organizationId) {
        if (cipher.userId !== userId) throw new NotFoundError('Cipher not found.');
        return { cipher, collectionIds: [], edit: true, viewPassword: true, manage: true };
    }

    const orgUser = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, cipher.organizationId),
            eq(organizationUsers.userId, userId),
        )).get();
    if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Cipher not found.');

    const org = await db.select().from(organizations).where(eq(organizations.id, cipher.organizationId)).get();
    const cipherCollections = await db.select().from(collectionCiphers)
        .where(eq(collectionCiphers.cipherId, cipher.id))
        .all();
    const collectionIds = cipherCollections.map((row) => row.collectionId);

    if (canAccessAllOrgItems(orgUser, org)) {
        return { cipher, collectionIds, edit: true, viewPassword: true, manage: true };
    }

    const collectionAccess = await getCollectionAccessForOrgUser(db, orgUser.id);
    const accessByCollection = new Map(collectionAccess.map((entry) => [entry.collectionId, entry]));
    const matchingAccess = collectionIds
        .map((collectionId) => accessByCollection.get(collectionId))
        .filter((entry): entry is CollectionAccess => !!entry);
    if (matchingAccess.length === 0) throw new NotFoundError('Cipher not found.');

    return {
        cipher,
        collectionIds,
        edit: matchingAccess.some((entry) => !entry.readOnly || entry.manage),
        viewPassword: matchingAccess.some((entry) => !entry.hidePasswords),
        manage: matchingAccess.some((entry) => entry.manage),
    };
}

async function getAccessibleCipher(db: ReturnType<typeof drizzle>, cipherId: string, userId: string): Promise<CipherRow> {
    return (await getCipherAccess(db, cipherId, userId)).cipher;
}

async function getEditableCipher(db: ReturnType<typeof drizzle>, cipherId: string, userId: string): Promise<CipherRow> {
    const access = await getCipherAccess(db, cipherId, userId);
    if (!access.edit) throw new NotFoundError('Cipher not found.');
    return access.cipher;
}

async function getAdminCipher(db: ReturnType<typeof drizzle>, cipherId: string, userId: string): Promise<CipherRow> {
    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher || !cipher.organizationId) throw new NotFoundError('Cipher not found.');
    const orgUser = await getOrgUser(db, cipher.organizationId, userId);
    if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Cipher not found.');
    const org = await db.select().from(organizations).where(eq(organizations.id, cipher.organizationId)).get();
    if (!canAccessAllOrgItems(orgUser, org)) {
        const access = await getCipherAccess(db, cipherId, userId);
        if (!access.manage) throw new NotFoundError('Cipher not found.');
    }
    return cipher;
}

async function replaceCipherCollections(
    db: ReturnType<typeof drizzle>,
    cipher: CipherRow,
    collectionIds: string[],
): Promise<void> {
    if (!cipher.organizationId) throw new NotFoundError('Cipher not found.');
    const uniqueIds = [...new Set(collectionIds)];
    if (uniqueIds.length > 0) {
        const orgCollections = await db.select({ id: collections.id }).from(collections)
            .where(and(eq(collections.organizationId, cipher.organizationId), inArray(collections.id, uniqueIds)))
            .all();
        const validIds = new Set(orgCollections.map((r) => r.id));
        if (uniqueIds.some((id) => !validIds.has(id))) {
            throw new BadRequestError('One or more collections not found or do not belong to this organization.');
        }
    }
    await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, cipher.id));
    if (uniqueIds.length > 0) {
        await db.insert(collectionCiphers).values(
            uniqueIds.map((collectionId) => ({ collectionId, cipherId: cipher.id })),
        ).onConflictDoNothing();
    }
}

/** 从请求 URL 中提取 baseUrl（protocol + host），用于构建附件绝对下载 URL */
function getBaseUrl(c: any): string {
    const url = new URL(c.req.url);
    // 通过反向代理/隧道（如 trycloudflare）时，内部请求可能是 http，
    // 需要从 X-Forwarded-Proto 获取客户端实际使用的协议
    const proto = c.req.header('x-forwarded-proto') || url.protocol.replace(':', '');
    return `${proto}://${url.host}`;
}

/**
 * 从 multipart form 中提取上传文件
 * 官方 .NET 服务端用 Request.Form.Files.FirstOrDefault() 获取第一个文件，
 * 不依赖特定字段名。这里兼容 'data'、'file' 以及任意字段名的 File。
 */
async function extractFileFromRequest(c: any): Promise<{ file: File; formData: Record<string, any> }> {
    const formData = await c.req.parseBody({ all: true });
    // 优先检查 'data' 字段（官方客户端标准字段名）
    if (formData['data'] instanceof File) {
        return { file: formData['data'], formData };
    }
    // 兼容 'file' 字段名
    if (formData['file'] instanceof File) {
        return { file: formData['file'], formData };
    }
    // 最后遍历所有字段，找到第一个 File 对象
    for (const key of Object.keys(formData)) {
        const val = formData[key];
        if (val instanceof File) {
            return { file: val, formData };
        }
        // parseBody({ all: true }) 可能返回数组
        if (Array.isArray(val)) {
            for (const item of val) {
                if (item instanceof File) {
                    return { file: item, formData };
                }
            }
        }
    }
    throw new BadRequestError('File data is required.');
}

/**
 * 将数据库记录转换为 Bitwarden API 响应格式
 * objectType: "cipher" 用于单个 CRUD 端点, "cipherDetails" 用于列表/sync, "cipherMiniDetails" 用于 GET .../admin
 */
export async function toCipherResponse(cipher: any, userId: string, baseUrl: string, secret: string, objectType: 'cipher' | 'cipherDetails' | 'cipherMiniDetails' = 'cipher'): Promise<CipherResponse> {
    const data = JSON.parse(cipher.data || '{}');
    const favorites = cipher.favorites ? JSON.parse(cipher.favorites) : {};
    const folders = cipher.folders ? JSON.parse(cipher.folders) : {};
    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    const attachments = await Promise.all(Object.keys(attachmentsMap).map(async (id) => {
        const a = attachmentsMap[id];
        const sizeBytes = parseInt(a.size || '0');
        const sizeName = sizeBytes >= 1048576 ? `${(sizeBytes / 1048576).toFixed(2)} MB` :
            sizeBytes >= 1024 ? `${(sizeBytes / 1024).toFixed(2)} KB` :
                `${sizeBytes} Bytes`;
        return {
            id: id,
            fileName: a.fileName,
            key: a.key,
            size: a.size || '0',
            sizeName: sizeName,
            url: await buildAttachmentDownloadUrl(baseUrl, cipher.id, id, secret),
        };
    }));

    // SSH key: 兼容旧的嵌套存储 (data.sshKey.xxx) 和新的扁平存储 (data.xxx)
    // 如果 keyFingerprint 缺失则不返回 sshKey（iOS 要求该字段为非空 String）
    let sshKeyData: { privateKey: string; publicKey: string; keyFingerprint: string } | undefined;
    if (cipher.type === 5) {
        const pk = data.privateKey || data.sshKey?.privateKey;
        const pub = data.publicKey || data.sshKey?.publicKey;
        const fp = data.keyFingerprint || data.sshKey?.keyFingerprint;
        if (pk && pub && fp) {
            sshKeyData = { privateKey: pk, publicKey: pub, keyFingerprint: fp };
        }
    }

    return {
        id: cipher.id,
        organizationId: cipher.organizationId,
        folderId: folders[userId] || null,
        type: cipher.type as CipherType,
        data: cipher.data,
        name: data.name || '',
        notes: data.notes || null,
        favorite: !!favorites[userId],
        reprompt: (cipher.reprompt ?? 0) as CipherRepromptType,
        login: cipher.type === 1 ? data.login : undefined,
        card: cipher.type === 3 ? data.card : undefined,
        identity: cipher.type === 4 ? data.identity : undefined,
        secureNote: cipher.type === 2 ? data.secureNote : undefined,
        sshKey: sshKeyData,
        fields: data.fields || null,
        passwordHistory: data.passwordHistory || null,
        attachments: attachments.length > 0 ? attachments : null,
        organizationUseTotp: false,
        revisionDate: cipher.revisionDate,
        creationDate: cipher.creationDate,
        deletedDate: cipher.deletedDate,
        archivedDate: cipher.archivedDate || null,
        key: cipher.key,
        object: objectType,
        collectionIds: [], // 个人 cipher 无 collection
        edit: true,
        viewPassword: true,
        permissions: {
            delete: true,
            restore: true,
            edit: true,
            viewPassword: true,
            manage: true,
        },
    };
}

/**
 * GET /api/ciphers
 * 对应 CiphersController.GetAll
 */
ciphersRoute.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    const results = await db.select().from(ciphers)
        .where(and(eq(ciphers.userId, userId), isNull(ciphers.deletedDate))).all();

    const baseUrl = getBaseUrl(c);
    const data = await Promise.all(results.map((cipher) =>
        toCipherResponse(cipher, userId, baseUrl, c.env.JWT_SECRET, 'cipherDetails')));

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/ciphers/organization-details
 * 对应 CiphersController.GetOrganizationCiphers
 * 返回组织的所有密码条目（管理员视图）
 */
ciphersRoute.get('/organization-details', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const organizationId = c.req.query('organizationId');

    if (!organizationId) {
        throw new BadRequestError('organizationId is required.');
    }

    const orgUser = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, organizationId),
            eq(organizationUsers.userId, userId)
        )).get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found.');
    }
    const org = await db.select().from(organizations).where(eq(organizations.id, organizationId)).get();
    if (!org || !canAccessAllOrgItems(orgUser, org)) {
        throw new NotFoundError('Organization not found.');
    }

    const orgCiphers = await db.select().from(ciphers)
        .where(eq(ciphers.organizationId, organizationId))
        .all();

    const cipherCollectionMap: Record<string, string[]> = {};
    if (orgCiphers.length > 0) {
        const cipherIds = orgCiphers.map(ci => ci.id);
        const orgCollCiphers = await batchedInArrayQuery<{ cipherId: string; collectionId: string }>(
            db, collectionCiphers, collectionCiphers.cipherId, cipherIds);
        for (const cc of orgCollCiphers) {
            if (!cipherCollectionMap[cc.cipherId]) cipherCollectionMap[cc.cipherId] = [];
            cipherCollectionMap[cc.cipherId].push(cc.collectionId);
        }
    }

    const baseUrl = getBaseUrl(c);
    const data = await Promise.all(orgCiphers.map(async (cipher) => {
        const resp = await toCipherResponse(cipher, userId, baseUrl, c.env.JWT_SECRET, 'cipherDetails');
        return {
            ...resp,
            collectionIds: cipherCollectionMap[cipher.id] || [],
            object: 'cipherMiniDetails',
        };
    }));

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/ciphers/organization-details/assigned
 * 对应 CiphersController.GetAssignedOrganizationCiphers
 * 返回用户在组织中被分配的密码条目
 */
ciphersRoute.get('/organization-details/assigned', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const organizationId = c.req.query('organizationId');

    if (!organizationId) {
        throw new BadRequestError('organizationId is required.');
    }

    const orgUser = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, organizationId),
            eq(organizationUsers.userId, userId)
        )).get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found.');
    }
    const org = await db.select().from(organizations).where(eq(organizations.id, organizationId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    const canAccessAll = canAccessAllOrgItems(orgUser, org);
    const allowedCollectionIds = canAccessAll
        ? null
        : new Set((await getCollectionAccessForOrgUser(db, orgUser.id)).map((entry) => entry.collectionId));

    const orgCiphers = await db.select().from(ciphers)
        .where(eq(ciphers.organizationId, organizationId))
        .all();

    const cipherCollectionMap: Record<string, string[]> = {};
    if (orgCiphers.length > 0) {
        const cipherIds = orgCiphers.map(ci => ci.id);
        const orgCollCiphers = await batchedInArrayQuery<{ cipherId: string; collectionId: string }>(
            db, collectionCiphers, collectionCiphers.cipherId, cipherIds);
        for (const cc of orgCollCiphers) {
            if (!cipherCollectionMap[cc.cipherId]) cipherCollectionMap[cc.cipherId] = [];
            cipherCollectionMap[cc.cipherId].push(cc.collectionId);
        }
    }

    const baseUrl = getBaseUrl(c);
    const assignedCiphers = canAccessAll
        ? orgCiphers
        : orgCiphers.filter((cipher) =>
            (cipherCollectionMap[cipher.id] || []).some((collectionId) => allowedCollectionIds?.has(collectionId)));

    const data = await Promise.all(assignedCiphers.map(async (cipher) => {
        const resp = await toCipherResponse(cipher, userId, baseUrl, c.env.JWT_SECRET, 'cipherDetails');
        return {
            ...resp,
            collectionIds: cipherCollectionMap[cipher.id] || [],
        };
    }));

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/ciphers/:id/details
 * 对应 CiphersController.GetDetails
 * 返回单个 cipher 的详细信息（供 Web / App 客户端使用）
 */
ciphersRoute.get('/:id/details', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getAccessibleCipher(db, cipherId, userId);
    return c.json(await toCipherResponse(cipher, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherDetails'));
});

/**
 * GET /api/ciphers/:id/full-details
 * 上游保留的 details 旧别名，官方旧客户端仍可能调用。
 */
ciphersRoute.get('/:id/full-details', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipher = await getAccessibleCipher(db, c.req.param('id'), userId);
    return c.json(await toCipherResponse(cipher, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherDetails'));
});

/**
 * GET /api/ciphers/:id/admin
 * 对应 CiphersController.GetAdmin
 * 管理员查看组织内任意密码条目（需 ViewAllCollections 权限：Owner/Admin 或 EditAnyCollection/DeleteAnyCollection）
 */
ciphersRoute.get('/:id/admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getAdminCipher(db, cipherId, userId);

    const cipherCollections = await db.select().from(collectionCiphers)
        .where(eq(collectionCiphers.cipherId, cipherId)).all();
    const collectionIds = cipherCollections.map(cc => cc.collectionId);

    const resp = await toCipherResponse(cipher, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherMiniDetails');
    resp.collectionIds = collectionIds;
    return c.json(resp);
});

/**
 * GET /api/ciphers/:id
 * 对应 CiphersController.Get
 */
ciphersRoute.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getAccessibleCipher(db, cipherId, userId);
    return c.json(await toCipherResponse(cipher, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * GET /api/ciphers/:id/events
 * 对应 CiphersController.GetEvents
 */
ciphersRoute.get('/:id/events', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getEditableCipher(db, cipherId, userId);

    const cipherEvents = await db.select().from(events)
        .where(eq(events.cipherId, cipherId))
        .orderBy(desc(events.date))
        .limit(50)
        .all();

    return c.json({
        data: cipherEvents.map(toEventResponse),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /api/ciphers/:id/attachment
 * 对应 CiphersController.PostAttachmentV1 (及 V2 等上传附件 API)
 */
const uploadAttachmentHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getEditableCipher(db, cipherId, userId);
    await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);

    const { file, formData } = await extractFileFromRequest(c);

    const attachmentId = generateUuid();
    // 存储在 R2 的 key = {cipherId}/{attachmentId}
    const r2Key = `${cipherId}/${attachmentId}`;

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    attachmentsMap[attachmentId] = {
        fileName: formData.filename || file.name || 'file',
        key: formData.key || '',
        size: file.size.toString()
    };

    const now = new Date().toISOString();
    await putObjectThenPersist(
        c.env.ATTACHMENTS, r2Key, file.stream(),
        { httpMetadata: { contentType: file.type } },
        async () => {
            await db.update(ciphers).set({
                attachments: JSON.stringify(attachmentsMap),
                revisionDate: now
            }).where(eq(ciphers.id, cipherId));
        },
    );

    await logEvent(c.env.DB, 1103, { userId, cipherId });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        cipher.organizationId ? null : userId, cipher.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
};

ciphersRoute.post('/:id/attachment', uploadAttachmentHandler);
ciphersRoute.post('/:id/attachment-admin', uploadAttachmentHandler);

/**
 * POST /api/ciphers/:id/attachment/v2
 * 对应 CiphersController.PostAttachment (v2 延迟上传流程)
 * 第一步：客户端发送附件元数据，服务端返回 attachmentId 和上传 URL
 * 第二步：客户端通过 POST /:id/attachment/:attachmentId 上传实际文件
 */
ciphersRoute.post('/:id/attachment/v2', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await getEditableCipher(db, cipherId, userId);
    await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);

    const body = await c.req.json<{
        key?: string;
        fileName?: string;
        fileSize?: number;
        adminRequest?: boolean;
        lastKnownRevisionDate?: string;
    }>();

    const attachmentId = generateUuid();

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    attachmentsMap[attachmentId] = {
        fileName: body.fileName || 'file',
        key: body.key || '',
        size: (body.fileSize || 0).toString(),
        validated: false,
    };

    const now = new Date().toISOString();
    await db.update(ciphers).set({
        attachments: JSON.stringify(attachmentsMap),
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const baseUrl = getBaseUrl(c);
    const isAdmin = !!body.adminRequest;
    const cipherResp = await toCipherResponse(
        updated!, userId, baseUrl, c.env.JWT_SECRET, isAdmin ? 'cipherMiniDetails' : 'cipherDetails');

    return c.json({
        attachmentId,
        url: `${cipherId}/attachment/${attachmentId}`,
        fileUploadType: 0, // Direct
        cipherResponse: isAdmin ? null : cipherResp,
        cipherMiniResponse: isAdmin ? cipherResp : null,
        object: 'attachment-fileUpload',
    });
});

/**
 * POST /api/ciphers/:id/attachment/:attachmentId
 * v2 第二步：上传实际文件到已创建的 attachment
 */
ciphersRoute.post('/:id/attachment/:attachmentId', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');

    const cipher = await getEditableCipher(db, cipherId, userId);
    await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }

    const { file } = await extractFileFromRequest(c);

    const r2Key = `${cipherId}/${attachmentId}`;
    attachmentsMap[attachmentId].size = file.size.toString();
    attachmentsMap[attachmentId].validated = true;

    const now = new Date().toISOString();
    await putObjectThenPersist(
        c.env.ATTACHMENTS, r2Key, file.stream(),
        { httpMetadata: { contentType: file.type } },
        async () => {
            await db.update(ciphers).set({
                attachments: JSON.stringify(attachmentsMap),
                revisionDate: now,
            }).where(eq(ciphers.id, cipherId));
        },
    );

    await logEvent(c.env.DB, 1103, { userId, cipherId });

    return c.json(null, 200);
});

/**
 * GET /api/ciphers/:id/attachment/:attachmentId/renew
 * 对应 CiphersController.RenewFileUploadUrl - 续期上传 URL
 */
ciphersRoute.get('/:id/attachment/:attachmentId/renew', async (c) => {
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');

    return c.json({
        url: `${cipherId}/attachment/${attachmentId}`,
        fileUploadType: 0, // Direct
        object: 'attachment-fileUpload',
    });
});

/**
 * GET /api/ciphers/:id/attachment/:attachmentId
 * 对应 CiphersController.GetAttachmentData
 * 返回附件下载 URL（iOS 客户端用此 URL 再请求实际文件）
 */
ciphersRoute.get('/:id/attachment/:attachmentId', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');

    const cipher = await getAccessibleCipher(db, cipherId, userId);

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    const meta = attachmentsMap[attachmentId];
    if (!meta) {
        throw new NotFoundError('Attachment metadata not found.');
    }

    const downloadUrl = await buildAttachmentDownloadUrl(getBaseUrl(c), cipherId, attachmentId, c.env.JWT_SECRET);

    const sizeBytes = parseInt(meta.size || '0');
    const sizeName = sizeBytes >= 1048576 ? `${(sizeBytes / 1048576).toFixed(2)} MB` :
        sizeBytes >= 1024 ? `${(sizeBytes / 1024).toFixed(2)} KB` :
            `${sizeBytes} Bytes`;

    return c.json({
        id: attachmentId,
        url: downloadUrl,
        fileName: meta.fileName,
        key: meta.key,
        size: meta.size || '0',
        sizeName: sizeName,
        object: 'attachment',
    });
});

/**
 * DELETE /api/ciphers/:id/attachment/:attachmentId
 * 删除附件
 */
const deleteAttachmentHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');

    const cipher = await getEditableCipher(db, cipherId, userId);
    await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }

    delete attachmentsMap[attachmentId];

    const now = new Date().toISOString();
    const updatedAttachments = Object.keys(attachmentsMap).length > 0 ? JSON.stringify(attachmentsMap) : null;
    const r2Key = `${cipherId}/${attachmentId}`;
    await removeMetadataThenDeleteObject(
        c.env.ATTACHMENTS, r2Key,
        async () => {
            await db.update(ciphers).set({
                attachments: updatedAttachments,
                revisionDate: now
            }).where(eq(ciphers.id, cipherId));
        },
        async () => {
            await db.update(ciphers).set({
                attachments: cipher.attachments,
                revisionDate: cipher.revisionDate,
            }).where(eq(ciphers.id, cipherId));
        },
    );

    await logEvent(c.env.DB, 1104, { userId, cipherId });

    // 官方返回 DeleteAttachmentResponseModel，包含更新后的 cipher
    const updatedCipher = { ...cipher, attachments: updatedAttachments, revisionDate: now };
    const baseUrl = getBaseUrl(c);
    return c.json({
        cipher: await toCipherResponse(updatedCipher, userId, baseUrl, c.env.JWT_SECRET, 'cipher'),
        object: 'deleteAttachment',
    }, 200);
};

ciphersRoute.delete('/:id/attachment/:attachmentId', deleteAttachmentHandler);
ciphersRoute.delete('/:id/attachment/:attachmentId/admin', deleteAttachmentHandler);
ciphersRoute.post('/:id/attachment/:attachmentId/delete', deleteAttachmentHandler);
ciphersRoute.post('/:id/attachment/:attachmentId/delete-admin', deleteAttachmentHandler);

/**
 * GET /api/ciphers/attachment/download
 * 兼容上游自托管附件下载入口。当前 Workers 的附件响应仍返回
 * /attachments/:cipherId/:attachmentId 公共下载 URL；这里补充 query 入口。
 */
ciphersRoute.get('/attachment/download', async (c) => {
    const cipherId = c.req.query('cipherId') || c.req.query('id');
    const attachmentId = c.req.query('attachmentId');
    if (!cipherId || !attachmentId) {
        throw new NotFoundError('Attachment not found.');
    }

    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipher = await getAccessibleCipher(db, cipherId, userId);
    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }

    const object = await c.env.ATTACHMENTS.get(`${cipherId}/${attachmentId}`);
    if (!object) throw new NotFoundError('Attachment not found.');

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Length', object.size.toString());
    headers.set('Cache-Control', 'private, max-age=0, no-store');
    return new Response(object.body, { headers });
});

/**
 * POST /api/ciphers/attachment/validate/azure
 * R2 直传不使用 Azure EventGrid；返回最小成功响应以兼容客户端回调。
 */
ciphersRoute.post('/attachment/validate/azure', (c) => c.json({ object: 'eventGridValidation' }));

/**
 * POST /api/ciphers/:id/attachment/:attachmentId/share
 * 分享 cipher 时附件内容已经在原 R2 key 下；Workers 不需要复制对象。
 */
ciphersRoute.post('/:id/attachment/:attachmentId/share', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const attachmentId = c.req.param('attachmentId');
    const cipher = await getAccessibleCipher(db, cipherId, userId);
    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }
    return c.body(null, 200);
});

/**
 * POST /api/ciphers
 * 对应 CiphersController.Post
 */
ciphersRoute.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<CipherRequest>();

    if (!body.type || !body.name) {
        throw new BadRequestError('Type and name are required.');
    }
    if (!body.organizationId) {
        await assertPersonalVaultWriteAllowed(db, userId);
    }

    const now = new Date().toISOString();
    const cipherId = generateUuid();

    // 构建 data JSON
    const data: any = {
        name: body.name,
        notes: body.notes || null,
        fields: body.fields || null,
        passwordHistory: body.passwordHistory || null,
    };

    // 根据类型存储对应数据
    if (body.type === 1) data.login = body.login;
    if (body.type === 2) data.secureNote = body.secureNote;
    if (body.type === 3) data.card = body.card;
    if (body.type === 4) data.identity = body.identity;
    if (body.type === 5 && body.sshKey) {
        data.privateKey = body.sshKey.privateKey;
        data.publicKey = body.sshKey.publicKey;
        data.keyFingerprint = body.sshKey.keyFingerprint;
    }

    // favorites 和 folders 使用 per-user 格式
    const favorites: Record<string, boolean> = {};
    if (body.favorite) favorites[userId] = true;

    const folders: Record<string, string> = {};
    if (body.folderId) folders[userId] = body.folderId;

    await db.insert(ciphers).values({
        id: cipherId,
        userId,
        organizationId: body.organizationId || null,
        type: body.type,
        data: JSON.stringify(data),
        favorites: JSON.stringify(favorites),
        folders: JSON.stringify(folders),
        reprompt: body.reprompt ?? 0,
        key: body.key || null,
        creationDate: now,
        revisionDate: now,
    });

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const created = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    // 更新 CollectionCiphers
    if (body.organizationId && body.collectionIds && body.collectionIds.length > 0) {
        for (const colId of body.collectionIds) {
            await db.insert(collectionCiphers).values({
                collectionId: colId,
                cipherId: cipherId,
            }).onConflictDoNothing();
        }
    }

    await logEvent(c.env.DB, 1100, { userId, cipherId });

    // 推送通知（不阻塞响应）
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherCreate, cipherId,
        body.organizationId ? null : userId, body.organizationId || null,
        body.collectionIds || null, now, contextId,
    ));

    return c.json(await toCipherResponse(created!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * POST /api/ciphers/create
 * 对应 CiphersController.PostCreate（用于带附件的创建）
 */
ciphersRoute.post('/create', async (c) => {
    // 简化处理，委托给 POST / 处理
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<any>();
    const cipherBody: CipherRequest = body.cipher || body;

    if (!cipherBody.type || !cipherBody.name) {
        throw new BadRequestError('Type and name are required.');
    }
    if (!cipherBody.organizationId) {
        await assertPersonalVaultWriteAllowed(db, userId);
    }

    const now = new Date().toISOString();
    const cipherId = generateUuid();

    const data: any = {
        name: cipherBody.name,
        notes: cipherBody.notes || null,
        fields: cipherBody.fields || null,
        passwordHistory: cipherBody.passwordHistory || null,
    };
    if (cipherBody.type === 1) data.login = cipherBody.login;
    if (cipherBody.type === 2) data.secureNote = cipherBody.secureNote;
    if (cipherBody.type === 3) data.card = cipherBody.card;
    if (cipherBody.type === 4) data.identity = cipherBody.identity;
    if (cipherBody.type === 5 && cipherBody.sshKey) {
        data.privateKey = cipherBody.sshKey.privateKey;
        data.publicKey = cipherBody.sshKey.publicKey;
        data.keyFingerprint = cipherBody.sshKey.keyFingerprint;
    }

    const favorites: Record<string, boolean> = {};
    if (cipherBody.favorite) favorites[userId] = true;
    const folders: Record<string, string> = {};
    if (cipherBody.folderId) folders[userId] = cipherBody.folderId;

    await db.insert(ciphers).values({
        id: cipherId,
        userId,
        organizationId: cipherBody.organizationId || null,
        type: cipherBody.type,
        data: JSON.stringify(data),
        favorites: JSON.stringify(favorites),
        folders: JSON.stringify(folders),
        reprompt: cipherBody.reprompt ?? 0,
        key: cipherBody.key || null,
        creationDate: now,
        revisionDate: now,
    });

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    await logEvent(c.env.DB, 1100, { userId, cipherId });

    const created = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(await toCipherResponse(created!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * POST /api/ciphers/admin
 * 管理员创建组织 cipher。保持与普通创建相同的密文存储语义。
 */
ciphersRoute.post('/admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<CipherRequest & { collectionIds?: string[] }>();

    if (!body.organizationId) throw new BadRequestError('organizationId is required.');
    const orgUser = await getOrgUser(db, body.organizationId, userId);
    if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Organization not found.');
    if (!body.type || !body.name) throw new BadRequestError('Type and name are required.');

    const now = new Date().toISOString();
    const cipherId = generateUuid();
    await db.insert(ciphers).values({
        id: cipherId,
        userId: null,
        organizationId: body.organizationId,
        type: body.type,
        data: JSON.stringify(buildCipherData(body)),
        favorites: JSON.stringify({}),
        folders: JSON.stringify({}),
        reprompt: body.reprompt ?? 0,
        key: body.key || null,
        creationDate: now,
        revisionDate: now,
    });

    const collectionIds = Array.isArray(body.collectionIds) ? body.collectionIds : [];
    const created = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (created && collectionIds.length > 0) {
        await replaceCipherCollections(db, created, collectionIds);
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1100, { userId, cipherId, organizationId: body.organizationId });

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherCreate, cipherId,
        null, body.organizationId, collectionIds.length ? collectionIds : null, now, contextId,
    ));

    const response = await toCipherResponse(created!, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherMiniDetails');
    response.collectionIds = collectionIds;
    return c.json(response);
});

/**
 * PUT /api/ciphers/:id/collections-admin
 * 对应 CiphersController.PutCollectionsAdmin：管理员更新密码条目所属集合
 */
ciphersRoute.put('/:id/collections-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json<{ collectionIds: string[] }>();

    const collectionIds = Array.isArray(body.collectionIds) ? body.collectionIds : [];

    const cipher = await db.select().from(ciphers)
        .where(eq(ciphers.id, cipherId)).get();
    if (!cipher || !cipher.organizationId) {
        throw new NotFoundError('Cipher not found.');
    }

    const orgId = cipher.organizationId;
    const orgUser = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            eq(organizationUsers.userId, userId)
        )).get();
    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Cipher not found.');
    }

    if (collectionIds.length > 0) {
        const orgCollections = await db.select({ id: collections.id }).from(collections)
            .where(and(eq(collections.organizationId, orgId), inArray(collections.id, collectionIds)))
            .all();
        const validIds = new Set(orgCollections.map((r) => r.id));
        const invalid = collectionIds.filter((id) => !validIds.has(id));
        if (invalid.length > 0) {
            throw new BadRequestError('One or more collections not found or do not belong to this organization.');
        }
    }

    const now = new Date().toISOString();
    await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, cipherId));
    if (collectionIds.length > 0) {
        await db.insert(collectionCiphers).values(
            collectionIds.map((collId) => ({ cipherId, collectionId: collId }))
        );
    }
    await db.update(ciphers).set({ revisionDate: now }).where(eq(ciphers.id, cipherId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const baseUrl = getBaseUrl(c);
    const resp = await toCipherResponse(updated!, userId, baseUrl, c.env.JWT_SECRET, 'cipherDetails');
    return c.json({
        ...resp,
        collectionIds,
        object: 'cipherMiniDetails',
    });
});

const updateCipherCollectionsHandler = async (c: any, options: { admin: boolean; v2: boolean }) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json() as { collectionIds?: string[] };
    const collectionIds = Array.isArray(body.collectionIds) ? body.collectionIds : [];

    const cipher = options.admin
        ? await getAdminCipher(db, cipherId, userId)
        : await getAccessibleCipher(db, cipherId, userId);
    await replaceCipherCollections(db, cipher, collectionIds);

    const now = new Date().toISOString();
    await db.update(ciphers).set({ revisionDate: now }).where(eq(ciphers.id, cipherId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const response = {
        ...await toCipherResponse(
            updated!, userId, getBaseUrl(c), c.env.JWT_SECRET,
            options.admin ? 'cipherMiniDetails' : 'cipherDetails',
        ),
        collectionIds,
    };

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        cipher.organizationId ? null : userId, cipher.organizationId || null,
        collectionIds, now, contextId,
    ));

    if (options.v2) {
        return c.json({ unavailable: false, cipher: response, object: 'optionalCipherDetails' });
    }
    return c.json(response);
};

ciphersRoute.put('/:id/collections', (c) => updateCipherCollectionsHandler(c, { admin: false, v2: false }));
ciphersRoute.post('/:id/collections', (c) => updateCipherCollectionsHandler(c, { admin: false, v2: false }));
ciphersRoute.put('/:id/collections_v2', (c) => updateCipherCollectionsHandler(c, { admin: false, v2: true }));
ciphersRoute.post('/:id/collections_v2', (c) => updateCipherCollectionsHandler(c, { admin: false, v2: true }));
ciphersRoute.post('/:id/collections-admin', (c) => updateCipherCollectionsHandler(c, { admin: true, v2: false }));

/**
 * POST /api/ciphers/bulk-collections
 * 对应 CiphersController.PostBulkCollections
 * 批量为 cipher 添加/移除 collection 关联
 */
ciphersRoute.post('/bulk-collections', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        organizationId: string;
        cipherIds: string[];
        collectionIds: string[];
        removeCollections?: boolean;
    }>();

    const { organizationId, cipherIds, collectionIds, removeCollections } = body;
    if (!organizationId || !cipherIds?.length || !collectionIds?.length) {
        throw new BadRequestError('organizationId, cipherIds, and collectionIds are required.');
    }

    const orgUser = await getOrgUser(db, organizationId, userId);
    if (!orgUser) throw new NotFoundError('Organization not found.');

    // 验证 ciphers 属于该组织
    const orgCiphers = await batchedInArrayQuery<{ id: string; organizationId: string | null }>(
        db, ciphers, ciphers.id, cipherIds);
    for (const ci of orgCiphers) {
        if (ci.organizationId !== organizationId) {
            throw new BadRequestError('Cipher does not belong to the organization.');
        }
    }
    if (orgCiphers.length !== cipherIds.length) {
        throw new NotFoundError('One or more ciphers not found.');
    }

    // 验证 collections 属于该组织
    const orgCols = await batchedInArrayQuery<{ id: string; organizationId: string }>(
        db, collections, collections.id, collectionIds);
    for (const col of orgCols) {
        if (col.organizationId !== organizationId) {
            throw new BadRequestError('Collection does not belong to the organization.');
        }
    }

    if (removeCollections) {
        // 移除关联：逐批删除
        for (const collectionId of collectionIds) {
            for (let i = 0; i < cipherIds.length; i += 50) {
                const batch = cipherIds.slice(i, i + 50);
                await db.delete(collectionCiphers).where(
                    and(
                        eq(collectionCiphers.collectionId, collectionId),
                        inArray(collectionCiphers.cipherId, batch),
                    )
                );
            }
        }
    } else {
        // 添加关联
        const toInsert: { collectionId: string; cipherId: string }[] = [];
        for (const collectionId of collectionIds) {
            for (const cipherId of cipherIds) {
                toInsert.push({ collectionId, cipherId });
            }
        }
        const BATCH = 50;
        for (let i = 0; i < toInsert.length; i += BATCH) {
            const chunk = toInsert.slice(i, i + BATCH);
            await db.insert(collectionCiphers).values(chunk).onConflictDoNothing();
        }
    }

    return c.json({});
});

/**
 * POST /api/ciphers/import-organization
 * 对应 ImportCiphersController.PostImportOrganization：组织保险库导入（集合 + 密码条目 + 关系）
 */
ciphersRoute.post('/import-organization', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const organizationId = c.req.query('organizationId');
    if (!organizationId) {
        throw new BadRequestError('organizationId is required.');
    }

    const body = await c.req.json<{
        collections?: Array<{ id?: string; name: string; externalId?: string }>;
        ciphers: CipherRequest[];
        collectionRelationships?: Array<{ key: number; value: number }>;
    }>();
    const collectionsList = body.collections ?? [];
    const ciphersList = body.ciphers ?? [];
    const collectionRelationships = body.collectionRelationships ?? [];

    const org = await db.select().from(organizations).where(eq(organizations.id, organizationId)).get();
    if (!org) throw new NotFoundError('Organization not found.');
    const orgUser = await getOrgUser(db, organizationId, userId);

    const orgCollectionIds = new Set(
        (await db.select({ id: collections.id }).from(collections).where(eq(collections.organizationId, organizationId))).map((r) => r.id)
    );
    const existingCollections = collectionsList.filter((col) => col.id && orgCollectionIds.has(col.id));
    const hasNewCollections = collectionsList.some((col) => !col.id || !orgCollectionIds.has(col.id));

    let authorized = canAccessImportExport(orgUser);
    if (!authorized && collectionsList.length === 0) authorized = true;
    else if (!authorized) {
        if (hasNewCollections && existingCollections.length > 0) {
            authorized = canCreateCollection(orgUser) && canAccessImportExport(orgUser);
        } else if (hasNewCollections) {
            authorized = canCreateCollection(orgUser);
        } else {
            authorized = canAccessImportExport(orgUser);
        }
    }
    if (!authorized) {
        throw new BadRequestError('Not enough privileges to import into this organization.');
    }

    if (org.maxCollections != null && collectionsList.length > 0) {
        const currentCount = orgCollectionIds.size;
        const newCount = collectionsList.filter((col) => !col.id || !orgCollectionIds.has(col.id)).length;
        if (org.maxCollections < currentCount + newCount) {
            throw new BadRequestError(
                'This organization can only have a maximum of ' + org.maxCollections + ' collections.'
            );
        }
    }

    const now = new Date().toISOString();
    const cipherIdMap = new Map<number, string>();
    for (let i = 0; i < ciphersList.length; i++) {
        cipherIdMap.set(i, generateUuid());
    }
    const collectionIdMap = new Map<number, string>();
    const newCollectionRows: { id: string; organizationId: string; name: string; externalId: string | null; creationDate: string; revisionDate: string }[] = [];
    for (let i = 0; i < collectionsList.length; i++) {
        const col = collectionsList[i];
        const existingId = col.id && orgCollectionIds.has(col.id) ? col.id : null;
        if (existingId) {
            collectionIdMap.set(i, existingId);
        } else {
            const newId = generateUuid();
            collectionIdMap.set(i, newId);
            newCollectionRows.push({
                id: newId,
                organizationId,
                name: col.name,
                externalId: col.externalId ?? null,
                creationDate: now,
                revisionDate: now,
            });
        }
    }

    // D1 单条 SQL 绑定变量上限约 100，每行 6 列，每批最多 floor(100/6)=16 条，取 10 留余量
    const COLLECTION_BATCH = 10;
    if (newCollectionRows.length > 0) {
        for (let i = 0; i < newCollectionRows.length; i += COLLECTION_BATCH) {
            const chunk = newCollectionRows.slice(i, i + COLLECTION_BATCH);
            await db.insert(collections).values(chunk);
        }
        for (const row of newCollectionRows) {
            await db.insert(collectionUsers).values({
                collectionId: row.id,
                organizationUserId: orgUser.id,
                readOnly: false,
                hidePasswords: false,
                manage: true,
            }).onConflictDoNothing();
        }
    }

    for (let i = 0; i < ciphersList.length; i++) {
        const bodyCipher = ciphersList[i];
        const cipherId = cipherIdMap.get(i);
        if (!cipherId) continue;
        const data: Record<string, unknown> = {
            name: bodyCipher.name,
            notes: bodyCipher.notes ?? null,
            fields: bodyCipher.fields ?? null,
            passwordHistory: bodyCipher.passwordHistory ?? null,
        };
        if (bodyCipher.type === 1) data.login = bodyCipher.login;
        if (bodyCipher.type === 2) data.secureNote = bodyCipher.secureNote;
        if (bodyCipher.type === 3) data.card = bodyCipher.card;
        if (bodyCipher.type === 4) data.identity = bodyCipher.identity;
        if (bodyCipher.type === 5 && bodyCipher.sshKey) {
            data.privateKey = bodyCipher.sshKey.privateKey;
            data.publicKey = bodyCipher.sshKey.publicKey;
            data.keyFingerprint = bodyCipher.sshKey.keyFingerprint;
        }
        const fav = bodyCipher.favorite ? { [userId]: true } : {};
        await db.insert(ciphers).values({
            id: cipherId,
            userId: null,
            organizationId,
            type: bodyCipher.type,
            data: JSON.stringify(data),
            favorites: JSON.stringify(fav),
            folders: JSON.stringify({}),
            reprompt: bodyCipher.reprompt ?? 0,
            key: bodyCipher.key ?? null,
            creationDate: now,
            revisionDate: now,
        });
    }

    const toInsert: { collectionId: string; cipherId: string }[] = [];
    for (const rel of collectionRelationships) {
        const cipherId = cipherIdMap.get(rel.key);
        const collectionId = collectionIdMap.get(rel.value);
        if (cipherId && collectionId) {
            toInsert.push({ collectionId, cipherId });
        }
    }
    console.log('[import-org] collections from request:', JSON.stringify(collectionsList.map((c, i) => ({ index: i, id: c.id, hasId: !!c.id }))));
    console.log('[import-org] orgCollectionIds:', JSON.stringify([...orgCollectionIds]));
    console.log('[import-org] newCollectionRows count:', newCollectionRows.length, 'total collections:', collectionsList.length);
    console.log('[import-org] cipherIdMap size:', cipherIdMap.size, 'toInsert size:', toInsert.length);
    // D1 绑定变量上限约 100，每行 2 列，每批最多 50 条
    const COLLECTION_CIPHER_BATCH = 50;
    for (let i = 0; i < toInsert.length; i += COLLECTION_CIPHER_BATCH) {
        const chunk = toInsert.slice(i, i + COLLECTION_CIPHER_BATCH);
        if (chunk.length > 0) {
            await db.insert(collectionCiphers).values(chunk).onConflictDoNothing();
        }
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    return c.json({});
});

/**
 * POST /api/ciphers/import
 * 对应 ImportCiphersController.PostImport：个人保险库导入（文件夹 + 密码条目 + 关系）
 * 必须定义在 post('/:id') 之前，否则 "import" 会被当作 cipher id 匹配导致 Cipher not found.
 */
ciphersRoute.post('/import', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        folders?: Array<{ id?: string; name: string }>;
        ciphers: CipherRequest[];
        folderRelationships?: Array<{ key: number; value: number }>;
    }>();
    const foldersList = body.folders ?? [];
    const ciphersList = body.ciphers ?? [];
    const folderRelationships = body.folderRelationships ?? [];
    await assertPersonalVaultWriteAllowed(db, userId);

    const userFolderIds = new Set(
        (await db.select({ id: folders.id }).from(folders).where(eq(folders.userId, userId))).map((r) => r.id)
    );

    const now = new Date().toISOString();
    const cipherIdMap = new Map<number, string>();
    for (let i = 0; i < ciphersList.length; i++) {
        cipherIdMap.set(i, generateUuid());
    }
    const folderIdMap = new Map<number, string>();
    const newFolderRows: { id: string; userId: string; name: string; creationDate: string; revisionDate: string }[] = [];
    for (let i = 0; i < foldersList.length; i++) {
        const f = foldersList[i];
        const existingId = f.id && userFolderIds.has(f.id) ? f.id : null;
        if (existingId) {
            folderIdMap.set(i, existingId);
        } else {
            const newId = generateUuid();
            folderIdMap.set(i, newId);
            newFolderRows.push({
                id: newId,
                userId,
                name: f.name,
                creationDate: now,
                revisionDate: now,
            });
        }
    }
    if (newFolderRows.length > 0) {
        for (const row of newFolderRows) {
            await db.insert(folders).values(row);
        }
    }

    for (let i = 0; i < ciphersList.length; i++) {
        const bodyCipher = ciphersList[i];
        const cipherId = cipherIdMap.get(i);
        if (!cipherId) continue;
        const folderForCipher = folderRelationships.find((r) => r.key === i);
        const folderId = folderForCipher != null ? folderIdMap.get(folderForCipher.value) : null;
        const foldersJson: Record<string, string> = folderId ? { [userId]: folderId } : {};

        const data: Record<string, unknown> = {
            name: bodyCipher.name,
            notes: bodyCipher.notes ?? null,
            fields: bodyCipher.fields ?? null,
            passwordHistory: bodyCipher.passwordHistory ?? null,
        };
        if (bodyCipher.type === 1) data.login = bodyCipher.login;
        if (bodyCipher.type === 2) data.secureNote = bodyCipher.secureNote;
        if (bodyCipher.type === 3) data.card = bodyCipher.card;
        if (bodyCipher.type === 4) data.identity = bodyCipher.identity;
        if (bodyCipher.type === 5 && bodyCipher.sshKey) {
            data.privateKey = bodyCipher.sshKey.privateKey;
            data.publicKey = bodyCipher.sshKey.publicKey;
            data.keyFingerprint = bodyCipher.sshKey.keyFingerprint;
        }
        const fav = bodyCipher.favorite ? { [userId]: true } : {};
        await db.insert(ciphers).values({
            id: cipherId,
            userId,
            organizationId: null,
            type: bodyCipher.type,
            data: JSON.stringify(data),
            favorites: JSON.stringify(fav),
            folders: JSON.stringify(foldersJson),
            reprompt: bodyCipher.reprompt ?? 0,
            key: bodyCipher.key ?? null,
            creationDate: now,
            revisionDate: now,
        });
        await logEvent(c.env.DB, 1100, { userId, cipherId });
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));
    return c.json({});
});

/**
 * PUT /api/ciphers/:id/delete
 * 对应 CiphersController.PutDelete（软删除 alt 路由）
 */
ciphersRoute.put('/:id/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');

    const now = new Date().toISOString();
    await db.update(ciphers).set({ deletedDate: now, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    await logEvent(c.env.DB, 1115, { userId, cipherId });

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherDelete, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.body(null, 204);
});

/**
 * PUT /api/ciphers/:id/restore
 * 对应 CiphersController.PutRestore（从回收站恢复）
 */
ciphersRoute.put('/:id/restore', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

    const now = new Date().toISOString();
    await db.update(ciphers).set({ deletedDate: null, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    await logEvent(c.env.DB, 1116, { userId, cipherId });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * PUT /api/ciphers/delete
 * 对应 CiphersController.PutDeleteMany（批量软删除）
 */
ciphersRoute.put('/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const now = new Date().toISOString();
    for (const id of body.ids) {
        await db.update(ciphers).set({ deletedDate: now, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId)));
        await logEvent(c.env.DB, 1115, { userId, cipherId: id });
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

/**
 * POST /api/ciphers/delete
 * 对应 CiphersController.DeleteMany（批量永久删除）
 */
ciphersRoute.post('/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    for (const id of body.ids) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (cipher) {
            // 删除关联附件
            if (cipher.attachments) {
                const attachmentsMap = JSON.parse(cipher.attachments);
                for (const attachmentId of Object.keys(attachmentsMap)) {
                    await c.env.ATTACHMENTS.delete(`${id}/${attachmentId}`);
                }
            }
            await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, id));
            await db.delete(ciphers).where(eq(ciphers.id, id));
            await logEvent(c.env.DB, 1102, { userId, cipherId: id });
        }
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    // 批量操作推送全量同步
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

/**
 * PUT /api/ciphers/delete-admin
 * 对应 CiphersController.PutDeleteManyAdmin（管理员批量软删除）
 */
ciphersRoute.put('/delete-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; organizationId: string }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const orgUser = await getOrgUser(db, body.organizationId, userId);
    if (!orgUser) throw new NotFoundError('Organization not found.');

    const now = new Date().toISOString();
    for (const id of body.ids) {
        await db.update(ciphers).set({ deletedDate: now, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.organizationId, body.organizationId)));
        await logEvent(c.env.DB, 1115, { userId, cipherId: id, organizationId: body.organizationId });
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

/**
 * POST /api/ciphers/delete-admin
 * 对应 CiphersController.PostDeleteManyAdmin（管理员批量永久删除）
 */
ciphersRoute.post('/delete-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; organizationId: string }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const orgUser = await getOrgUser(db, body.organizationId, userId);
    if (!orgUser) throw new NotFoundError('Organization not found.');

    for (const id of body.ids) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.organizationId, body.organizationId))).get();
        if (cipher) {
            if (cipher.attachments) {
                const attachmentsMap = JSON.parse(cipher.attachments);
                for (const attachmentId of Object.keys(attachmentsMap)) {
                    await c.env.ATTACHMENTS.delete(`${id}/${attachmentId}`);
                }
            }
            await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, id));
            await db.delete(ciphers).where(eq(ciphers.id, id));
            await logEvent(c.env.DB, 1102, { userId, cipherId: id, organizationId: body.organizationId });
        }
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

/**
 * PUT /api/ciphers/restore
 * 对应 CiphersController.PutRestoreMany（批量恢复）
 */
ciphersRoute.put('/restore', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const now = new Date().toISOString();
    const results: any[] = [];
    for (const id of body.ids) {
        const existing = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (!existing) continue;
        await assertCipherPersonalVaultWriteAllowed(db, userId, existing);
        await db.update(ciphers).set({ deletedDate: null, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId)));
        await logEvent(c.env.DB, 1116, { userId, cipherId: id });
        const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();
        if (updated) results.push(await toCipherResponse(updated, userId, getBaseUrl(c), c.env.JWT_SECRET));
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json({ data: results, object: 'list', continuationToken: null });
});

/**
 * PUT /api/ciphers/restore-admin
 * 对应 CiphersController.PutRestoreManyAdmin（管理员批量恢复）
 */
ciphersRoute.put('/restore-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; organizationId: string }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const orgUser = await getOrgUser(db, body.organizationId, userId);
    if (!orgUser) throw new NotFoundError('Organization not found.');

    const now = new Date().toISOString();
    const results: any[] = [];
    for (const id of body.ids) {
        await db.update(ciphers).set({ deletedDate: null, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.organizationId, body.organizationId)));
        await logEvent(c.env.DB, 1116, { userId, cipherId: id, organizationId: body.organizationId });
        const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();
        if (updated) results.push(await toCipherResponse(updated, userId, getBaseUrl(c), c.env.JWT_SECRET));
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json({ data: results, object: 'list', continuationToken: null });
});

/**
 * PUT/POST /api/ciphers/share
 * 对应 CiphersController PutShareMany/PostShareMany（批量分享到组织）
 *
 * 兼容两种客户端请求形态：
 * - 旧形态：{ ciphers: [{ cipher, collectionIds }] }
 * - 新 Web：{ ciphers: [cipher], collectionIds? }
 */
const shareManyCiphersHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json() as {
        ciphers?: Array<
            | (CipherRequest & { id?: string; organizationId?: string; collectionIds?: string[] })
            | { cipher?: CipherRequest & { id?: string; organizationId?: string }; collectionIds?: string[] }
        >;
        collectionIds?: string[];
    };

    const now = new Date().toISOString();
    for (const item of body.ciphers ?? []) {
        const itemAny = item as any;
        const cipher = (itemAny.cipher ?? itemAny) as CipherRequest & {
            id?: string;
            organizationId?: string;
            collectionIds?: string[];
        };
        if (!cipher.id || !cipher.organizationId) continue;

        const existing = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, cipher.id), eq(ciphers.userId, userId))).get();
        if (!existing) continue;

        const orgUser = await getOrgUser(db, cipher.organizationId, userId);
        if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Organization not found.');

        const collectionIds = Array.isArray(itemAny.collectionIds)
            ? itemAny.collectionIds
            : Array.isArray(cipher.collectionIds)
                ? cipher.collectionIds
                : Array.isArray(body.collectionIds)
                    ? body.collectionIds
                    : [];
        const attachments = buildAttachmentsMap(cipher.attachments);

        await db.update(ciphers).set({
            organizationId: cipher.organizationId,
            userId: null,
            data: JSON.stringify(buildCipherData(cipher)),
            attachments: attachments === undefined ? existing.attachments : attachments,
            key: cipher.key ?? existing.key,
            revisionDate: now,
        }).where(eq(ciphers.id, cipher.id));

        const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipher.id)).get();
        if (updated) await replaceCipherCollections(db, updated, collectionIds);
        await logEvent(c.env.DB, 1101, { userId, cipherId: cipher.id, organizationId: cipher.organizationId });
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncCiphers, userId, contextId));

    return c.json({});
};

ciphersRoute.put('/share', shareManyCiphersHandler);
ciphersRoute.post('/share', shareManyCiphersHandler);

/**
 * PUT /api/ciphers/move
 * 对应 CiphersController.PutMoveMany（批量移动到文件夹）
 */
ciphersRoute.put('/move', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; folderId: string | null }>();

    const now = new Date().toISOString();
    for (const id of body.ids) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (cipher) {
            await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);
            const folders = cipher.folders ? JSON.parse(cipher.folders) : {};
            if (body.folderId) folders[userId] = body.folderId;
            else delete folders[userId];
            await db.update(ciphers).set({ folders: JSON.stringify(folders), revisionDate: now })
                .where(eq(ciphers.id, id));
        }
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncCiphers, userId, contextId));

    return c.json(null, 200);
});

/**
 * POST /api/ciphers/purge
 * 对应批量永久删除（清空回收站）
 */
ciphersRoute.post('/purge', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ masterPasswordHash: string }>();

    // 验证密码
    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const { verifyPassword } = await import('../services/crypto');
    const valid = await verifyPassword(body.masterPasswordHash, user.masterPassword || '');
    if (!valid) throw new BadRequestError('Invalid master password.');
    await assertUserNotClaimedForAccountAction(
        db,
        userId,
        'Claimed organization accounts cannot purge their vault.',
    );

    // 永久删除所有已软删除（在回收站）的 ciphers
    const softDeleted = await db.select({ id: ciphers.id }).from(ciphers)
        .where(and(eq(ciphers.userId, userId), isNotNull(ciphers.deletedDate))).all();

    for (const cipher of softDeleted) {
        await db.delete(ciphers).where(eq(ciphers.id, cipher.id));
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.body(null, 204);
});

const partialCipherHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json() as { folderId?: string | null; favorite?: boolean };

    const existing = await getAccessibleCipher(db, cipherId, userId);
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);
    const now = new Date().toISOString();
    const favorites = existing.favorites ? JSON.parse(existing.favorites) : {};
    const folderMap = existing.folders ? JSON.parse(existing.folders) : {};

    if (body.favorite !== undefined) {
        if (body.favorite) favorites[userId] = true;
        else delete favorites[userId];
    }
    if (body.folderId !== undefined) {
        if (body.folderId) folderMap[userId] = body.folderId;
        else delete folderMap[userId];
    }

    await db.update(ciphers).set({
        favorites: JSON.stringify(favorites),
        folders: JSON.stringify(folderMap),
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));
    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
};

ciphersRoute.put('/:id/partial', partialCipherHandler);
ciphersRoute.post('/:id/partial', partialCipherHandler);

const adminUpdateCipherHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json() as CipherRequest & { collectionIds?: string[] };

    const existing = await getAdminCipher(db, cipherId, userId);
    const now = new Date().toISOString();
    await db.update(ciphers).set({
        type: body.type ?? existing.type,
        data: JSON.stringify(buildCipherData(body)),
        reprompt: body.reprompt ?? existing.reprompt,
        key: body.key !== undefined ? body.key : existing.key,
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

    const collectionIds = Array.isArray(body.collectionIds) ? body.collectionIds : null;
    if (collectionIds) {
        await replaceCipherCollections(db, existing, collectionIds);
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1101, { userId, cipherId, organizationId: existing.organizationId ?? undefined });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        null, existing.organizationId, collectionIds, now, contextId,
    ));
    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherMiniDetails'));
};

ciphersRoute.put('/:id/admin', adminUpdateCipherHandler);
ciphersRoute.post('/:id/admin', adminUpdateCipherHandler);

const shareCipherHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json() as { cipher?: CipherRequest & { id?: string; organizationId?: string }; collectionIds?: string[] };
    const cipherBody = body.cipher ?? (body as any);
    if (!cipherBody.organizationId) throw new BadRequestError('organizationId is required.');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    const orgUser = await getOrgUser(db, cipherBody.organizationId, userId);
    if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Organization not found.');

    const now = new Date().toISOString();
    await db.update(ciphers).set({
        organizationId: cipherBody.organizationId,
        userId: null,
        data: JSON.stringify(buildCipherData(cipherBody)),
        key: cipherBody.key ?? existing.key,
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const collectionIds = Array.isArray(body.collectionIds) ? body.collectionIds : [];
    if (updated) await replaceCipherCollections(db, updated, collectionIds);

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        null, cipherBody.organizationId, collectionIds, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
};

ciphersRoute.put('/:id/share', shareCipherHandler);
ciphersRoute.post('/:id/share', shareCipherHandler);

ciphersRoute.post('/move', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; folderId: string | null }>();

    const now = new Date().toISOString();
    for (const id of body.ids ?? []) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (!cipher) continue;
        await assertCipherPersonalVaultWriteAllowed(db, userId, cipher);
        const folderMap = cipher.folders ? JSON.parse(cipher.folders) : {};
        if (body.folderId) folderMap[userId] = body.folderId;
        else delete folderMap[userId];
        await db.update(ciphers).set({ folders: JSON.stringify(folderMap), revisionDate: now })
            .where(eq(ciphers.id, id));
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncCiphers, userId, contextId));
    return c.json(null, 200);
});

ciphersRoute.post('/:id/delete', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    if (existing.attachments) {
        const attachmentsMap = JSON.parse(existing.attachments);
        for (const attachmentId of Object.keys(attachmentsMap)) {
            await c.env.ATTACHMENTS.delete(`${cipherId}/${attachmentId}`);
        }
    }
    await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, cipherId));
    await db.delete(ciphers).where(eq(ciphers.id, cipherId));
    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1102, { userId, cipherId });
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(c.env, PushType.SyncCipherDelete, cipherId, userId, null, null, now, contextId));
    return c.body(null, 204);
});

ciphersRoute.post('/:id/delete-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const existing = await getAdminCipher(db, cipherId, userId);
    if (existing.attachments) {
        const attachmentsMap = JSON.parse(existing.attachments);
        for (const attachmentId of Object.keys(attachmentsMap)) {
            await c.env.ATTACHMENTS.delete(`${cipherId}/${attachmentId}`);
        }
    }
    await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, cipherId));
    await db.delete(ciphers).where(eq(ciphers.id, cipherId));
    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1102, { userId, cipherId, organizationId: existing.organizationId ?? undefined });
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(c.env, PushType.SyncCipherDelete, cipherId, null, existing.organizationId, null, now, contextId));
    return c.body(null, 204);
});

ciphersRoute.put('/:id/delete-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const existing = await getAdminCipher(db, cipherId, userId);
    const now = new Date().toISOString();
    await db.update(ciphers).set({ deletedDate: now, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1115, { userId, cipherId, organizationId: existing.organizationId ?? undefined });
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(c.env, PushType.SyncCipherDelete, cipherId, null, existing.organizationId, null, now, contextId));
    return c.body(null, 204);
});

ciphersRoute.put('/:id/restore-admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const existing = await getAdminCipher(db, cipherId, userId);
    const now = new Date().toISOString();
    await db.update(ciphers).set({ deletedDate: null, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1116, { userId, cipherId, organizationId: existing.organizationId ?? undefined });
    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(c.env, PushType.SyncCipherUpdate, cipherId, null, existing.organizationId, null, now, contextId));
    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET, 'cipherMiniDetails'));
});

/**
 * PUT /api/ciphers/archive
 * 对应 CiphersController.PutArchiveMany（批量归档）
 *
 * 必须注册在 PUT /:id 之前，否则 Hono 会把 /archive 当作 id=archive。
 */
ciphersRoute.put('/archive', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids || body.ids.length === 0) throw new BadRequestError('No IDs provided.');
    if (body.ids.length > 500) throw new BadRequestError('You can only archive up to 500 items at a time.');

    const now = new Date().toISOString();
    const results: any[] = [];

    for (const id of body.ids) {
        const existing = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (!existing) continue;
        await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

        await db.update(ciphers).set({ archivedDate: now, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId)));

        const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();
        if (updated) results.push(updated);

        const contextId = c.get('jwtPayload')?.device || null;
        c.executionCtx.waitUntil(pushSyncCipher(
            c.env, PushType.SyncCipherUpdate, id,
            existing.organizationId ? null : userId, existing.organizationId || null,
            null, now, contextId,
        ));
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const baseUrl = getBaseUrl(c);
    return c.json({
        data: await Promise.all(results.map(r => toCipherResponse(r, userId, baseUrl, c.env.JWT_SECRET))),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * PUT /api/ciphers/unarchive
 * 对应 CiphersController.PutUnarchiveMany（批量取消归档）
 *
 * 必须注册在 PUT /:id 之前，否则 Hono 会把 /unarchive 当作 id=unarchive。
 */
ciphersRoute.put('/unarchive', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids || body.ids.length === 0) throw new BadRequestError('No IDs provided.');
    if (body.ids.length > 500) throw new BadRequestError('You can only unarchive up to 500 items at a time.');

    const now = new Date().toISOString();
    const results: any[] = [];

    for (const id of body.ids) {
        const existing = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (!existing) continue;
        await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

        await db.update(ciphers).set({ archivedDate: null, revisionDate: now })
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId)));

        const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();
        if (updated) results.push(updated);

        const contextId = c.get('jwtPayload')?.device || null;
        c.executionCtx.waitUntil(pushSyncCipher(
            c.env, PushType.SyncCipherUpdate, id,
            existing.organizationId ? null : userId, existing.organizationId || null,
            null, now, contextId,
        ));
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const baseUrl = getBaseUrl(c);
    return c.json({
        data: await Promise.all(results.map(r => toCipherResponse(r, userId, baseUrl, c.env.JWT_SECRET))),
        object: 'list',
        continuationToken: null,
    });
});

// ==================== 通配符 /:id 路由（必须在所有静态路由之后注册） ====================

/**
 * POST /api/ciphers/:id (alias for PUT, Bitwarden 客户端兼容)
 */
ciphersRoute.post('/:id', async (c) => {
    const id = c.req.param('id');
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<CipherRequest>();

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

    const now = new Date().toISOString();
    const data: any = {
        name: body.name,
        notes: body.notes || null,
        fields: body.fields || null,
        passwordHistory: body.passwordHistory || null,
    };
    if (body.type === 1) data.login = body.login;
    if (body.type === 2) data.secureNote = body.secureNote;
    if (body.type === 3) data.card = body.card;
    if (body.type === 4) data.identity = body.identity;
    if (body.type === 5 && body.sshKey) {
        data.privateKey = body.sshKey.privateKey;
        data.publicKey = body.sshKey.publicKey;
        data.keyFingerprint = body.sshKey.keyFingerprint;
    }

    const existingFavorites = existing.favorites ? JSON.parse(existing.favorites) : {};
    const existingFolders = existing.folders ? JSON.parse(existing.folders) : {};
    if (body.favorite !== undefined) {
        if (body.favorite) existingFavorites[userId] = true;
        else delete existingFavorites[userId];
    }
    if (body.folderId !== undefined) {
        if (body.folderId) existingFolders[userId] = body.folderId;
        else delete existingFolders[userId];
    }

    await db.update(ciphers).set({
        type: body.type ?? existing.type,
        data: JSON.stringify(data),
        favorites: JSON.stringify(existingFavorites),
        folders: JSON.stringify(existingFolders),
        reprompt: body.reprompt ?? existing.reprompt,
        key: body.key !== undefined ? body.key : existing.key,
        revisionDate: now,
    }).where(eq(ciphers.id, id));

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1101, { userId, cipherId: id });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, id,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * DELETE /api/ciphers/:id
 * 对应 CiphersController.Delete（永久删除）
 */
/**
 * DELETE /api/ciphers
 * 对应 CiphersController.DeleteMany（批量永久删除个人 cipher）
 */
ciphersRoute.delete('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[] }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    for (const id of body.ids) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
        if (cipher) {
            if (cipher.attachments) {
                const attachmentsMap = JSON.parse(cipher.attachments);
                for (const attachmentId of Object.keys(attachmentsMap)) {
                    await c.env.ATTACHMENTS.delete(`${id}/${attachmentId}`);
                }
            }
            await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, id));
            await db.delete(ciphers).where(eq(ciphers.id, id));
            await logEvent(c.env.DB, 1102, { userId, cipherId: id });
        }
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

/**
 * DELETE /api/ciphers/admin
 * 对应 CiphersController.DeleteManyAdmin（管理员批量永久删除组织 cipher）
 */
ciphersRoute.delete('/admin', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{ ids: string[]; organizationId: string }>();

    if (!body.ids?.length) {
        throw new BadRequestError('No cipher ids provided.');
    }

    const orgUser = await getOrgUser(db, body.organizationId, userId);
    if (!orgUser) throw new NotFoundError('Organization not found.');

    for (const id of body.ids) {
        const cipher = await db.select().from(ciphers)
            .where(and(eq(ciphers.id, id), eq(ciphers.organizationId, body.organizationId))).get();
        if (cipher) {
            if (cipher.attachments) {
                const attachmentsMap = JSON.parse(cipher.attachments);
                for (const attachmentId of Object.keys(attachmentsMap)) {
                    await c.env.ATTACHMENTS.delete(`${id}/${attachmentId}`);
                }
            }
            await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, id));
            await db.delete(ciphers).where(eq(ciphers.id, id));
            await logEvent(c.env.DB, 1102, { userId, cipherId: id, organizationId: body.organizationId });
        }
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncVault, userId, contextId));

    return c.json(null, 200);
});

ciphersRoute.delete('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');

    if (existing.attachments) {
        const attachmentsMap = JSON.parse(existing.attachments);
        for (const attachmentId of Object.keys(attachmentsMap)) {
            await c.env.ATTACHMENTS.delete(`${cipherId}/${attachmentId}`);
        }
    }

    await db.delete(collectionCiphers).where(eq(collectionCiphers.cipherId, cipherId));
    await db.delete(ciphers).where(eq(ciphers.id, cipherId));

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1102, { userId, cipherId });

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherDelete, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.body(null, 204);
});

/**
 * PUT /api/ciphers/:id
 * 对应 CiphersController.Put
 */
ciphersRoute.put('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');
    const body = await c.req.json<CipherRequest>();

    // 同时支持个人和组织 cipher
    let existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) {
        // 尝试查找组织 cipher（管理员编辑）
        existing = await db.select().from(ciphers)
            .where(eq(ciphers.id, cipherId)).get();
        if (existing?.organizationId) {
            await getOrgUser(db, existing.organizationId, userId);
        } else {
            throw new NotFoundError('Cipher not found.');
        }
    }
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

    const now = new Date().toISOString();
    const data: any = {
        name: body.name,
        notes: body.notes || null,
        fields: body.fields || null,
        passwordHistory: body.passwordHistory || null,
    };
    if (body.type === 1) data.login = body.login;
    if (body.type === 2) data.secureNote = body.secureNote;
    if (body.type === 3) data.card = body.card;
    if (body.type === 4) data.identity = body.identity;
    if (body.type === 5 && body.sshKey) {
        data.privateKey = body.sshKey.privateKey;
        data.publicKey = body.sshKey.publicKey;
        data.keyFingerprint = body.sshKey.keyFingerprint;
    }

    const existingFavorites = existing.favorites ? JSON.parse(existing.favorites) : {};
    const existingFolders = existing.folders ? JSON.parse(existing.folders) : {};
    if (body.favorite !== undefined) {
        if (body.favorite) existingFavorites[userId] = true;
        else delete existingFavorites[userId];
    }
    if (body.folderId !== undefined) {
        if (body.folderId) existingFolders[userId] = body.folderId;
        else delete existingFolders[userId];
    }

    await db.update(ciphers).set({
        type: body.type ?? existing.type,
        data: JSON.stringify(data),
        favorites: JSON.stringify(existingFavorites),
        folders: JSON.stringify(existingFolders),
        reprompt: body.reprompt ?? existing.reprompt,
        key: body.key !== undefined ? body.key : existing.key,
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    // 推送通知
    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * PUT /api/ciphers/:id/archive
 * 对应 CiphersController.PutArchive（归档单个）
 */
ciphersRoute.put('/:id/archive', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

    const now = new Date().toISOString();
    await db.update(ciphers).set({ archivedDate: now, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

/**
 * PUT /api/ciphers/:id/unarchive
 * 对应 CiphersController.PutUnarchive（取消归档单个）
 */
ciphersRoute.put('/:id/unarchive', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');
    await assertCipherPersonalVaultWriteAllowed(db, userId, existing);

    const now = new Date().toISOString();
    await db.update(ciphers).set({ archivedDate: null, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncCipher(
        c.env, PushType.SyncCipherUpdate, cipherId,
        existing.organizationId ? null : userId, existing.organizationId || null,
        null, now, contextId,
    ));

    return c.json(await toCipherResponse(updated!, userId, getBaseUrl(c), c.env.JWT_SECRET));
});

export default ciphersRoute;
