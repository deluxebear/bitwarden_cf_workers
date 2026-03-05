/**
 * Bitwarden Workers - Ciphers 路由
 * 对应原始项目 Api/Vault/Controllers/CiphersController.cs
 * 处理：密码条目的 CRUD 操作
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, desc, isNull, isNotNull } from 'drizzle-orm';
import { users, ciphers, folders, collectionCiphers, events } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { logEvent } from '../services/events';
import { toEventResponse } from './events';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import type { Bindings, Variables, CipherRequest, CipherResponse, CipherType, CipherRepromptType } from '../types';

const ciphersRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有端点都需要认证
ciphersRoute.use('/*', authMiddleware);

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
 * objectType: "cipher" 用于单个 CRUD 端点, "cipherDetails" 用于列表/sync
 */
function toCipherResponse(cipher: any, userId: string, baseUrl: string, objectType: 'cipher' | 'cipherDetails' = 'cipher'): CipherResponse {
    const data = JSON.parse(cipher.data || '{}');
    const favorites = cipher.favorites ? JSON.parse(cipher.favorites) : {};
    const folders = cipher.folders ? JSON.parse(cipher.folders) : {};
    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    const attachments = Object.keys(attachmentsMap).map(id => {
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
            url: `${baseUrl}/attachments/${cipher.id}/${id}`
        };
    });

    return {
        id: cipher.id,
        organizationId: cipher.organizationId,
        folderId: folders[userId] || null,
        type: cipher.type as CipherType,
        data: data, // 原始加密 JSON - 官方 CipherMiniResponseModel 必返回
        name: data.name || '',
        notes: data.notes || null,
        favorite: !!favorites[userId],
        reprompt: (cipher.reprompt ?? 0) as CipherRepromptType,
        login: cipher.type === 1 ? data.login : undefined,
        card: cipher.type === 3 ? data.card : undefined,
        identity: cipher.type === 4 ? data.identity : undefined,
        secureNote: cipher.type === 2 ? data.secureNote : undefined,
        sshKey: cipher.type === 5 ? data.sshKey : undefined,
        fields: data.fields || null,
        passwordHistory: data.passwordHistory || null,
        attachments: attachments.length > 0 ? attachments : null,
        organizationUseTotp: false,
        revisionDate: cipher.revisionDate,
        creationDate: cipher.creationDate,
        deletedDate: cipher.deletedDate,
        archivedDate: null, // 归档日期 - CipherResponseModel
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
    const data = results.map((cipher) => toCipherResponse(cipher, userId, baseUrl, 'cipherDetails'));

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/ciphers/:id
 * 对应 CiphersController.Get
 */
ciphersRoute.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();

    if (!cipher) {
        throw new NotFoundError('Cipher not found.');
    }

    return c.json(toCipherResponse(cipher, userId, getBaseUrl(c)));
});

/**
 * GET /api/ciphers/:id/events
 * 对应 CiphersController.GetEvents
 */
ciphersRoute.get('/:id/events', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

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

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

    const { file, formData } = await extractFileFromRequest(c);

    const attachmentId = generateUuid();
    // 存储在 R2 的 key = {cipherId}/{attachmentId}
    const r2Key = `${cipherId}/${attachmentId}`;

    await c.env.ATTACHMENTS.put(r2Key, file.stream(), {
        httpMetadata: { contentType: file.type }
    });

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    attachmentsMap[attachmentId] = {
        fileName: formData.filename || file.name || 'file',
        key: formData.key || '',
        size: file.size.toString()
    };

    const now = new Date().toISOString();
    await db.update(ciphers).set({
        attachments: JSON.stringify(attachmentsMap),
        revisionDate: now
    }).where(eq(ciphers.id, cipherId));

    await logEvent(c.env.DB, 1103, { userId, cipherId });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(toCipherResponse(updated!, userId, getBaseUrl(c)));
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

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

    const body = await c.req.json<{
        key?: string;
        fileName?: string;
        fileSize?: number;
        adminRequest?: boolean;
    }>();

    const attachmentId = generateUuid();

    // 预创建附件元数据（validated=false，等待实际文件上传）
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

    return c.json({
        attachmentId,
        url: `${cipherId}/attachment/${attachmentId}`,
        fileUploadType: 0, // Direct
        cipherResponse: toCipherResponse(updated!, userId, getBaseUrl(c), 'cipherDetails'),
        cipherMiniResponse: null,
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

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }

    const { file } = await extractFileFromRequest(c);

    // 上传到 R2
    const r2Key = `${cipherId}/${attachmentId}`;
    await c.env.ATTACHMENTS.put(r2Key, file.stream(), {
        httpMetadata: { contentType: file.type }
    });

    // 更新元数据：标记已验证，更新实际文件大小
    attachmentsMap[attachmentId].size = file.size.toString();
    attachmentsMap[attachmentId].validated = true;

    const now = new Date().toISOString();
    await db.update(ciphers).set({
        attachments: JSON.stringify(attachmentsMap),
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

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

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    const meta = attachmentsMap[attachmentId];
    if (!meta) {
        throw new NotFoundError('Attachment metadata not found.');
    }

    // 使用 getBaseUrl 构建绝对下载 URL（已处理反向代理协议）
    const downloadUrl = `${getBaseUrl(c)}/attachments/${cipherId}/${attachmentId}`;

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

    const cipher = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    if (!cipher) throw new NotFoundError('Cipher not found');
    if (cipher.userId !== userId && !cipher.organizationId) {
        throw new NotFoundError('Cipher not found');
    }

    const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    if (!attachmentsMap[attachmentId]) {
        throw new NotFoundError('Attachment not found.');
    }

    const r2Key = `${cipherId}/${attachmentId}`;
    await c.env.ATTACHMENTS.delete(r2Key);

    delete attachmentsMap[attachmentId];

    const now = new Date().toISOString();
    const updatedAttachments = Object.keys(attachmentsMap).length > 0 ? JSON.stringify(attachmentsMap) : null;
    await db.update(ciphers).set({
        attachments: updatedAttachments,
        revisionDate: now
    }).where(eq(ciphers.id, cipherId));

    await logEvent(c.env.DB, 1104, { userId, cipherId });

    // 官方返回 DeleteAttachmentResponseModel，包含更新后的 cipher
    const updatedCipher = { ...cipher, attachments: updatedAttachments, revisionDate: now };
    const baseUrl = getBaseUrl(c);
    return c.json({
        cipher: toCipherResponse(updatedCipher, userId, baseUrl, 'cipher'),
        object: 'deleteAttachment',
    }, 200);
};

ciphersRoute.delete('/:id/attachment/:attachmentId', deleteAttachmentHandler);
ciphersRoute.delete('/:id/attachment/:attachmentId/admin', deleteAttachmentHandler);

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
    if (body.type === 5) data.sshKey = body.sshKey;

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

    return c.json(toCipherResponse(created!, userId, getBaseUrl(c)));
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
    if (cipherBody.type === 5) data.sshKey = cipherBody.sshKey;

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
    return c.json(toCipherResponse(created!, userId, getBaseUrl(c)));
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

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();

    if (!existing) {
        throw new NotFoundError('Cipher not found.');
    }

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
    if (body.type === 5) data.sshKey = body.sshKey;

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
    return c.json(toCipherResponse(updated!, userId, getBaseUrl(c)));
});

/**
 * POST /api/ciphers/:id (alias for PUT, Bitwarden 客户端兼容)
 */
ciphersRoute.post('/:id', async (c) => {
    const id = c.req.param('id');
    // 跳过特殊路由
    if (['create', 'delete', 'restore', 'move', 'share', 'purge'].includes(id)) {
        return;
    }
    // 复用 PUT 逻辑
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<CipherRequest>();

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, id), eq(ciphers.userId, userId))).get();
    if (!existing) throw new NotFoundError('Cipher not found.');

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
    if (body.type === 5) data.sshKey = body.sshKey;

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
    return c.json(toCipherResponse(updated!, userId, getBaseUrl(c)));
});

/**
 * DELETE /api/ciphers/:id
 * 对应 CiphersController.Delete（软删除）
 */
ciphersRoute.delete('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const cipherId = c.req.param('id');

    const existing = await db.select().from(ciphers)
        .where(and(eq(ciphers.id, cipherId), eq(ciphers.userId, userId))).get();

    if (!existing) {
        throw new NotFoundError('Cipher not found.');
    }

    const now = new Date().toISOString();

    // 软删除（移到回收站）
    await db.update(ciphers).set({
        deletedDate: now,
        revisionDate: now,
    }).where(eq(ciphers.id, cipherId));

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    await logEvent(c.env.DB, 1115, { userId, cipherId });

    return c.body(null, 204);
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

    const now = new Date().toISOString();
    await db.update(ciphers).set({ deletedDate: null, revisionDate: now }).where(eq(ciphers.id, cipherId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    await logEvent(c.env.DB, 1116, { userId, cipherId });

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(toCipherResponse(updated!, userId, getBaseUrl(c)));
});

/**
 * POST /api/ciphers/delete
 * 对应 CiphersController.DeleteMany（批量软删除）
 */
ciphersRoute.post('/delete', async (c) => {
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
    return c.json(null, 200);
});

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
            const folders = cipher.folders ? JSON.parse(cipher.folders) : {};
            if (body.folderId) folders[userId] = body.folderId;
            else delete folders[userId];
            await db.update(ciphers).set({ folders: JSON.stringify(folders), revisionDate: now })
                .where(eq(ciphers.id, id));
        }
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
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

    // 永久删除所有已软删除（在回收站）的 ciphers
    const softDeleted = await db.select({ id: ciphers.id }).from(ciphers)
        .where(and(eq(ciphers.userId, userId), isNotNull(ciphers.deletedDate))).all();

    for (const cipher of softDeleted) {
        await db.delete(ciphers).where(eq(ciphers.id, cipher.id));
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    return c.body(null, 204);
});

export default ciphersRoute;
