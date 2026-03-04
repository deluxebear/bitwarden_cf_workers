/**
 * Bitwarden Workers - Ciphers 路由
 * 对应原始项目 Api/Vault/Controllers/CiphersController.cs
 * 处理：密码条目的 CRUD 操作
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, isNull } from 'drizzle-orm';
import { ciphers, users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import type { Bindings, Variables, CipherRequest, CipherResponse, CipherType, CipherRepromptType } from '../types';

const ciphersRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有端点都需要认证
ciphersRoute.use('/*', authMiddleware);

/**
 * 将数据库记录转换为 Bitwarden API 响应格式
 */
function toCipherResponse(cipher: any, userId: string): CipherResponse {
    const data = JSON.parse(cipher.data || '{}');
    const favorites = cipher.favorites ? JSON.parse(cipher.favorites) : {};
    const folders = cipher.folders ? JSON.parse(cipher.folders) : {};

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
        attachments: null,
        organizationUseTotp: false,
        revisionDate: cipher.revisionDate,
        creationDate: cipher.creationDate,
        deletedDate: cipher.deletedDate,
        archivedDate: null, // 归档日期 - CipherResponseModel
        key: cipher.key,
        object: 'cipherDetails', // 官方 Sync 使用 cipherDetails
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

    const data = results.map((cipher) => toCipherResponse(cipher, userId));

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

    return c.json(toCipherResponse(cipher, userId));
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

    // 更新用户的 account revision date
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const created = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(toCipherResponse(created!, userId));
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

    const created = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(toCipherResponse(created!, userId));
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
    return c.json(toCipherResponse(updated!, userId));
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
    const updated = await db.select().from(ciphers).where(eq(ciphers.id, id)).get();
    return c.json(toCipherResponse(updated!, userId));
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

    return c.json(null, 200);
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

    return c.json(null, 200);
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

    const updated = await db.select().from(ciphers).where(eq(ciphers.id, cipherId)).get();
    return c.json(toCipherResponse(updated!, userId));
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

    // 永久删除所有已软删除的 ciphers
    const softDeleted = await db.select({ id: ciphers.id }).from(ciphers)
        .where(and(eq(ciphers.userId, userId))).all();

    // 简化：删除所有该用户的 ciphers
    for (const cipher of softDeleted) {
        await db.delete(ciphers).where(eq(ciphers.id, cipher.id));
    }

    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    return c.json(null, 200);
});

export default ciphersRoute;
