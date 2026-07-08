/**
 * Bitwarden Workers - Sends 路由
 * 对应原始项目 Api/Tools/Controllers/SendsController.cs
 * 处理：Send（安全分享）的 CRUD 及匿名访问
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and } from 'drizzle-orm';
import { sends, users } from '../db/schema';
import { authMiddleware, verifyJwt } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid, hashSendPassword, verifySendPassword } from '../services/crypto';
import type { Bindings, Variables, SendRequest, SendResponse, SendAccessResponse, SendType } from '../types';
import { pushSyncSend } from '../services/push-notification';
import { PushType } from '../types/push-notification';
import { validateSendCanSave } from '../services/policy-requirements';

const sendsRoute = new Hono<{ Bindings: Bindings; Variables: Variables }>();
const MAX_SEND_FILE_SIZE = 501 * 1024 * 1024;
const SEND_FILE_DOWNLOAD_TOKEN_LIFETIME_SECONDS = 5 * 60;

type SendRow = typeof sends.$inferSelect;

type SendFileData = {
    id?: string | null;
    name?: string | null;
    notes?: string | null;
    file?: {
        id?: string | null;
        fileName?: string | null;
        size?: string | number | null;
        sizeName?: string | null;
        validated?: boolean;
    } | null;
};

type SendAccessRequestBody = {
    password?: string | null;
};

type SendAccessJwtPayload = {
    sub?: string;
    send_id?: string;
    type?: string;
    scope?: string[] | string;
};

function parseSendData(send: Pick<SendRow, 'data'>): any {
    return send.data ? JSON.parse(send.data) : null;
}

function getSendFileId(data: any): string | null {
    return data?.file?.id ?? data?.id ?? null;
}

function getSendFileMetadata(data: any) {
    const id = getSendFileId(data);
    const file = data?.file ?? {};
    const size = file.size ?? data?.size ?? null;
    return {
        id,
        fileName: file.fileName ?? data?.fileName ?? '',
        size: size == null ? null : String(size),
        sizeName: file.sizeName ?? (size == null ? null : formatSizeName(Number(size))),
    };
}

function formatSizeName(size: number): string {
    if (!Number.isFinite(size) || size < 0) return '0 Bytes';
    if (size >= 1073741824) return `${(size / 1073741824).toFixed(2)} GB`;
    if (size >= 1048576) return `${(size / 1048576).toFixed(2)} MB`;
    if (size >= 1024) return `${(size / 1024).toFixed(2)} KB`;
    return `${size} Bytes`;
}

function getBaseUrl(c: any): string {
    const url = new URL(c.req.url);
    const proto = c.req.header('x-forwarded-proto') || url.protocol.replace(':', '');
    return `${proto}://${url.host}`;
}

function encodeBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeBase64Url(value: string): Uint8Array {
    let base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    if (pad) base64 += '='.repeat(4 - pad);
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function uuidFromAccessId(accessId: string): string {
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(accessId)) {
        return accessId.toLowerCase();
    }

    let bytes: Uint8Array;
    try {
        bytes = decodeBase64Url(accessId);
    } catch {
        throw new BadRequestError('Invalid Send id.');
    }
    if (bytes.length !== 16) {
        throw new BadRequestError('Invalid Send id.');
    }
    // .NET Guid.ToByteArray uses little-endian order for the first three fields.
    const guidBytes = [
        bytes[3], bytes[2], bytes[1], bytes[0],
        bytes[5], bytes[4],
        bytes[7], bytes[6],
        ...bytes.slice(8),
    ];
    const hex = guidBytes.map((b) => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function accessIdFromUuid(uuid: string): string {
    const hex = uuid.replace(/-/g, '');
    const bytes = new Uint8Array([
        parseInt(hex.slice(6, 8), 16), parseInt(hex.slice(4, 6), 16),
        parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(0, 2), 16),
        parseInt(hex.slice(10, 12), 16), parseInt(hex.slice(8, 10), 16),
        parseInt(hex.slice(14, 16), 16), parseInt(hex.slice(12, 14), 16),
        ...Array.from({ length: 8 }, (_, i) => parseInt(hex.slice(16 + i * 2, 18 + i * 2), 16)),
    ]);
    return encodeBase64Url(bytes);
}

async function signDownloadToken(sendId: string, fileId: string, secret: string): Promise<string> {
    const payload = {
        s: sendId,
        f: fileId,
        exp: Math.floor(Date.now() / 1000) + SEND_FILE_DOWNLOAD_TOKEN_LIFETIME_SECONDS,
    };
    const payloadB64 = encodeBase64Url(new TextEncoder().encode(JSON.stringify(payload)));
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign'],
    );
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
    return `${payloadB64}.${encodeBase64Url(new Uint8Array(sig))}`;
}

async function verifyDownloadToken(token: string, sendId: string, fileId: string, secret: string): Promise<boolean> {
    const dot = token.indexOf('.');
    if (dot <= 0) return false;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify'],
    );
    const verified = await crypto.subtle.verify(
        'HMAC',
        key,
        decodeBase64Url(sigB64),
        new TextEncoder().encode(payloadB64),
    );
    if (!verified) return false;

    try {
        const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(payloadB64))) as {
            s?: string;
            f?: string;
            exp?: number;
        };
        return payload.s === sendId &&
            payload.f === fileId &&
            typeof payload.exp === 'number' &&
            payload.exp >= Math.floor(Date.now() / 1000);
    } catch {
        return false;
    }
}

async function extractFileFromRequest(c: any): Promise<File> {
    const formData = await c.req.parseBody({ all: true });
    for (const key of ['data', 'file']) {
        const value = formData[key];
        if (value instanceof File) return value;
        if (Array.isArray(value)) {
            const file = value.find((item) => item instanceof File);
            if (file instanceof File) return file;
        }
    }
    for (const value of Object.values(formData)) {
        if (value instanceof File) return value;
        if (Array.isArray(value)) {
            const file = value.find((item) => item instanceof File);
            if (file instanceof File) return file;
        }
    }
    throw new BadRequestError('File data is required.');
}

async function ensureSendAccess(c: any, send: SendRow, password?: string | null): Promise<Response | null> {
    const now = new Date().toISOString();
    if (send.disabled) throw new NotFoundError('Send not found.');
    if (send.deletionDate <= now) throw new NotFoundError('Send not found.');
    if (send.expirationDate && send.expirationDate <= now) throw new NotFoundError('Send not found.');
    if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
        throw new NotFoundError('Send not found.');
    }

    if ((send as any).emails) throw new NotFoundError('Send not found.');
    if (!send.password) return null;
    if (!password) {
        return c.json({ error: 'password_required', error_description: 'A password is required.', object: 'error' }, 401);
    }

    let ok = false;
    try {
        ok = await verifySendPassword(password, send.password);
    } catch {
        // PBKDF2 computation error — treat as invalid password.
    }
    if (!ok) {
        throw new BadRequestError('Invalid password.');
    }
    return null;
}

function ensureSendCanBeAccessed(send: SendRow): void {
    const now = new Date().toISOString();
    if (send.disabled) throw new NotFoundError('Send not found.');
    if (send.deletionDate <= now) throw new NotFoundError('Send not found.');
    if (send.expirationDate && send.expirationDate <= now) throw new NotFoundError('Send not found.');
    if (send.maxAccessCount !== null && send.accessCount >= send.maxAccessCount) {
        throw new NotFoundError('Send not found.');
    }
}

async function getSendIdFromAccessToken(c: any): Promise<string> {
    const authHeader = c.req.header('Authorization');
    if (!authHeader?.startsWith('Bearer ')) {
        throw new NotFoundError('Send not found.');
    }

    const payload = await verifyJwt(authHeader.slice(7), c.env.JWT_SECRET) as SendAccessJwtPayload | null;
    const scopes = Array.isArray(payload?.scope)
        ? payload.scope
        : typeof payload?.scope === 'string'
            ? payload.scope.split(/\s+/).filter(Boolean)
            : [];

    if (
        !payload?.send_id ||
        payload.type !== 'Send' ||
        !scopes.includes('api.send.access')
    ) {
        throw new NotFoundError('Send not found.');
    }

    return payload.send_id;
}

async function getSendForAccessToken(c: any): Promise<SendRow> {
    const db = drizzle(c.env.DB);
    const sendId = await getSendIdFromAccessToken(c);
    const send = await db.select().from(sends).where(eq(sends.id, sendId)).get();
    if (!send) throw new NotFoundError('Send not found.');
    ensureSendCanBeAccessed(send);
    return send;
}

function toSendAccessResponse(send: SendRow): SendAccessResponse {
    const data = parseSendData(send);
    const response: SendAccessResponse & { authType: number } = {
        id: accessIdFromUuid(send.id),
        type: send.type as SendType,
        authType: (send as any).emails ? 0 : send.password ? 1 : 2,
        name: data?.name || '',
        key: send.key || '',
        expirationDate: send.expirationDate,
        object: 'send-access',
    };

    if (send.type === 0) {
        const textObj = typeof data?.text === 'object' ? data.text : undefined;
        response.text = {
            text: textObj?.text ?? data?.text ?? '',
            hidden: textObj?.hidden ?? data?.hidden ?? false,
        };
    } else if (send.type === 1) {
        response.file = getSendFileMetadata(data);
    }

    return response;
}

function toSendResponse(send: any): SendResponse {
    const data = parseSendData(send);

    // AuthType 推断逻辑 (参照 Bitwarden Core)
    // 0: Email, 1: Password, 2: None
    let authType = 2;
    if ((send as any).emails) authType = 0;
    if (send.password) authType = 1;

    const baseResponse: any = {
        id: send.id,
        accessId: accessIdFromUuid(send.id),
        userId: send.userId,
        type: send.type as SendType,
        authType,
        name: data?.name || '',
        notes: data?.notes || null,
        key: send.key || '',
        maxAccessCount: send.maxAccessCount,
        accessCount: send.accessCount,
        revisionDate: send.revisionDate,
        expirationDate: send.expirationDate,
        deletionDate: send.deletionDate,
        password: send.password ? 'set' : null,
        emails: (send as any).emails ?? null,
        disabled: send.disabled,
        hideEmail: send.hideEmail,
        object: 'send',
    };

    if (send.type === 0) { // Text
        const textObj = typeof data?.text === 'object' ? data.text : undefined;
        baseResponse.text = {
            text: textObj?.text ?? data?.text ?? '',
            hidden: textObj?.hidden ?? data?.hidden ?? false
        };
    } else if (send.type === 1) { // File
        baseResponse.file = getSendFileMetadata(data);
    }

    return baseResponse;
}

// ==================== 公开端点（匿名访问，必须先于认证路由注册）====================

/**
 * POST /api/sends/access/:id
 * 对应 SendsController.Access - 匿名访问 Send
 */
sendsRoute.post('/access/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const sendId = uuidFromAccessId(c.req.param('id'));
    const body = await c.req.json<SendAccessRequestBody>().catch(() => ({ password: undefined }));

    const send = await db.select().from(sends).where(eq(sends.id, sendId)).get();
    if (!send) throw new NotFoundError('Send not found.');

    const authResponse = await ensureSendAccess(c, send, body.password);
    if (authResponse) return authResponse;

    if (send.type === 0) {
        await db.update(sends).set({ accessCount: send.accessCount + 1 }).where(eq(sends.id, sendId));
    }

    return c.json(toSendAccessResponse(send));
});

/**
 * POST /api/sends/:encodedSendId/access/file/:fileId
 * 匿名获取文件 Send 的短期下载 URL。文件 Send 的 accessCount 在这里递增。
 */
sendsRoute.post('/:encodedSendId/access/file/:fileId', async (c) => {
    const db = drizzle(c.env.DB);
    const sendId = uuidFromAccessId(c.req.param('encodedSendId'));
    const fileId = c.req.param('fileId');
    const body = await c.req.json<SendAccessRequestBody>().catch(() => ({ password: undefined }));

    const send = await db.select().from(sends).where(eq(sends.id, sendId)).get();
    if (!send || send.type !== 1) throw new NotFoundError('Send not found.');

    const data = parseSendData(send);
    if (getSendFileId(data) !== fileId) {
        throw new NotFoundError('Send file not found.');
    }
    const authResponse = await ensureSendAccess(c, send, body.password);
    if (authResponse) return authResponse;

    await db.update(sends).set({ accessCount: send.accessCount + 1 }).where(eq(sends.id, sendId));

    const token = await signDownloadToken(sendId, fileId, c.env.JWT_SECRET);
    return c.json({
        id: fileId,
        url: `${getBaseUrl(c)}/api/sends/${sendId}/file/${fileId}/download?token=${encodeURIComponent(token)}`,
        object: 'send-fileDownload',
    });
});

/**
 * GET /api/sends/:id/file/:fileId/download
 * 签名 URL 的实际下载端点。Workers/R2 没有 Azure SAS，这里用短期 HMAC token
 * 约束 sendId/fileId/过期时间，再通过 R2 binding 流式返回对象。
 */
sendsRoute.get('/:id/file/:fileId/download', async (c) => {
    const sendId = uuidFromAccessId(c.req.param('id'));
    const fileId = c.req.param('fileId');
    const token = c.req.query('token');
    if (!token || !await verifyDownloadToken(token, sendId, fileId, c.env.JWT_SECRET)) {
        throw new NotFoundError('Send file not found.');
    }

    const db = drizzle(c.env.DB);
    const send = await db.select().from(sends).where(eq(sends.id, sendId)).get();
    if (!send || send.type !== 1) throw new NotFoundError('Send not found.');
    const data = parseSendData(send);
    if (getSendFileId(data) !== fileId) throw new NotFoundError('Send file not found.');

    const object = await c.env.ATTACHMENTS.get(`sends/${sendId}/${fileId}`);
    if (!object) throw new NotFoundError('Send file not found.');

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Length', object.size.toString());
    headers.set('Cache-Control', 'private, max-age=0, no-store');
    return new Response(object.body, { headers });
});

/**
 * POST /api/sends/access
 * 新版官方客户端在取得 Send access token 后调用。
 * 对应上游 SendsController.AccessUsingAuth，不再重复校验密码。
 */
sendsRoute.post('/access', async (c) => {
    const db = drizzle(c.env.DB);
    const send = await getSendForAccessToken(c);

    if (send.type === 0) {
        const now = new Date().toISOString();
        await db.update(sends).set({
            accessCount: send.accessCount + 1,
            revisionDate: now,
        }).where(eq(sends.id, send.id));
        if (send.userId) {
            const contextId = c.get('jwtPayload')?.device || null;
            c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendUpdate, send.id, send.userId, now, contextId));
        }
    }

    return c.json(toSendAccessResponse(send));
});

/**
 * POST /api/sends/access/file/:fileId
 * 新版 token 下载路径。文件 Send 的 accessCount 在签发下载 URL 时递增。
 */
sendsRoute.post('/access/file/:fileId', async (c) => {
    const db = drizzle(c.env.DB);
    const send = await getSendForAccessToken(c);
    const fileId = c.req.param('fileId');
    if (send.type !== 1) throw new NotFoundError('Send not found.');

    const data = parseSendData(send);
    if (getSendFileId(data) !== fileId) {
        throw new NotFoundError('Send file not found.');
    }

    const now = new Date().toISOString();
    await db.update(sends).set({
        accessCount: send.accessCount + 1,
        revisionDate: now,
    }).where(eq(sends.id, send.id));
    if (send.userId) {
        const contextId = c.get('jwtPayload')?.device || null;
        c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendUpdate, send.id, send.userId, now, contextId));
    }

    const token = await signDownloadToken(send.id, fileId, c.env.JWT_SECRET);
    return c.json({
        id: fileId,
        url: `${getBaseUrl(c)}/api/sends/${send.id}/file/${fileId}/download?token=${encodeURIComponent(token)}`,
        object: 'send-fileDownload',
    });
});

/**
 * POST /api/sends/file/validate/azure
 * R2 直传不使用 Azure EventGrid；返回最小成功响应，避免自托管客户端重试。
 */
sendsRoute.post('/file/validate/azure', (c) => c.json({ object: 'eventGridValidation' }));

// ==================== 认证端点 ====================

const authed = new Hono<{ Bindings: Bindings; Variables: Variables }>();
authed.use('/*', authMiddleware);

/**
 * GET /api/sends - 获取所有 Send
 */
authed.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const results = await db.select().from(sends).where(eq(sends.userId, userId)).all();
    const now = new Date().toISOString();
    const active = results.filter(s => s.deletionDate > now);
    return c.json({ data: active.map(toSendResponse), object: 'list', continuationToken: null });
});

/**
 * POST /api/sends/file/v2 - 创建文件 Send 元数据，返回直传信息
 */
authed.post('/file/v2', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<SendRequest & { fileLength?: number | null }>();

    if (body.type !== 1) {
        throw new BadRequestError('Invalid content.');
    }
    if (!body.deletionDate || !body.file?.fileName || !body.fileLength) {
        throw new BadRequestError('Invalid content. File metadata and file size hint are required.');
    }
    if (body.fileLength > MAX_SEND_FILE_SIZE) {
        throw new BadRequestError('Max file size is 501 MB.');
    }
    await validateSendCanSave(db, userId, {
        type: body.type,
        password: body.password ?? null,
        hideEmail: body.hideEmail ?? false,
        emails: body.emails ?? null,
    });

    const now = new Date().toISOString();
    const sendId = generateUuid();
    const fileId = generateUuid();
    const fileData: SendFileData = {
        id: fileId,
        name: body.name || null,
        notes: body.notes || null,
        file: {
            id: fileId,
            fileName: body.file.fileName,
            size: String(body.fileLength),
            sizeName: formatSizeName(body.fileLength),
            validated: false,
        },
    };

    let hashedPassword: string | null = null;
    if (body.password) hashedPassword = await hashSendPassword(body.password);

    await db.insert(sends).values({
        id: sendId,
        userId,
        type: body.type,
        data: JSON.stringify(fileData),
        key: body.key,
        password: hashedPassword,
        emails: body.emails ?? null,
        maxAccessCount: body.maxAccessCount ?? null,
        accessCount: 0,
        expirationDate: body.expirationDate ?? null,
        deletionDate: body.deletionDate,
        disabled: body.disabled ?? false,
        hideEmail: body.hideEmail ?? false,
        creationDate: now,
        revisionDate: now,
    });

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const created = await db.select().from(sends).where(eq(sends.id, sendId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendCreate, sendId, userId, now, contextId));

    return c.json({
        url: `${sendId}/file/${fileId}`,
        fileUploadType: 0,
        sendResponse: toSendResponse(created!),
        object: 'send-fileUpload',
    });
});

/**
 * GET /api/sends/:id/file/:fileId - 续期文件上传 URL
 */
authed.get('/:id/file/:fileId', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');
    const fileId = c.req.param('fileId');

    const send = await db.select().from(sends)
        .where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!send || send.type !== 1) throw new NotFoundError('Send not found.');

    const data = parseSendData(send);
    if (getSendFileId(data) !== fileId || data?.file?.validated) {
        throw new NotFoundError('Send file not found.');
    }

    return c.json({
        url: `${sendId}/file/${fileId}`,
        fileUploadType: 0,
        sendResponse: toSendResponse(send),
        object: 'send-fileUpload',
    });
});

/**
 * GET /api/sends/:id - 获取单个 Send
 */
authed.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');
    const send = await db.select().from(sends).where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!send) throw new NotFoundError('Send not found.');
    return c.json(toSendResponse(send));
});

/**
 * POST /api/sends - 创建 Send
 */
authed.post('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<SendRequest>();

    if (body.type === undefined || !body.deletionDate) {
        throw new BadRequestError('Type and deletion date are required.');
    }
    await validateSendCanSave(db, userId, {
        type: body.type,
        password: body.password ?? null,
        hideEmail: body.hideEmail ?? false,
        emails: body.emails ?? null,
    });

    const now = new Date().toISOString();
    const sendId = generateUuid();

    const data: any = { name: body.name || null, notes: body.notes || null };
    if (body.type === 0) data.text = body.text;
    if (body.type === 1) data.file = body.file;

    let hashedPassword: string | null = null;
    if (body.password) hashedPassword = await hashSendPassword(body.password);

    await db.insert(sends).values({
        id: sendId, userId, type: body.type,
        data: JSON.stringify(data), key: body.key,
        password: hashedPassword,
        emails: body.emails ?? null,
        maxAccessCount: body.maxAccessCount ?? null, accessCount: 0,
        expirationDate: body.expirationDate ?? null,
        deletionDate: body.deletionDate,
        disabled: body.disabled ?? false,
        hideEmail: body.hideEmail ?? false,
        creationDate: now, revisionDate: now,
    });

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const created = await db.select().from(sends).where(eq(sends.id, sendId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendCreate, sendId, userId, now, contextId));

    return c.json(toSendResponse(created!));
});

/**
 * POST /api/sends/:id/file/:fileId - 直传文件内容到 R2
 */
authed.post('/:id/file/:fileId', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');
    const fileId = c.req.param('fileId');

    const send = await db.select().from(sends)
        .where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!send || send.type !== 1) throw new NotFoundError('Send not found.');

    const data = parseSendData(send) as SendFileData | null;
    if (!data || getSendFileId(data) !== fileId) {
        throw new NotFoundError('Send file not found.');
    }
    if (data.file?.validated) {
        throw new BadRequestError('File has already been uploaded.');
    }

    const file = await extractFileFromRequest(c);
    const expectedSize = Number(data.file?.size ?? 0);
    if (expectedSize > 0 && file.size !== expectedSize) {
        await db.delete(sends).where(eq(sends.id, sendId));
        throw new BadRequestError('File received does not match expected file length.');
    }

    await c.env.ATTACHMENTS.put(`sends/${sendId}/${fileId}`, file.stream(), {
        httpMetadata: { contentType: file.type || 'application/octet-stream' },
    });

    const now = new Date().toISOString();
    data.id = fileId;
    data.file = {
        ...data.file,
        id: fileId,
        size: String(file.size),
        sizeName: formatSizeName(file.size),
        validated: true,
    };
    await db.update(sends).set({
        data: JSON.stringify(data),
        revisionDate: now,
    }).where(eq(sends.id, sendId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendUpdate, sendId, userId, now, contextId));

    return c.body(null, 200);
});

/**
 * PUT /api/sends/:id - 更新 Send
 */
authed.put('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');
    const body = await c.req.json<SendRequest>();

    const existing = await db.select().from(sends)
        .where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!existing) throw new NotFoundError('Send not found.');

    const now = new Date().toISOString();
    const existingData = parseSendData(existing);
    const data: any = { name: body.name || null, notes: body.notes || null };
    if (body.type === 0) data.text = body.text;
    if (body.type === 1) {
        const existingFileId = getSendFileId(existingData);
        data.id = existingFileId;
        data.file = {
            ...existingData?.file,
            ...body.file,
            id: body.file?.id ?? existingFileId,
        };
    }

    let hashedPassword = existing.password;
    if (body.password !== undefined) {
        hashedPassword = body.password ? await hashSendPassword(body.password) : null;
    }
    const nextEmails = body.emails !== undefined ? body.emails : (existing as any).emails ?? null;

    await validateSendCanSave(db, userId, {
        type: body.type ?? existing.type,
        password: body.password ?? null,
        hasPassword: !!hashedPassword,
        hideEmail: body.hideEmail !== undefined ? body.hideEmail : existing.hideEmail,
        emails: nextEmails,
    });

    await db.update(sends).set({
        data: JSON.stringify(data),
        key: body.key !== undefined ? body.key : existing.key,
        password: hashedPassword,
        emails: nextEmails,
        maxAccessCount: body.maxAccessCount !== undefined ? body.maxAccessCount : existing.maxAccessCount,
        expirationDate: body.expirationDate !== undefined ? body.expirationDate : existing.expirationDate,
        deletionDate: body.deletionDate || existing.deletionDate,
        disabled: body.disabled !== undefined ? body.disabled : existing.disabled,
        hideEmail: body.hideEmail !== undefined ? body.hideEmail : existing.hideEmail,
        revisionDate: now,
    }).where(eq(sends.id, sendId));

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    const updated = await db.select().from(sends).where(eq(sends.id, sendId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendUpdate, sendId, userId, now, contextId));

    return c.json(toSendResponse(updated!));
});

const removeSendAuthHandler = async (c: any) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');

    const existing = await db.select().from(sends)
        .where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!existing) throw new NotFoundError('Send not found.');

    await validateSendCanSave(db, userId, {
        type: existing.type,
        password: null,
        hasPassword: false,
        hideEmail: existing.hideEmail,
        emails: null,
    });

    const now = new Date().toISOString();
    await db.update(sends).set({ password: null, emails: null, revisionDate: now }).where(eq(sends.id, sendId));
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const updated = await db.select().from(sends).where(eq(sends.id, sendId)).get();

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendUpdate, sendId, userId, now, contextId));

    return c.json(toSendResponse(updated!));
};

/**
 * PUT /api/sends/:id/remove-password - 移除密码
 */
authed.put('/:id/remove-password', removeSendAuthHandler);

/**
 * PUT /api/sends/:id/remove-auth - 移除所有 Send 访问认证
 */
authed.put('/:id/remove-auth', removeSendAuthHandler);

/**
 * DELETE /api/sends/:id - 删除 Send
 */
authed.delete('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const sendId = c.req.param('id');

    const existing = await db.select().from(sends)
        .where(and(eq(sends.id, sendId), eq(sends.userId, userId))).get();
    if (!existing) throw new NotFoundError('Send not found.');

    if (existing.type === 1) {
        const data = parseSendData(existing);
        const fileId = getSendFileId(data);
        if (fileId) {
            await c.env.ATTACHMENTS.delete(`sends/${sendId}/${fileId}`);
        }
    }

    await db.delete(sends).where(eq(sends.id, sendId));
    const now = new Date().toISOString();
    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));

    const contextId = c.get('jwtPayload')?.device || null;
    c.executionCtx.waitUntil(pushSyncSend(c.env, PushType.SyncSendDelete, sendId, userId, now, contextId));

    return c.body(null, 204);
});

// 挂载认证路由（在公开路由之后）
sendsRoute.route('/', authed);

export default sendsRoute;
