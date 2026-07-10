/**
 * Bitwarden Workers - Emergency Access 路由
 *
 * 状态和密钥均持久化到 D1。服务端只保存客户端加密后的 keyEncrypted，
 * 不持有、解密或重新包装任何用户密钥。
 */

import { Hono, type Context } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, isNull, sql } from 'drizzle-orm';
import { HTTPException } from 'hono/http-exception';
import { ciphers, emergencyAccess, users } from '../db/schema';
import { authMiddleware, signJwtClaims, verifyJwt } from '../middleware/auth';
import { BadRequestError, ConflictError, NotFoundError } from '../middleware/error';
import { generateSecureRandomString, generateUuid } from '../services/crypto';
import { buildAttachmentDownloadUrl } from '../services/attachment-token';
import { sendEmergencyAccessInvite } from '../services/email';
import {
    EmergencyAccessDomainError,
    EmergencyAccessStatus,
    EmergencyAccessType,
    acceptEmergencyAccess,
    approveEmergencyAccess,
    assertEmergencyAccessCanBeUsed,
    confirmEmergencyAccess,
    createEmergencyAccessInvite,
    initiateEmergencyAccess,
    rejectEmergencyAccess,
    revokeEmergencyAccess,
    type EmergencyAccessRecord,
} from '../services/emergency-access';
import { pushNotification } from '../services/push-notification';
import { PushType } from '../types/push-notification';
import type { Bindings, Variables } from '../types';
import { toCipherResponse } from './ciphers';

const emergency = new Hono<{ Bindings: Bindings; Variables: Variables }>();
emergency.use('/*', authMiddleware);

type Db = ReturnType<typeof drizzle>;
type UserRow = typeof users.$inferSelect;
type AppContext = Context<{ Bindings: Bindings; Variables: Variables }>;

function toRecord(row: typeof emergencyAccess.$inferSelect): EmergencyAccessRecord {
    return row as EmergencyAccessRecord;
}

function mapDomainError(error: unknown): never {
    if (!(error instanceof EmergencyAccessDomainError)) throw error;
    if (error.code === 'forbidden') throw new HTTPException(403, { message: error.message });
    throw new BadRequestError(error.message);
}

async function getRecord(db: Db, id: string): Promise<EmergencyAccessRecord> {
    const row = await db.select().from(emergencyAccess).where(eq(emergencyAccess.id, id)).get();
    if (!row) throw new NotFoundError('Emergency Access not found.');
    return toRecord(row);
}

export async function persistEmergencyAccessRecordCas(
    db: Db,
    original: EmergencyAccessRecord,
    updated: EmergencyAccessRecord,
): Promise<void> {
    const result = await db.update(emergencyAccess).set({
        grantorId: updated.grantorId,
        granteeId: updated.granteeId,
        email: updated.email,
        keyEncrypted: updated.keyEncrypted,
        type: updated.type,
        status: updated.status,
        waitTimeDays: updated.waitTimeDays,
        recoveryInitiatedDate: updated.recoveryInitiatedDate,
        recoveryRejectedDate: updated.recoveryRejectedDate,
        lastNotificationDate: updated.lastNotificationDate,
        revokedDate: updated.revokedDate,
        revokedByUserId: updated.revokedByUserId,
        revisionDate: updated.revisionDate,
    }).where(and(
        eq(emergencyAccess.id, original.id),
        eq(emergencyAccess.revisionDate, original.revisionDate),
        isNull(emergencyAccess.revokedDate),
    )).run();
    if (result.meta.changes !== 1) {
        throw new ConflictError('Emergency Access was changed by another request.');
    }
}

function granteeResponse(record: EmergencyAccessRecord, grantee?: UserRow | null) {
    return {
        id: record.id,
        granteeId: record.granteeId,
        name: grantee?.name ?? null,
        email: record.email ?? grantee?.email ?? null,
        avatarColor: grantee?.avatarColor ?? null,
        type: record.type,
        status: record.status,
        waitTimeDays: record.waitTimeDays,
        creationDate: record.creationDate,
        object: 'emergencyAccessGranteeDetails',
    };
}

function grantorResponse(record: EmergencyAccessRecord, grantor: UserRow) {
    return {
        id: record.id,
        grantorId: record.grantorId,
        name: grantor.name,
        email: grantor.email,
        avatarColor: grantor.avatarColor,
        type: record.type,
        status: record.status,
        waitTimeDays: record.waitTimeDays,
        creationDate: record.creationDate,
        object: 'emergencyAccessGrantorDetails',
    };
}

function listResponse(data: unknown[]) {
    return { data, object: 'list', continuationToken: null };
}

function nextRevision(record: EmergencyAccessRecord): string {
    const now = Date.now();
    const previous = Date.parse(record.revisionDate);
    return new Date(Number.isFinite(previous) && now <= previous ? previous + 1 : now).toISOString();
}

function getBaseUrl(c: AppContext): string {
    const url = new URL(c.req.url);
    const protocol = c.req.header('x-forwarded-proto') || url.protocol.replace(':', '');
    return `${protocol}://${url.host}`;
}

function readableSize(value: unknown): { size: string; sizeName: string } {
    const size = typeof value === 'string' ? value : String(value ?? '0');
    const bytes = Number.parseInt(size, 10);
    const safeBytes = Number.isFinite(bytes) && bytes >= 0 ? bytes : 0;
    const sizeName = safeBytes >= 1048576 ? `${(safeBytes / 1048576).toFixed(2)} MB`
        : safeBytes >= 1024 ? `${(safeBytes / 1024).toFixed(2)} KB`
            : `${safeBytes} Bytes`;
    return { size, sizeName };
}

function notifyUser(c: AppContext, userId: string | null, action: string, record: EmergencyAccessRecord): void {
    if (!userId) return;
    const notificationId = generateUuid();
    c.executionCtx.waitUntil(pushNotification(c.env, 'user', userId, PushType.Notification, {
        Id: notificationId,
        Priority: 0,
        Global: false,
        ClientType: 0,
        UserId: userId,
        OrganizationId: null,
        InstallationId: null,
        TaskId: null,
        Title: 'Emergency Access updated',
        Body: `Emergency Access ${action}.`,
        CreationDate: record.revisionDate,
        RevisionDate: record.revisionDate,
        ReadDate: null,
        DeletedDate: null,
    }, null).catch((error) => {
        console.error(JSON.stringify({
            event: 'emergency_access.notification.failed',
            action,
            emergencyAccessId: record.id,
            error: error instanceof Error ? error.message : 'unknown',
        }));
    }));
}

async function queueInviteEmail(c: AppContext, record: EmergencyAccessRecord, grantor: UserRow): Promise<void> {
    if (!record.email) return;
    const token = await signJwtClaims({
        purpose: 'emergency_access_invite',
        emergencyAccessId: record.id,
        email: record.email,
        revisionDate: record.revisionDate,
    }, c.env.JWT_SECRET, 7 * 24 * 60 * 60);
    const baseUrl = (c.env.VAULT_BASE_URL || new URL(c.req.url).origin).replace(/\/+$/, '');
    const inviteUrl = `${baseUrl}/accept-emergency?id=${encodeURIComponent(record.id)}`
        + `&name=${encodeURIComponent(grantor.name || grantor.email)}`
        + `&email=${encodeURIComponent(record.email)}&token=${encodeURIComponent(token)}`;
    c.executionCtx.waitUntil(sendEmergencyAccessInvite(
        c.env,
        record.email,
        grantor.name || grantor.email,
        inviteUrl,
    ).catch((error) => {
        console.error(JSON.stringify({
            event: 'emergency_access.invite_email.failed',
            emergencyAccessId: record.id,
            error: error instanceof Error ? error.message : 'unknown',
        }));
    }));
}

emergency.get('/trusted', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const rows = await db.select({ access: emergencyAccess, grantee: users })
        .from(emergencyAccess)
        .leftJoin(users, eq(users.id, emergencyAccess.granteeId))
        .where(and(eq(emergencyAccess.grantorId, userId), isNull(emergencyAccess.revokedDate)))
        .all();
    return c.json(listResponse(rows.map(({ access, grantee }) => granteeResponse(toRecord(access), grantee))));
});

emergency.get('/granted', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const rows = await db.select({ access: emergencyAccess, grantor: users })
        .from(emergencyAccess)
        .innerJoin(users, eq(users.id, emergencyAccess.grantorId))
        .where(and(eq(emergencyAccess.granteeId, userId), isNull(emergencyAccess.revokedDate)))
        .all();
    return c.json(listResponse(rows.map(({ access, grantor }) => grantorResponse(toRecord(access), grantor))));
});

emergency.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    if (record.grantorId !== c.get('userId') || record.revokedDate) {
        throw new HTTPException(403, { message: 'Emergency Access not valid.' });
    }
    const grantee = record.granteeId
        ? await db.select().from(users).where(eq(users.id, record.granteeId)).get()
        : null;
    return c.json(granteeResponse(record, grantee));
});

emergency.get('/:id/policies', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    try {
        assertEmergencyAccessCanBeUsed(record, c.get('userId'), EmergencyAccessType.Takeover, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    // 组织 Owner 策略聚合尚未进入 Worker Emergency Access 的账号接管流程。
    return c.json(listResponse([]));
});

async function updateAccess(c: AppContext) {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    if (record.grantorId !== c.get('userId') || record.revokedDate) {
        throw new HTTPException(403, { message: 'Emergency Access not valid.' });
    }
    const body = await c.req.json().catch(() => {
        throw new BadRequestError('Invalid JSON.');
    }) as Record<string, unknown>;
    const type = Number(body.type);
    const waitTimeDays = Number(body.waitTimeDays);
    if ((type !== EmergencyAccessType.View && type !== EmergencyAccessType.Takeover)
        || !Number.isInteger(waitTimeDays) || waitTimeDays < 0 || waitTimeDays > 365) {
        throw new BadRequestError('Emergency Access settings are not valid.');
    }
    const grantor = await db.select().from(users).where(eq(users.id, record.grantorId)).get();
    if (type === EmergencyAccessType.Takeover && grantor?.usesKeyConnector) {
        throw new BadRequestError('You cannot use Emergency Access Takeover because you are using Key Connector.');
    }
    const keyEncrypted = typeof body.keyEncrypted === 'string' && record.keyEncrypted
        ? body.keyEncrypted
        : record.keyEncrypted;
    await persistEmergencyAccessRecordCas(db, record, {
        ...record,
        type,
        waitTimeDays,
        keyEncrypted,
        revisionDate: nextRevision(record),
    });
    return c.body(null, 200);
}

emergency.put('/:id', updateAccess);

async function deleteAccess(c: AppContext) {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    let revoked: EmergencyAccessRecord;
    try {
        revoked = revokeEmergencyAccess(record, c.get('userId'), new Date());
    } catch (error) {
        mapDomainError(error);
    }
    await persistEmergencyAccessRecordCas(db, record, revoked!);
    notifyUser(c, record.grantorId === c.get('userId') ? record.granteeId : record.grantorId, 'revoked', revoked!);
    return c.body(null, 204);
}

emergency.delete('/:id', deleteAccess);
emergency.post('/:id/delete', deleteAccess);

emergency.post('/invite', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<Record<string, unknown>>().catch(() => {
        throw new BadRequestError('Invalid JSON.');
    });
    const grantor = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!grantor) throw new NotFoundError('User not found.');
    let record: EmergencyAccessRecord;
    try {
        record = createEmergencyAccessInvite({
            id: generateUuid(),
            grantorId: userId,
            grantorEmail: grantor.email,
            granteeEmail: typeof body.email === 'string' ? body.email : '',
            type: Number(body.type) as EmergencyAccessType,
            waitTimeDays: Number(body.waitTimeDays),
            now: new Date(),
        });
    } catch (error) {
        mapDomainError(error);
    }
    const duplicate = await db.select({ id: emergencyAccess.id }).from(emergencyAccess)
        .where(and(
            eq(emergencyAccess.grantorId, userId),
            eq(emergencyAccess.email, record!.email!),
            isNull(emergencyAccess.revokedDate),
        )).get();
    if (duplicate) throw new ConflictError('Emergency Access contact already exists.');
    try {
        await db.insert(emergencyAccess).values(record!);
    } catch (error) {
        const message = error instanceof Error ? error.message.toLowerCase() : '';
        if (message.includes('unique') || message.includes('constraint')) {
            throw new ConflictError('Emergency Access contact already exists.');
        }
        throw error;
    }

    const invited = await db.select({ id: users.id }).from(users).where(eq(users.email, record!.email!)).get();
    notifyUser(c, invited?.id ?? null, 'invited', record!);
    await queueInviteEmail(c, record!, grantor);
    return c.body(null, 200);
});

// deprecated：必须注册在静态 /invite 之后，避免 Hono 将 invite 当作 :id。
emergency.post('/:id', updateAccess);

emergency.post('/:id/reinvite', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    if (record.grantorId !== c.get('userId') || record.revokedDate
        || record.status !== EmergencyAccessStatus.Invited || !record.email) {
        throw new BadRequestError('Emergency Access not valid.');
    }
    const revisionDate = nextRevision(record);
    const updated = { ...record, lastNotificationDate: revisionDate, revisionDate };
    await persistEmergencyAccessRecordCas(db, record, updated);
    const invited = await db.select({ id: users.id }).from(users).where(eq(users.email, record.email)).get();
    notifyUser(c, invited?.id ?? null, 'reinvited', updated);
    const grantor = await db.select().from(users).where(eq(users.id, record.grantorId)).get();
    if (!grantor) throw new NotFoundError('Emergency Access grantor not found.');
    await queueInviteEmail(c, updated, grantor);
    return c.body(null, 200);
});

emergency.post('/:id/accept', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    const body = await c.req.json<Record<string, unknown>>().catch(() => ({} as Record<string, unknown>));
    const token = typeof body.token === 'string' ? body.token : '';
    const claims = token ? await verifyJwt(token, c.env.JWT_SECRET) : null;
    const inviteClaims = claims as unknown as Record<string, unknown> | null;
    if (!inviteClaims
        || inviteClaims.purpose !== 'emergency_access_invite'
        || inviteClaims.emergencyAccessId !== record.id
        || inviteClaims.email !== record.email
        || inviteClaims.revisionDate !== record.revisionDate) {
        throw new BadRequestError('Invalid Emergency Access invitation token.');
    }
    let updated: EmergencyAccessRecord;
    try {
        updated = acceptEmergencyAccess(record, { userId: c.get('userId'), email: c.get('email') }, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    await persistEmergencyAccessRecordCas(db, record, updated!);
    notifyUser(c, record.grantorId, 'accepted', updated!);
    return c.body(null, 200);
});

emergency.post('/:id/confirm', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<Record<string, unknown>>().catch(() => {
        throw new BadRequestError('Invalid JSON.');
    });
    const record = await getRecord(db, c.req.param('id'));
    const grantor = await db.select().from(users).where(eq(users.id, record.grantorId)).get();
    if (record.type === EmergencyAccessType.Takeover && grantor?.usesKeyConnector) {
        throw new BadRequestError('You cannot use Emergency Access Takeover because you are using Key Connector.');
    }
    let updated: EmergencyAccessRecord;
    try {
        updated = confirmEmergencyAccess(record, c.get('userId'),
            typeof body.key === 'string' ? body.key : '', new Date());
    } catch (error) {
        mapDomainError(error);
    }
    await persistEmergencyAccessRecordCas(db, record, updated!);
    notifyUser(c, updated!.granteeId, 'confirmed', updated!);
    return c.body(null, 200);
});

async function transition(c: AppContext, action: 'initiate' | 'approve' | 'reject') {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    let updated: EmergencyAccessRecord;
    try {
        if (action === 'initiate') {
            const grantor = await db.select().from(users).where(eq(users.id, record.grantorId)).get();
            if (record.type === EmergencyAccessType.Takeover && grantor?.usesKeyConnector) {
                throw new BadRequestError('You cannot takeover an account that is using Key Connector.');
            }
            updated = initiateEmergencyAccess(record, c.get('userId'), new Date());
        } else if (action === 'approve') {
            updated = approveEmergencyAccess(record, c.get('userId'), new Date());
        } else {
            updated = rejectEmergencyAccess(record, c.get('userId'), new Date());
        }
    } catch (error) {
        mapDomainError(error);
    }
    await persistEmergencyAccessRecordCas(db, record, updated!);
    notifyUser(c, action === 'initiate' ? record.grantorId : record.granteeId, action, updated!);
    return c.body(null, 200);
}

emergency.post('/:id/initiate', (c) => transition(c, 'initiate'));
emergency.post('/:id/approve', (c) => transition(c, 'approve'));
emergency.post('/:id/reject', (c) => transition(c, 'reject'));

emergency.post('/:id/takeover', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    try {
        assertEmergencyAccessCanBeUsed(record, c.get('userId'), EmergencyAccessType.Takeover, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    const grantor = await db.select().from(users).where(eq(users.id, record.grantorId)).get();
    if (!grantor) throw new NotFoundError('Emergency Access grantor not found.');
    if (grantor.usesKeyConnector) throw new BadRequestError('You cannot takeover an account that is using Key Connector.');
    return c.json({
        keyEncrypted: record.keyEncrypted,
        kdf: grantor.kdf,
        kdfIterations: grantor.kdfIterations,
        kdfMemory: grantor.kdfMemory,
        kdfParallelism: grantor.kdfParallelism,
        salt: grantor.email.trim().toLowerCase(),
        object: 'emergencyAccessTakeover',
    });
});

emergency.post('/:id/password', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    try {
        assertEmergencyAccessCanBeUsed(record, c.get('userId'), EmergencyAccessType.Takeover, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    const body = await c.req.json<Record<string, unknown>>().catch(() => {
        throw new BadRequestError('Invalid JSON.');
    });
    if (body.unlockData !== undefined || body.authenticationData !== undefined) {
        throw new BadRequestError(
            'The new Emergency Access password payload is not supported by this Workers version.',
        );
    }
    const newMasterPasswordHash = typeof body.newMasterPasswordHash === 'string'
        ? body.newMasterPasswordHash
        : '';
    const key = typeof body.key === 'string' ? body.key : '';
    if (!newMasterPasswordHash.trim() || newMasterPasswordHash.length > 300 || !key.trim()) {
        throw new BadRequestError('Emergency Access password data is not valid.');
    }
    const grantor = await db.select({
        id: users.id,
        usesKeyConnector: users.usesKeyConnector,
    }).from(users).where(eq(users.id, record.grantorId)).get();
    if (!grantor) throw new NotFoundError('Emergency Access grantor not found.');
    if (grantor.usesKeyConnector) {
        throw new BadRequestError('You cannot takeover an account that is using Key Connector.');
    }

    const now = new Date().toISOString();
    const updateUser = c.env.DB.prepare(`
        UPDATE users
        SET master_password = ?, key = ?, security_stamp = ?,
            two_factor_providers = ?, two_factor_recovery_code = NULL,
            failed_login_count = 0, last_failed_login_date = NULL,
            revision_date = ?, account_revision_date = ?, last_password_change_date = ?
        WHERE id = ? AND EXISTS (
            SELECT 1 FROM emergency_access
            WHERE id = ? AND revision_date = ? AND revoked_date IS NULL
              AND status = ? AND type = ? AND grantee_id = ?
        )
    `).bind(
        newMasterPasswordHash,
        key,
        generateSecureRandomString(50),
        '[]',
        now,
        now,
        now,
        grantor.id,
        record.id,
        record.revisionDate,
        EmergencyAccessStatus.RecoveryApproved,
        EmergencyAccessType.Takeover,
        c.get('userId'),
    );
    const revokeRefreshTokens = c.env.DB.prepare(`
        DELETE FROM refresh_tokens
        WHERE user_id = ? AND EXISTS (
            SELECT 1 FROM emergency_access
            WHERE id = ? AND revision_date = ? AND revoked_date IS NULL
              AND status = ? AND type = ? AND grantee_id = ?
        )
    `).bind(
        grantor.id,
        record.id,
        record.revisionDate,
        EmergencyAccessStatus.RecoveryApproved,
        EmergencyAccessType.Takeover,
        c.get('userId'),
    );
    const removeNonOwnerOrganizations = c.env.DB.prepare(`
        DELETE FROM organization_users
        WHERE user_id = ? AND type <> 0 AND EXISTS (
            SELECT 1 FROM emergency_access
            WHERE id = ? AND revision_date = ? AND revoked_date IS NULL
              AND status = ? AND type = ? AND grantee_id = ?
        )
    `).bind(
        grantor.id,
        record.id,
        record.revisionDate,
        EmergencyAccessStatus.RecoveryApproved,
        EmergencyAccessType.Takeover,
        c.get('userId'),
    );
    const results = await c.env.DB.batch([updateUser, revokeRefreshTokens, removeNonOwnerOrganizations]);
    if (results[0].meta.changes !== 1) {
        throw new ConflictError('Emergency Access was changed by another request.');
    }

    notifyUser(c, grantor.id, 'password changed', { ...record, revisionDate: now });
    return c.body(null, 200);
});

emergency.post('/:id/view', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    try {
        assertEmergencyAccessCanBeUsed(record, c.get('userId'), EmergencyAccessType.View, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    const personalCiphers = await db.select().from(ciphers).where(and(
        eq(ciphers.userId, record.grantorId),
        isNull(ciphers.organizationId),
        sql`EXISTS (
            SELECT 1 FROM emergency_access ea
            WHERE ea.id = ${record.id} AND ea.revision_date = ${record.revisionDate}
              AND ea.revoked_date IS NULL AND ea.status = ${EmergencyAccessStatus.RecoveryApproved}
              AND ea.type = ${EmergencyAccessType.View} AND ea.grantee_id = ${c.get('userId')}
        )`,
    )).all();
    const baseUrl = getBaseUrl(c);
    return c.json({
        keyEncrypted: record.keyEncrypted,
        ciphers: await Promise.all(personalCiphers.map((cipher) => toCipherResponse(
            cipher,
            record.grantorId,
            baseUrl,
            c.env.JWT_SECRET,
            'cipher',
        ))),
        object: 'emergencyAccessView',
    });
});

emergency.get('/:id/:cipherId/attachment/:attachmentId', async (c) => {
    const db = drizzle(c.env.DB);
    const record = await getRecord(db, c.req.param('id'));
    try {
        assertEmergencyAccessCanBeUsed(record, c.get('userId'), EmergencyAccessType.View, new Date());
    } catch (error) {
        mapDomainError(error);
    }
    const cipherId = c.req.param('cipherId');
    const attachmentId = c.req.param('attachmentId');
    const cipher = await db.select({
        id: ciphers.id,
        attachments: ciphers.attachments,
    }).from(ciphers).where(and(
        eq(ciphers.id, cipherId),
        eq(ciphers.userId, record.grantorId),
        isNull(ciphers.organizationId),
        sql`EXISTS (
            SELECT 1 FROM emergency_access ea
            WHERE ea.id = ${record.id} AND ea.revision_date = ${record.revisionDate}
              AND ea.revoked_date IS NULL AND ea.status = ${EmergencyAccessStatus.RecoveryApproved}
              AND ea.type = ${EmergencyAccessType.View} AND ea.grantee_id = ${c.get('userId')}
        )`,
    )).get();
    if (!cipher) throw new NotFoundError('Cipher not found.');

    let attachments: Record<string, { fileName?: string | null; key?: string | null; size?: string }>;
    try {
        attachments = cipher.attachments ? JSON.parse(cipher.attachments) : {};
    } catch {
        throw new NotFoundError('Attachment not found.');
    }
    const metadata = attachments[attachmentId];
    if (!metadata) throw new NotFoundError('Attachment not found.');
    const stored = await c.env.ATTACHMENTS.head(`${cipherId}/${attachmentId}`);
    if (!stored) throw new NotFoundError('Attachment not found.');

    const { size, sizeName } = readableSize(metadata.size ?? stored.size);
    return c.json({
        id: attachmentId,
        url: await buildAttachmentDownloadUrl(getBaseUrl(c), cipherId, attachmentId, c.env.JWT_SECRET),
        fileName: metadata.fileName ?? null,
        key: metadata.key ?? null,
        size,
        sizeName,
        object: 'attachment',
    });
});

export default emergency;
