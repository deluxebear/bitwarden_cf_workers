import { env, SELF } from 'cloudflare:test';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { beforeAll, describe, expect, it } from 'vitest';
import { signJwt, signJwtClaims } from '../src/middleware/auth';
import { emergencyAccess } from '../src/db/schema';
import { persistEmergencyAccessRecordCas } from '../src/routes/emergency-access';
import { approveExpiredEmergencyAccessRecords } from '../src/services/scheduled';
import { EmergencyAccessStatus, type EmergencyAccessRecord } from '../src/services/emergency-access';

type TestUser = { id: string; email: string; securityStamp: string; token: string };

async function createUser(id: string, email: string): Promise<TestUser> {
    const securityStamp = `stamp-${id}`;
    const now = new Date().toISOString();
    await env.DB.prepare(`
        INSERT INTO users
            (id, email, security_stamp, account_revision_date, api_key, creation_date, revision_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(id, email, securityStamp, now, `api-${id}`, now, now).run();
    const token = await signJwt({
        sub: id,
        email,
        email_verified: true,
        name: id,
        premium: true,
        sstamp: securityStamp,
        device: `device-${id}`,
        scope: ['api'],
        amr: ['Application'],
    }, env.JWT_SECRET, 3600);
    return { id, email, securityStamp, token };
}

function request(user: TestUser, path: string, init?: RequestInit) {
    const headers = new Headers(init?.headers);
    headers.set('Authorization', `Bearer ${user.token}`);
    if (init?.body) headers.set('Content-Type', 'application/json');
    return SELF.fetch(`https://example.com/api/emergency-access${path}`, { ...init, headers });
}

describe('Emergency Access routes', () => {
    let grantor: TestUser;
    let grantee: TestUser;
    let outsider: TestUser;
    let accessId: string;
    let inviteToken: string;

    beforeAll(async () => {
        grantor = await createUser('ea-grantor', 'ea-grantor@example.com');
        grantee = await createUser('ea-grantee', 'ea-grantee@example.com');
        outsider = await createUser('ea-outsider', 'ea-outsider@example.com');
    });

    it('persists invite, lists it, and enforces detail ownership', async () => {
        const invited = await request(grantor, '/invite', {
            method: 'POST',
            body: JSON.stringify({ email: grantee.email, type: 1, waitTimeDays: 0 }),
        });
        expect(invited.status).toBe(200);

        const row = await env.DB.prepare(
            'SELECT id, status, email, revision_date FROM emergency_access WHERE grantor_id = ?',
        ).bind(grantor.id).first<{ id: string; status: number; email: string; revision_date: string }>();
        expect(row).toMatchObject({ status: 0, email: grantee.email });
        accessId = row!.id;
        inviteToken = await signJwtClaims({
            purpose: 'emergency_access_invite',
            emergencyAccessId: accessId,
            email: grantee.email,
            revisionDate: row!.revision_date,
        }, env.JWT_SECRET, 3600);

        const trusted = await request(grantor, '/trusted');
        expect(trusted.status).toBe(200);
        const trustedBody = await trusted.json<any>();
        expect(trustedBody.data).toEqual([
            expect.objectContaining({ id: accessId, email: grantee.email, status: 0,
                object: 'emergencyAccessGranteeDetails' }),
        ]);

        expect((await request(outsider, `/${accessId}`)).status).toBe(403);
        const details = await request(grantor, `/${accessId}`);
        expect(details.status).toBe(200);
        await expect(details.json()).resolves.toEqual(expect.objectContaining({ id: accessId, status: 0 }));
    });

    it('runs accept, confirm, initiate, approve and takeover against D1', async () => {
        expect((await request(grantee, `/${accessId}/accept`, {
            method: 'POST', body: JSON.stringify({ token: 'not-a-signed-token' }),
        })).status).toBe(400);
        const beforeAccept = await env.DB.prepare(
            'SELECT status, grantee_id FROM emergency_access WHERE id = ?',
        ).bind(accessId).first();
        expect(beforeAccept).toEqual(expect.objectContaining({ status: 0, grantee_id: null }));

        expect((await request(grantee, `/${accessId}/accept`, {
            method: 'POST', body: JSON.stringify({ token: inviteToken }),
        })).status).toBe(200);

        const granted = await request(grantee, '/granted');
        const grantedBody = await granted.json<any>();
        expect(grantedBody.data).toEqual([
            expect.objectContaining({ id: accessId, grantorId: grantor.id, status: 1,
                object: 'emergencyAccessGrantorDetails' }),
        ]);

        expect((await request(grantor, `/${accessId}/confirm`, {
            method: 'POST', body: JSON.stringify({ key: 'client-encrypted-key' }),
        })).status).toBe(200);
        expect((await request(grantee, `/${accessId}/initiate`, { method: 'POST' })).status).toBe(200);

        expect((await request(grantee, `/${accessId}/takeover`, { method: 'POST' })).status).toBe(403);
        expect((await request(grantor, `/${accessId}/approve`, { method: 'POST' })).status).toBe(200);

        const takeover = await request(grantee, `/${accessId}/takeover`, { method: 'POST' });
        expect(takeover.status).toBe(200);
        await expect(takeover.json()).resolves.toEqual(expect.objectContaining({
            keyEncrypted: 'client-encrypted-key',
            salt: grantor.email,
            object: 'emergencyAccessTakeover',
        }));

        const persisted = await env.DB.prepare(
            'SELECT status, grantee_id, key_encrypted FROM emergency_access WHERE id = ?',
        ).bind(accessId).first();
        expect(persisted).toEqual(expect.objectContaining({
            status: 4,
            grantee_id: grantee.id,
            key_encrypted: 'client-encrypted-key',
        }));
    });

    it('updates the grantor password atomically and revokes refresh tokens', async () => {
        const before = await env.DB.prepare(
            'SELECT security_stamp, kdf, kdf_iterations FROM users WHERE id = ?',
        ).bind(grantor.id).first<{ security_stamp: string; kdf: number; kdf_iterations: number }>();
        await env.DB.prepare(`
            INSERT INTO refresh_tokens (id, user_id, token_hash, expiration_date, creation_date)
            VALUES (?, ?, ?, ?, ?)
        `).bind(
            'ea-refresh-token', grantor.id, 'ea-refresh-hash',
            new Date(Date.now() + 86400000).toISOString(), new Date().toISOString(),
        ).run();
        const membershipNow = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO organizations (id, name, billing_email, creation_date, revision_date)
                VALUES (?, ?, ?, ?, ?)
            `).bind('ea-member-org', 'Member organization', grantor.email, membershipNow, membershipNow),
            env.DB.prepare(`
                INSERT INTO organizations (id, name, billing_email, creation_date, revision_date)
                VALUES (?, ?, ?, ?, ?)
            `).bind('ea-owner-org', 'Owner organization', grantor.email, membershipNow, membershipNow),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 2, 2, ?, ?)
            `).bind('ea-member-membership', 'ea-member-org', grantor.id, grantor.email, membershipNow, membershipNow),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 2, 0, ?, ?)
            `).bind('ea-owner-membership', 'ea-owner-org', grantor.id, grantor.email, membershipNow, membershipNow),
        ]);

        const unsupportedNewPayload = await request(grantee, `/${accessId}/password`, {
            method: 'POST', body: JSON.stringify({ unlockData: {}, authenticationData: {} }),
        });
        expect(unsupportedNewPayload.status).toBe(400);
        await expect(unsupportedNewPayload.json()).resolves.toEqual(expect.objectContaining({
            message: expect.stringContaining('new Emergency Access password payload'),
        }));

        const password = await request(grantee, `/${accessId}/password`, {
            method: 'POST', body: JSON.stringify({
                newMasterPasswordHash: 'new-grantor-master-password-hash',
                key: 'new-master-password-wrapped-user-key',
            }),
        });
        expect(password.status).toBe(200);

        const after = await env.DB.prepare(`
            SELECT master_password, key, security_stamp, two_factor_providers,
                   account_revision_date, revision_date, last_password_change_date,
                   kdf, kdf_iterations
            FROM users WHERE id = ?
        `).bind(grantor.id).first<Record<string, unknown>>();
        expect(after).toEqual(expect.objectContaining({
            master_password: 'new-grantor-master-password-hash',
            key: 'new-master-password-wrapped-user-key',
            two_factor_providers: '[]',
            kdf: before!.kdf,
            kdf_iterations: before!.kdf_iterations,
        }));
        expect(after!.security_stamp).not.toBe(before!.security_stamp);
        expect(after!.account_revision_date).toBe(after!.revision_date);
        expect(after!.last_password_change_date).toBe(after!.revision_date);
        expect(await env.DB.prepare(
            'SELECT COUNT(*) AS count FROM refresh_tokens WHERE user_id = ?',
        ).bind(grantor.id).first<{ count: number }>()).toEqual({ count: 0 });
        expect(await env.DB.prepare(`
            SELECT organization_id, type
            FROM organization_users
            WHERE user_id = ?
            ORDER BY organization_id
        `).bind(grantor.id).all()).toEqual(expect.objectContaining({
            results: [{ organization_id: 'ea-owner-org', type: 0 }],
        }));

        expect((await request(grantee, `/${accessId}`, { method: 'DELETE' })).status).toBe(204);
        const granted = await request(grantee, '/granted');
        await expect(granted.json()).resolves.toEqual(expect.objectContaining({ data: [] }));
        expect((await request(grantee, `/${accessId}/takeover`, { method: 'POST' })).status).toBe(400);
    });

    it('returns only the grantor personal vault and protects attachment access', async () => {
        const now = new Date().toISOString();
        const viewAccessId = 'ea-view-approved';
        const personalCipherId = 'ea-personal-cipher';
        const organizationCipherId = 'ea-organization-cipher';
        const outsiderCipherId = 'ea-outsider-cipher';
        const attachmentId = 'ea-attachment';
        const attachmentMetadata = JSON.stringify({
            [attachmentId]: {
                fileName: 'encrypted-file-name',
                key: 'encrypted-attachment-key',
                size: '18',
            },
        });

        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO emergency_access
                    (id, grantor_id, grantee_id, key_encrypted, type, status, wait_time_days,
                     creation_date, revision_date)
                VALUES (?, ?, ?, ?, 0, 4, 0, ?, ?)
            `).bind(viewAccessId, grantor.id, grantee.id, 'view-encrypted-key', now, now),
            env.DB.prepare(`
                INSERT INTO ciphers
                    (id, user_id, organization_id, type, data, attachments, creation_date, revision_date)
                VALUES (?, ?, NULL, 1, ?, ?, ?, ?)
            `).bind(
                personalCipherId,
                grantor.id,
                JSON.stringify({ name: 'encrypted-personal-name', login: { username: 'encrypted-user' } }),
                attachmentMetadata,
                now,
                now,
            ),
            env.DB.prepare(`
                INSERT INTO ciphers
                    (id, user_id, organization_id, type, data, creation_date, revision_date)
                VALUES (?, ?, ?, 1, ?, ?, ?)
            `).bind(
                organizationCipherId, grantor.id, 'ea-organization',
                JSON.stringify({ name: 'encrypted-organization-name' }), now, now,
            ),
            env.DB.prepare(`
                INSERT INTO ciphers
                    (id, user_id, organization_id, type, data, creation_date, revision_date)
                VALUES (?, ?, NULL, 1, ?, ?, ?)
            `).bind(
                outsiderCipherId, outsider.id,
                JSON.stringify({ name: 'encrypted-outsider-name' }), now, now,
            ),
        ]);
        await env.ATTACHMENTS.put(
            `${personalCipherId}/${attachmentId}`,
            new TextEncoder().encode('encrypted-r2-body'),
            { httpMetadata: { contentType: 'application/octet-stream' } },
        );

        expect((await request(outsider, `/${viewAccessId}/view`, { method: 'POST' })).status).toBe(403);
        const view = await request(grantee, `/${viewAccessId}/view`, { method: 'POST' });
        expect(view.status).toBe(200);
        const viewBody = await view.json<any>();
        expect(viewBody).toEqual(expect.objectContaining({
            keyEncrypted: 'view-encrypted-key',
            object: 'emergencyAccessView',
        }));
        expect(viewBody.ciphers).toHaveLength(1);
        expect(viewBody.ciphers[0]).toEqual(expect.objectContaining({
            id: personalCipherId,
            data: expect.stringContaining('encrypted-personal-name'),
            object: 'cipher',
        }));

        expect((await request(outsider,
            `/${viewAccessId}/${personalCipherId}/attachment/${attachmentId}`)).status).toBe(403);
        expect((await request(grantee,
            `/${viewAccessId}/${outsiderCipherId}/attachment/${attachmentId}`)).status).toBe(404);

        const attachment = await request(grantee,
            `/${viewAccessId}/${personalCipherId}/attachment/${attachmentId}`);
        expect(attachment.status).toBe(200);
        const attachmentBody = await attachment.json<any>();
        expect(attachmentBody).toEqual(expect.objectContaining({
            id: attachmentId,
            fileName: 'encrypted-file-name',
            key: 'encrypted-attachment-key',
            size: '18',
            object: 'attachment',
        }));
        const download = await SELF.fetch(attachmentBody.url);
        expect(download.status).toBe(200);
        expect(new TextDecoder().decode(await download.arrayBuffer())).toBe('encrypted-r2-body');
    });

    it('uses revision CAS so a stale state transition cannot resurrect revoked access', async () => {
        const casGrantor = await createUser('ea-cas-grantor', 'ea-cas-grantor@example.com');
        const casGrantee = await createUser('ea-cas-grantee', 'ea-cas-grantee@example.com');
        const now = new Date().toISOString();
        const id = 'ea-cas-access';
        await env.DB.prepare(`
            INSERT INTO emergency_access
                (id, grantor_id, grantee_id, key_encrypted, type, status, wait_time_days,
                 recovery_initiated_date, creation_date, revision_date)
            VALUES (?, ?, ?, ?, 0, 3, 0, ?, ?, ?)
        `).bind(id, casGrantor.id, casGrantee.id, 'cas-key', now, now, now).run();

        const db = drizzle(env.DB);
        const original = await db.select().from(emergencyAccess)
            .where(eq(emergencyAccess.id, id)).get() as EmergencyAccessRecord;
        const revokedAt = new Date(Date.now() + 1000).toISOString();
        await env.DB.prepare(`
            UPDATE emergency_access
            SET revoked_date = ?, revoked_by_user_id = ?, revision_date = ?
            WHERE id = ?
        `).bind(revokedAt, casGrantor.id, revokedAt, id).run();

        await expect(persistEmergencyAccessRecordCas(db, original, {
            ...original,
            status: EmergencyAccessStatus.RecoveryApproved,
            revisionDate: new Date(Date.now() + 2000).toISOString(),
        })).rejects.toThrow(/changed by another request/i);
        expect(await env.DB.prepare(
            'SELECT status, revoked_date FROM emergency_access WHERE id = ?',
        ).bind(id).first()).toEqual(expect.objectContaining({
            status: EmergencyAccessStatus.RecoveryInitiated,
            revoked_date: revokedAt,
        }));
    });

    it('auto-approves only elapsed, active recovery requests', async () => {
        const fixedNow = new Date('2026-07-10T12:00:00.000Z');
        const rows = [
            { suffix: 'due', initiated: '2026-07-08T12:00:00.000Z', waitDays: 1, revoked: null },
            { suffix: 'waiting', initiated: '2026-07-10T00:00:00.000Z', waitDays: 1, revoked: null },
            { suffix: 'revoked', initiated: '2026-07-08T12:00:00.000Z', waitDays: 1,
                revoked: '2026-07-09T12:00:00.000Z' },
        ];
        for (const row of rows) {
            const autoGrantor = await createUser(
                `ea-auto-grantor-${row.suffix}`,
                `ea-auto-grantor-${row.suffix}@example.com`,
            );
            const autoGrantee = await createUser(
                `ea-auto-grantee-${row.suffix}`,
                `ea-auto-grantee-${row.suffix}@example.com`,
            );
            await env.DB.prepare(`
                INSERT INTO emergency_access
                    (id, grantor_id, grantee_id, key_encrypted, type, status, wait_time_days,
                     recovery_initiated_date, revoked_date, revoked_by_user_id,
                     creation_date, revision_date)
                VALUES (?, ?, ?, ?, 0, 3, ?, ?, ?, ?, ?, ?)
            `).bind(
                `ea-auto-${row.suffix}`,
                autoGrantor.id,
                autoGrantee.id,
                `auto-key-${row.suffix}`,
                row.waitDays,
                row.initiated,
                row.revoked,
                row.revoked ? autoGrantor.id : null,
                row.initiated,
                row.revoked ?? row.initiated,
            ).run();
        }

        expect(await approveExpiredEmergencyAccessRecords(env, fixedNow)).toBe(1);
        const statuses = await env.DB.prepare(`
            SELECT id, status, revoked_date FROM emergency_access WHERE id LIKE 'ea-auto-%' ORDER BY id
        `).all<{ id: string; status: number; revoked_date: string | null }>();
        expect(statuses.results).toEqual([
            expect.objectContaining({ id: 'ea-auto-due', status: EmergencyAccessStatus.RecoveryApproved }),
            expect.objectContaining({ id: 'ea-auto-revoked', status: EmergencyAccessStatus.RecoveryInitiated,
                revoked_date: '2026-07-09T12:00:00.000Z' }),
            expect.objectContaining({ id: 'ea-auto-waiting', status: EmergencyAccessStatus.RecoveryInitiated }),
        ]);
    });
});
