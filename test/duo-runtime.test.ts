import { env } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';

import {
    consumeDuoLoginState,
    createDuoLoginState,
    deleteDuoConfig,
    getDuoConfigByOwner,
    upsertDuoConfig,
} from '../src/services/duo-storage';

const userId = 'duo-runtime-user';
const organizationId = 'duo-runtime-organization';
const clientId = 'DIABCDEFGHIJKLMNOPQR';
const clientSecret = '0123456789012345678901234567890123456789';
const host = 'api-12345678.duosecurity.com';
const key = btoa(String.fromCharCode(...Uint8Array.from({ length: 32 }, (_, index) => index + 1)));

describe('Duo encrypted configuration and one-time login state', () => {
    beforeAll(async () => {
        const now = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, security_stamp, account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(userId, 'duo-runtime@example.com', 'duo-runtime-stamp', now, 'duo-runtime-api', now, now),
            env.DB.prepare(`
                INSERT INTO organizations (id, name, billing_email, creation_date, revision_date)
                VALUES (?, ?, ?, ?, ?)
            `).bind(organizationId, 'Duo runtime organization', 'duo-runtime@example.com', now, now),
        ]);
    });

    it('round-trips an encrypted user config without persisting the plaintext secret', async () => {
        const stored = await upsertDuoConfig(env.DB, key, { userId }, { clientId, clientSecret, host });
        expect(stored).toMatchObject({ id: `user:${userId}`, userId, clientId, clientSecret, host });
        expect(stored.clientSecretPrefix).toBe(clientSecret.slice(0, 6));

        const raw = await env.DB.prepare(`
            SELECT client_secret_ciphertext, client_secret_iv, client_secret_prefix
            FROM duo_configs WHERE id = ?
        `).bind(stored.id).first<Record<string, string>>();
        expect(raw?.client_secret_ciphertext).not.toContain(clientSecret);
        expect(raw?.client_secret_prefix).toBe(clientSecret.slice(0, 6));
        await expect(getDuoConfigByOwner(env.DB, key, { userId })).resolves.toMatchObject({ clientSecret });
    });

    it('allows only one writer for the same expected config revision', async () => {
        const previous = await getDuoConfigByOwner(env.DB, key, { userId });
        const attempts = await Promise.allSettled([
            upsertDuoConfig(env.DB, key, { userId }, {
                clientId,
                clientSecret: 'a'.repeat(40),
                host,
            }, previous!.revisionDate),
            upsertDuoConfig(env.DB, key, { userId }, {
                clientId,
                clientSecret: 'b'.repeat(40),
                host,
            }, previous!.revisionDate),
        ]);
        expect(attempts.filter((attempt) => attempt.status === 'fulfilled')).toHaveLength(1);
        expect(attempts.filter((attempt) => attempt.status === 'rejected')).toHaveLength(1);
    });

    it('atomically consumes state once and binds it to user and provider', async () => {
        const config = await getDuoConfigByOwner(env.DB, key, { userId });
        const created = await createDuoLoginState(env.DB, {
            userId,
            providerType: 2,
            organizationId: null,
            configId: config!.id,
            configRevision: config!.revisionDate,
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=web',
        });
        expect(created.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(created.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);

        await expect(consumeDuoLoginState(env.DB, {
            state: created.state, userId: 'another-user', providerType: 2,
        })).resolves.toBeNull();
        await expect(consumeDuoLoginState(env.DB, {
            state: created.state, userId, providerType: 6,
        })).resolves.toBeNull();
        await expect(consumeDuoLoginState(env.DB, {
            state: created.state, userId, providerType: 2,
        })).resolves.toMatchObject({
            userId, providerType: 2, organizationId: null, configId: config!.id,
            nonce: created.nonce,
        });
        await expect(consumeDuoLoginState(env.DB, {
            state: created.state, userId, providerType: 2,
        })).resolves.toBeNull();

        await expect(createDuoLoginState(env.DB, {
            userId,
            providerType: 2,
            organizationId: null,
            configId: config!.id,
            configRevision: 'stale-revision',
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=web',
        })).rejects.toThrow('persist');
    });

    it('enforces organization ownership and cascades states when a config is deleted', async () => {
        const config = await upsertDuoConfig(
            env.DB, key, { organizationId }, { clientId, clientSecret, host: 'api-87654321.duofederal.com' },
        );
        const created = await createDuoLoginState(env.DB, {
            userId,
            providerType: 6,
            organizationId,
            configId: config.id,
            configRevision: config.revisionDate,
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=desktop&deeplinkScheme=bitwarden',
        });
        await expect(createDuoLoginState(env.DB, {
            userId,
            providerType: 6,
            organizationId: null,
            configId: config.id,
            configRevision: config.revisionDate,
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=web',
        })).rejects.toThrow('requires an organization');

        await expect(deleteDuoConfig(env.DB, { organizationId })).resolves.toBe(true);
        await expect(consumeDuoLoginState(env.DB, {
            state: created.state, userId, providerType: 6,
        })).resolves.toBeNull();
    });
});
