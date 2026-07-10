import { env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { validateClientRedirectUri } from '../src/services/oidc-login';

type ClientProfile = {
    name: 'web' | 'browser' | 'desktop' | 'mobile';
    deviceType: number;
    excludeDomains: boolean;
};

const clients: ClientProfile[] = [
    { name: 'web', deviceType: 9, excludeDomains: false },
    { name: 'browser', deviceType: 2, excludeDomains: false },
    { name: 'desktop', deviceType: 6, excludeDomains: true },
    { name: 'mobile', deviceType: 0, excludeDomains: false },
];

const now = '2026-07-10T00:00:00.000Z';

function userId(client: ClientProfile): string {
    return `compat-${client.name}-user`;
}

function email(client: ClientProfile): string {
    return `compat-${client.name}@example.com`;
}

function deviceIdentifier(client: ClientProfile): string {
    return `compat-${client.name}-device`;
}

function tokenRequest(client: ClientProfile, grant: 'password' | 'refresh_token', value: string) {
    const form = new URLSearchParams({
        grant_type: grant,
        client_id: client.name,
        scope: 'api offline_access',
    });
    if (grant === 'password') {
        form.set('username', email(client).toUpperCase());
        form.set('password', value);
        form.set('deviceType', String(client.deviceType));
        form.set('deviceIdentifier', deviceIdentifier(client));
        form.set('deviceName', `${client.name} compatibility client`);
    } else {
        form.set('refresh_token', value);
    }
    return form;
}

describe('official client compatibility contract', () => {
    beforeAll(async () => {
        const statements: D1PreparedStatement[] = [];
        for (const client of clients) {
            statements.push(
                env.DB.prepare(`
                    INSERT INTO users
                        (id, name, email, email_verified, master_password, security_stamp,
                         account_revision_date, key, public_key, private_key, kdf,
                         kdf_iterations, api_key, creation_date, revision_date)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, 600000, ?, ?, ?)
                `).bind(
                    userId(client), `${client.name} client`, email(client),
                    `compat-password-${client.name}`, `compat-stamp-${client.name}`,
                    now, `2.compat-key-${client.name}`, `compat-public-${client.name}`,
                    `2.compat-private-${client.name}`, `compat-api-key-${client.name}`, now, now,
                ),
                env.DB.prepare(`
                    INSERT INTO devices
                        (id, user_id, name, type, identifier, active, creation_date, revision_date)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                `).bind(
                    `compat-${client.name}-device-row`, userId(client),
                    `${client.name} compatibility client`, client.deviceType,
                    deviceIdentifier(client), now, now,
                ),
            );
            if (client.name === 'browser') {
                statements.push(env.DB.prepare(`
                    INSERT INTO devices
                        (id, user_id, name, type, identifier, active, creation_date, revision_date)
                    VALUES (?, ?, ?, 26, ?, 1, ?, ?)
                `).bind(
                    'compat-duckduckgo-device-row', userId(client),
                    'DuckDuckGo compatibility client', 'compat-duckduckgo-device', now, now,
                ));
            }
        }
        statements.push(env.DB.prepare(`
            INSERT INTO users
                (id, email, email_verified, security_stamp, account_revision_date,
                 kdf, kdf_iterations, kdf_memory, kdf_parallelism, api_key,
                 creation_date, revision_date)
            VALUES (?, ?, 1, ?, ?, 1, 3, 64, 4, ?, ?, ?)
        `).bind(
            'compat-argon-user', 'compat-argon@example.com', 'compat-argon-stamp', now,
            'compat-argon-api-key', now, now,
        ));
        await env.DB.batch(statements);
    });

    describe('prelogin', () => {
        it('keeps legacy and current endpoints byte-for-byte compatible for Argon2 clients', async () => {
            const request = () => ({
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ email: '  COMPAT-ARGON@EXAMPLE.COM  ' }),
            });
            const legacy = await SELF.fetch('https://example.com/identity/accounts/prelogin', request());
            const current = await SELF.fetch('https://example.com/identity/accounts/prelogin/password', request());

            expect(legacy.status).toBe(200);
            expect(current.status).toBe(200);
            const legacyBody = await legacy.json<Record<string, unknown>>();
            const currentBody = await current.json<Record<string, unknown>>();
            expect(currentBody).toEqual(legacyBody);
            expect(currentBody).toEqual({
                kdf: 1,
                kdfIterations: 3,
                kdfMemory: 64,
                kdfParallelism: 4,
                kdfSettings: {
                    kdfType: 1,
                    iterations: 3,
                    memory: 64,
                    parallelism: 4,
                },
                salt: 'compat-argon@example.com',
            });
        });

        it('normalizes an unknown account salt consistently without revealing account existence', async () => {
            const prelogin = async (value: string) => SELF.fetch(
                'https://example.com/identity/accounts/prelogin/password',
                {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify({ email: value }),
                },
            );
            const lower = await prelogin('missing-compat@example.com');
            const mixed = await prelogin('  MISSING-COMPAT@EXAMPLE.COM ');

            expect(lower.status).toBe(200);
            expect(mixed.status).toBe(200);
            await expect(lower.json()).resolves.toEqual(await mixed.json());
        });
    });

    describe.each(clients)('$name password, refresh and sync', (client) => {
        it('accepts the shared client form contract and returns client-parseable responses', async () => {
            const password = await SELF.fetch('https://example.com/identity/connect/token', {
                method: 'POST',
                headers: {
                    'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
                    accept: 'application/json',
                    'device-type': String(client.deviceType),
                },
                body: tokenRequest(client, 'password', `compat-password-${client.name}`),
            });
            expect(password.status).toBe(200);
            const passwordBody = await password.json<Record<string, unknown>>();
            expect(passwordBody).toEqual(expect.objectContaining({
                access_token: expect.any(String),
                expires_in: expect.any(Number),
                refresh_token: expect.any(String),
                token_type: 'Bearer',
                Key: `2.compat-key-${client.name}`,
                PrivateKey: `2.compat-private-${client.name}`,
                Kdf: 0,
                KdfIterations: 600000,
                ForcePasswordReset: false,
                scope: 'api offline_access',
                UserDecryptionOptions: expect.objectContaining({
                    HasMasterPassword: true,
                    MasterPasswordUnlock: expect.objectContaining({
                        MasterKeyEncryptedUserKey: `2.compat-key-${client.name}`,
                        Salt: email(client),
                    }),
                }),
            }));

            const refresh = await SELF.fetch('https://example.com/identity/connect/token', {
                method: 'POST',
                headers: {
                    'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
                    accept: 'application/json',
                    'device-type': String(client.deviceType),
                },
                body: tokenRequest(client, 'refresh_token', String(passwordBody.refresh_token)),
            });
            expect(refresh.status).toBe(200);
            const refreshBody = await refresh.json<Record<string, unknown>>();
            expect(refreshBody).toEqual(expect.objectContaining({
                access_token: expect.any(String),
                expires_in: expect.any(Number),
                refresh_token: expect.any(String),
                token_type: 'Bearer',
            }));
            expect(refreshBody.refresh_token).not.toBe(passwordBody.refresh_token);

            const syncPath = client.excludeDomains
                ? '/api/sync?excludeDomains=true'
                : '/api/sync';
            const sync = await SELF.fetch(`https://example.com${syncPath}`, {
                headers: { authorization: `Bearer ${String(refreshBody.access_token)}` },
            });
            expect(sync.status).toBe(200);
            const syncBody = await sync.json<Record<string, any>>();
            expect(syncBody).toEqual(expect.objectContaining({
                object: 'sync',
                profile: expect.objectContaining({
                    id: userId(client),
                    email: email(client),
                    emailVerified: true,
                    forcePasswordReset: false,
                    object: 'profile',
                }),
                folders: [],
                collections: [],
                policies: [],
                ciphers: [],
                sends: [],
                userDecryption: expect.objectContaining({
                    masterPasswordUnlock: expect.objectContaining({
                        masterKeyEncryptedUserKey: `2.compat-key-${client.name}`,
                        salt: email(client),
                    }),
                }),
            }));
            if (client.excludeDomains) {
                expect(syncBody.domains).toBeNull();
            } else {
                expect(syncBody.domains).toEqual(expect.objectContaining({ object: 'domains' }));
            }
        });
    });

    describe('OIDC registered redirect allowlist', () => {
        it.each([
            ['web', 'https://vault.example.com/sso-connector.html'],
            ['browser', 'https://vault.example.com/sso-connector.html'],
            ['desktop', 'bitwarden://sso-callback'],
            ['desktop', 'http://localhost:8065/'],
            ['desktop', 'http://localhost:8070/'],
            ['mobile', 'bitwarden://sso-callback'],
            ['mobile', 'https://bitwarden.pw/sso-callback'],
            ['mobile', 'https://bitwarden.com/sso-callback'],
            ['mobile', 'https://bitwarden.eu/sso-callback'],
            ['mobile', 'https://bitwarden-gov.com/sso-callback'],
        ])('accepts the upstream %s callback %s', (clientId, redirectUri) => {
            expect(validateClientRedirectUri(redirectUri, clientId, 'https://vault.example.com'))
                .toBe(new URL(redirectUri).toString());
        });

        it.each([
            ['web', 'https://attacker.example/sso-connector.html'],
            ['browser', 'https://vault.example.com/other.html'],
            ['desktop', 'http://localhost:8064/'],
            ['desktop', 'http://127.0.0.1:8065/'],
            ['mobile', 'https://attacker.example/sso-callback'],
            ['unknown', 'bitwarden://sso-callback'],
        ])('rejects an unregistered %s callback %s', (clientId, redirectUri) => {
            expect(() => validateClientRedirectUri(redirectUri, clientId, 'https://vault.example.com'))
                .toThrow('redirect_uri is not registered');
        });
    });

    describe('client and device allowlists', () => {
        it.each(['web', 'browser', 'desktop', 'mobile', 'cli', 'connector'])(
            'recognizes official client_id %s before validating credentials',
            async (clientId) => {
                const response = await SELF.fetch('https://example.com/identity/connect/token', {
                    method: 'POST',
                    headers: { 'content-type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        grant_type: 'password',
                        client_id: clientId,
                        username: 'missing-client-allowlist@example.com',
                        password: 'invalid-password',
                    }),
                });
                expect(response.status).toBe(400);
                await expect(response.json()).resolves.toEqual(expect.objectContaining({
                    error: 'invalid_grant',
                }));
            },
        );

        it.each(['password', 'refresh_token', 'authorization_code', 'webauthn'])(
            'rejects unknown client_id for the %s grant before grant processing',
            async (grantType) => {
                const response = await SELF.fetch('https://example.com/identity/connect/token', {
                    method: 'POST',
                    headers: { 'content-type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({
                        grant_type: grantType,
                        client_id: 'unregistered-client',
                    }),
                });
                expect(response.status).toBe(400);
                await expect(response.json()).resolves.toEqual(expect.objectContaining({
                    error: 'invalid_client',
                    error_description: 'client_id is invalid.',
                }));
            },
        );

        it('does not apply the interactive client allowlist to the internal send_access grant', async () => {
            const response = await SELF.fetch('https://example.com/identity/connect/token', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ grant_type: 'send_access' }),
            });
            expect(response.status).toBe(400);
            const body = await response.json<Record<string, unknown>>();
            expect(body.error).toBe('invalid_request');
            expect(body.error).not.toBe('invalid_client');
        });

        it('accepts the current DuckDuckGoBrowser device type 26', async () => {
            const client = clients.find((entry) => entry.name === 'browser')!;
            const form = tokenRequest(client, 'password', 'compat-password-browser');
            form.set('deviceType', '26');
            form.set('deviceIdentifier', 'compat-duckduckgo-device');
            form.set('deviceName', 'DuckDuckGo compatibility client');
            const response = await SELF.fetch('https://example.com/identity/connect/token', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: form,
            });
            expect(response.status).toBe(200);
        });

        it('continues to reject device types beyond the current upstream enum', async () => {
            const client = clients.find((entry) => entry.name === 'browser')!;
            const form = tokenRequest(client, 'password', 'compat-password-browser');
            form.set('deviceType', '27');
            form.set('deviceIdentifier', 'compat-duckduckgo-device');
            const response = await SELF.fetch('https://example.com/identity/connect/token', {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: form,
            });
            expect(response.status).toBe(400);
            await expect(response.json()).resolves.toEqual(expect.objectContaining({
                message: 'deviceType is invalid.',
            }));
        });
    });
});
