import { env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { upsertDuoConfig } from '../src/services/duo-storage';
import { createDuoTwoFactorParams } from '../src/routes/identity';

const encryptionKey = 'MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=';
const duoConfig = {
    clientId: 'DIXXXXXXXXXXXXXXXXXX',
    clientSecret: '0123456789012345678901234567890123456789',
    host: 'api-test.duosecurity.com',
};

function passwordForm(email: string, password: string, provider?: number, token?: string) {
    const form = new URLSearchParams({
        grant_type: 'password',
        client_id: 'web',
        scope: 'api offline_access',
        username: email,
        password,
        deviceType: '9',
        deviceIdentifier: `duo-device-${email}`,
        deviceName: 'Duo integration browser',
    });
    if (provider !== undefined) form.set('TwoFactorProvider', String(provider));
    if (token) form.set('TwoFactorToken', token);
    return form;
}

describe('Duo Universal Prompt login integration', () => {
    beforeAll(async () => {
        const now = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, email_verified, master_password, premium, security_stamp,
                     account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, 1, ?, 1, ?, ?, ?, ?, ?)
            `).bind(
                'duo-login-user', 'duo-login@example.com', 'duo-password', 'duo-stamp', now,
                'duo-api-key', now, now,
            ),
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, email_verified, master_password, security_stamp,
                     account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)
            `).bind(
                'duo-org-user', 'duo-org-user@example.com', 'duo-org-password', 'duo-org-stamp', now,
                'duo-org-api-key', now, now,
            ),
            env.DB.prepare(`
                INSERT INTO organizations
                    (id, name, billing_email, use_2fa, enabled, two_factor_providers,
                     creation_date, revision_date)
                VALUES (?, ?, ?, 1, 1, NULL, ?, ?)
            `).bind(
                'duo-login-org', 'Duo organization', 'duo-org-user@example.com',
                now, now,
            ),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 2, 2, ?, ?)
            `).bind(
                'duo-login-org-user', 'duo-login-org', 'duo-org-user', 'duo-org-user@example.com', now, now,
            ),
        ]);
        const personal = await upsertDuoConfig(env.DB, encryptionKey, { userId: 'duo-login-user' }, duoConfig);
        const organization = await upsertDuoConfig(
            env.DB,
            encryptionKey,
            { organizationId: 'duo-login-org' },
            { ...duoConfig, clientId: 'DIYYYYYYYYYYYYYYYYYY' },
        );
        await env.DB.batch([
            env.DB.prepare('UPDATE users SET two_factor_providers = ? WHERE id = ?').bind(
                JSON.stringify({ 2: { enabled: true, metaData: { ConfigId: personal.id } } }),
                'duo-login-user',
            ),
            env.DB.prepare('UPDATE organizations SET two_factor_providers = ? WHERE id = ?').bind(
                JSON.stringify({ 6: { enabled: true, metaData: { ConfigId: organization.id } } }),
                'duo-login-org',
            ),
        ]);
    });

    it('returns a client-compatible personal Duo challenge without exposing the secret', async () => {
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?')
            .bind('duo-login-user').first<any>();
        const params = await createDuoTwoFactorParams(
            env,
            user!,
            { providerType: 2, provider: { metaData: { ConfigId: 'user:duo-login-user' } }, organizationId: null },
            'web',
            undefined,
            async () => true,
        );
        expect(params).toEqual(expect.objectContaining({
            Host: duoConfig.host,
            AuthUrl: expect.stringContaining(`https://${duoConfig.host}/oauth/v1/authorize?`),
        }));
        expect(JSON.stringify(params)).not.toContain(duoConfig.clientSecret);
        const authUrl = new URL(params.AuthUrl);
        expect(authUrl.searchParams.get('redirect_uri')).toBe(
            'https://vault.example.com/duo-redirect-connector.html?client=web',
        );
        expect(authUrl.searchParams.get('scope')).toBe('openid');
    });

    it('rejects an unbound Duo state without contacting Duo', async () => {
        const response = await SELF.fetch('https://example.com/identity/connect/token', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: passwordForm('duo-login@example.com', 'duo-password', 2, 'code|not-a-valid-state'),
        });
        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toEqual(expect.objectContaining({
            error: 'invalid_grant',
        }));
    });

    it('enforces the first enabled organization Duo provider', async () => {
        const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?')
            .bind('duo-org-user').first<any>();
        const params = await createDuoTwoFactorParams(
            env,
            user!,
            {
                providerType: 6,
                provider: { metaData: { ConfigId: 'organization:duo-login-org' } },
                organizationId: 'duo-login-org',
            },
            'web',
            undefined,
            async () => true,
        );
        expect(params).toEqual(expect.objectContaining({
            Host: duoConfig.host,
            AuthUrl: expect.any(String),
        }));
    });
});
