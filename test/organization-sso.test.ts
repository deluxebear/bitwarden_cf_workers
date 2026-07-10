import { env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { signJwt } from '../src/middleware/auth';

const userId = 'sso-owner';
const email = 'sso-owner@example.com';
const organizationId = 'sso-organization';
let token: string;

interface SsoResponseBody {
    enabled: boolean;
    data: Record<string, unknown>;
}

function ssoRequest(init?: RequestInit) {
    const headers = new Headers(init?.headers);
    headers.set('Authorization', `Bearer ${token}`);
    if (init?.body) headers.set('Content-Type', 'application/json');
    return SELF.fetch(`https://example.com/api/organizations/${organizationId}/sso`, { ...init, headers });
}

describe('Organization SSO configuration routes', () => {
    beforeAll(async () => {
        const now = new Date().toISOString();
        const securityStamp = 'stamp-sso-owner';
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, security_stamp, account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `).bind(userId, email, securityStamp, now, 'api-sso-owner', now, now),
            env.DB.prepare(`
                INSERT INTO organizations
                    (id, name, billing_email, use_sso, creation_date, revision_date)
                VALUES (?, ?, ?, 1, ?, ?)
            `).bind(organizationId, 'SSO Test Organization', email, now, now),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 2, 0, ?, ?)
            `).bind('sso-owner-membership', organizationId, userId, email, now, now),
        ]);
        token = await signJwt({
            sub: userId,
            email,
            email_verified: true,
            name: userId,
            premium: true,
            sstamp: securityStamp,
            device: 'device-sso-owner',
            scope: ['api'],
            amr: ['Application'],
        }, env.JWT_SECRET, 3600);
    });

    it('persists disabled OIDC settings without storing or returning a plaintext secret', async () => {
        const rejected = await ssoRequest({
            method: 'POST',
            body: JSON.stringify({
                enabled: false,
                identifier: 'sso-test',
                data: { clientSecret: 'must-never-be-stored' },
            }),
        });
        expect(rejected.status).toBe(400);

        const saved = await ssoRequest({
            method: 'POST',
            body: JSON.stringify({
                enabled: false,
                identifier: 'sso-test',
                data: {
                    configType: 0,
                    authority: 'https://id.example.com/tenant/',
                    clientId: 'web-vault',
                    clientSecretEnv: 'SSO_OIDC_TEST_SECRET',
                    claimMapping: { email: ['email'] },
                },
            }),
        });
        expect(saved.status).toBe(200);
        const savedBody = await saved.json<SsoResponseBody>();
        expect(savedBody.enabled).toBe(false);
        expect(savedBody.data).toMatchObject({
            authority: 'https://id.example.com/tenant',
            clientId: 'web-vault',
            clientSecretEnv: 'SSO_OIDC_TEST_SECRET',
            clientSecretConfigured: true,
            redirectUri: 'https://example.com/oidc-signin',
            claimMapping: { email: ['email'] },
        });
        expect(savedBody.data).not.toHaveProperty('clientSecret');

        const row = await env.DB.prepare(`
            SELECT issuer, client_id, client_secret_env, redirect_uri, claim_mapping, data
            FROM sso_configs WHERE organization_id = ?
        `).bind(organizationId).first<Record<string, string>>();
        expect(row).toMatchObject({
            issuer: 'https://id.example.com/tenant',
            client_id: 'web-vault',
            client_secret_env: 'SSO_OIDC_TEST_SECRET',
            redirect_uri: 'https://example.com/oidc-signin',
            claim_mapping: JSON.stringify({ email: ['email'] }),
        });
        expect(row?.data).not.toContain('must-never-be-stored');
        expect(JSON.parse(row!.data)).not.toHaveProperty('clientSecret');

        const fetched = await ssoRequest();
        expect(fetched.status).toBe(200);
        const fetchedBody = await fetched.json<SsoResponseBody>();
        expect(fetchedBody.data).not.toHaveProperty('clientSecret');
        expect(fetchedBody.data.clientSecretEnv).toBe('SSO_OIDC_TEST_SECRET');
    });

    it('fails closed when enabling a config whose Worker secret binding is absent', async () => {
        const response = await ssoRequest({
            method: 'POST',
            body: JSON.stringify({ enabled: true, identifier: 'sso-test' }),
        });

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toEqual(expect.objectContaining({
            message: 'The configured OIDC Worker secret binding is missing.',
        }));
        const row = await env.DB.prepare(
            'SELECT enabled FROM sso_configs WHERE organization_id = ?',
        ).bind(organizationId).first<{ enabled: number }>();
        expect(row?.enabled).toBe(0);
    });
});
