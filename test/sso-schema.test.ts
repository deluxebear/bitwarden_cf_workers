import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('SSO OIDC D1 migration', () => {
    it('adds dedicated non-plaintext OIDC configuration columns', async () => {
        const columns = await env.DB.prepare('PRAGMA table_info(sso_configs)').all<{ name: string }>();
        const names = columns.results.map((column) => column.name);

        expect(names).toEqual(expect.arrayContaining([
            'issuer',
            'client_id',
            'client_secret_env',
            'redirect_uri',
            'claim_mapping',
        ]));
        expect(names).not.toContain('client_secret');
    });

    it('creates replay-safe OIDC runtime tables and a case-insensitive identifier index', async () => {
        const tables = await env.DB.prepare(`
            SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'oidc_%'
        `).all<{ name: string }>();
        expect(tables.results.map((row) => row.name)).toEqual(expect.arrayContaining([
            'oidc_login_states',
            'oidc_authorization_codes',
            'oidc_identities',
        ]));

        const index = await env.DB.prepare(`
            SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_organizations_identifier_lower'
        `).first<{ sql: string }>();
        expect(index?.sql).toContain('lower(`identifier`)');
    });
});
