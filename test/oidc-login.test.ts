import { env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { createPkceChallenge } from '../src/services/oidc';
import { createOidcAuthorizationCode, createOidcLoginState } from '../src/services/oidc-login';

const organizationId = 'oidc-runtime-org';
const userId = 'oidc-runtime-user';
const email = 'oidc-user@example.com';
const clientRedirectUri = 'https://vault.example.com/sso-connector.html';
const clientId = 'web';
const verifier = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-._~'.slice(0, 64);

describe('OIDC SSO login runtime', () => {
    beforeAll(async () => {
        const now = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, email_verified, security_stamp, account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, 1, ?, ?, ?, ?, ?)
            `).bind(userId, email, 'oidc-stamp', now, 'oidc-api-key', now, now),
            env.DB.prepare(`
                INSERT INTO organizations
                    (id, identifier, name, billing_email, use_sso, enabled, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
            `).bind(organizationId, 'oidc-runtime', 'OIDC Runtime', email, now, now),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 2, 2, ?, ?)
            `).bind('oidc-runtime-membership', organizationId, userId, email, now, now),
            env.DB.prepare(`
                INSERT INTO sso_configs
                    (id, organization_id, enabled, issuer, client_id, client_secret_env, redirect_uri,
                     claim_mapping, data, creation_date, revision_date)
                VALUES (?, ?, 1, ?, ?, ?, ?, '{}', '{}', ?, ?)
            `).bind(
                'oidc-runtime-config', organizationId, 'https://id.example.com/tenant', 'provider-client',
                'SSO_OIDC_RUNTIME_SECRET', 'https://example.com/oidc-signin', now, now,
            ),
        ]);
    });

    it('prevalidates enabled identifiers case-insensitively without exposing provider configuration', async () => {
        const response = await SELF.fetch('https://example.com/identity/sso/prevalidate?domainHint=OIDC-RUNTIME');
        expect(response.status).toBe(200);
        const body = await response.json<Record<string, unknown>>();
        expect(body).toEqual({ token: expect.any(String), object: 'ssoPreValidate' });
        expect(JSON.stringify(body)).not.toContain('provider-client');
    });

    it('rejects unregistered client redirects before contacting the provider', async () => {
        const prevalidate = await SELF.fetch('https://example.com/identity/sso/prevalidate?domainHint=oidc-runtime');
        const { token } = await prevalidate.json<{ token: string }>();
        const query = new URLSearchParams({
            domain_hint: 'oidc-runtime',
            ssoToken: token,
            client_id: 'web',
            redirect_uri: 'https://attacker.example/callback',
            response_type: 'code',
            code_challenge: await createPkceChallenge(verifier),
            code_challenge_method: 'S256',
        });
        const response = await SELF.fetch(`https://example.com/identity/connect/authorize?${query}`);
        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toEqual(expect.objectContaining({ error: 'invalid_request' }));
    });

    it('mounts both callback paths and consumes provider state once', async () => {
        for (const path of ['/oidc-signin', '/identity/connect/callback']) {
            const state = await createOidcLoginState(env.DB, {
                organizationId,
                nonce: `nonce-${path}`,
                providerPkceVerifier: verifier,
                clientId,
                clientRedirectUri,
                clientState: `client-state-${path}`,
                clientCodeChallenge: await createPkceChallenge(verifier),
            });
            const callback = await SELF.fetch(
                `https://example.com${path}?error=access_denied&state=${encodeURIComponent(state)}`,
                { redirect: 'manual' },
            );
            expect(callback.status).toBe(302);
            const redirect = new URL(callback.headers.get('location')!);
            expect(redirect.origin + redirect.pathname).toBe(clientRedirectUri);
            expect(redirect.searchParams.get('error')).toBe('access_denied');
            expect(redirect.searchParams.get('state')).toBe(`client-state-${path}`);

            const replay = await SELF.fetch(
                `https://example.com${path}?error=access_denied&state=${encodeURIComponent(state)}`,
                { redirect: 'manual' },
            );
            expect(replay.status).toBe(400);
        }
    });

    it('exchanges a PKCE-bound downstream authorization code only once', async () => {
        const code = await createOidcAuthorizationCode(env.DB, {
            organizationId,
            userId,
            clientId,
            redirectUri: clientRedirectUri,
            codeChallenge: await createPkceChallenge(verifier),
        });
        const form = () => new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            code_verifier: verifier,
            redirect_uri: clientRedirectUri,
            client_id: clientId,
            deviceType: '10',
            deviceIdentifier: 'oidc-device',
            deviceName: 'OIDC Test Browser',
        });
        const exchange = await SELF.fetch('https://example.com/identity/connect/token', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: form(),
        });
        expect(exchange.status).toBe(200);
        await expect(exchange.json()).resolves.toEqual(expect.objectContaining({
            access_token: expect.any(String),
            refresh_token: expect.any(String),
            token_type: 'Bearer',
        }));

        const replay = await SELF.fetch('https://example.com/identity/connect/token', {
            method: 'POST',
            headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: form(),
        });
        expect(replay.status).toBe(400);
        await expect(replay.json()).resolves.toEqual(expect.objectContaining({ error: 'invalid_grant' }));
    });

    it('caps active anonymous login states per organization', async () => {
        for (let index = 0; index < 100; index += 1) {
            await createOidcLoginState(env.DB, {
                organizationId,
                nonce: `quota-nonce-${index}`,
                providerPkceVerifier: verifier,
                clientId,
                clientRedirectUri,
                clientState: null,
                clientCodeChallenge: await createPkceChallenge(verifier),
            });
        }
        await expect(createOidcLoginState(env.DB, {
            organizationId,
            nonce: 'quota-overflow',
            providerPkceVerifier: verifier,
            clientId,
            clientRedirectUri,
            clientState: null,
            clientCodeChallenge: await createPkceChallenge(verifier),
        })).rejects.toThrow('Too many active OIDC login requests.');
    });
});
