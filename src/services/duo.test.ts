import { decodeJwt, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import {
    buildDuoRedirectUri,
    checkDuoHealth,
    createDuoAuthorizationUrl,
    exchangeDuoAuthorizationCode,
    generateDuoOpaqueValue,
    normalizeDuoHost,
} from './duo';

const config = {
    clientId: 'DIABCDEFGHIJKLMNOPQR',
    clientSecret: '0123456789012345678901234567890123456789',
    host: 'api-12345678.duosecurity.com',
};
const now = new Date();

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
    return new Response(JSON.stringify(value), {
        ...init,
        headers: { 'content-type': 'application/json', ...init.headers },
    });
}

describe('Duo Universal Prompt configuration', () => {
    it('accepts only canonical Duo API hosts and emits official connector callbacks', () => {
        expect(normalizeDuoHost(' API-12345678.DUOSECURITY.COM ')).toBe(config.host);
        expect(() => normalizeDuoHost('api-12345678.duosecurity.com.evil.example')).toThrow();
        expect(() => normalizeDuoHost('api-12345678.duosecurity.com/path')).toThrow();

        expect(buildDuoRedirectUri('https://vault.example.com', 'desktop')).toBe(
            'https://vault.example.com/duo-redirect-connector.html?client=desktop&deeplinkScheme=bitwarden',
        );
        expect(buildDuoRedirectUri('https://vault.example.com/base/', 'mobile', 'https')).toBe(
            'https://vault.example.com/base/duo-redirect-connector.html?client=mobile&deeplinkScheme=https',
        );
        expect(buildDuoRedirectUri('https://vault.example.com', 'unknown')).toBe(
            'https://vault.example.com/duo-redirect-connector.html?client=web',
        );
        expect(buildDuoRedirectUri('https://vault.example.com', 'connector')).toBe(
            'https://vault.example.com/duo-redirect-connector.html?client=web',
        );
        expect(() => buildDuoRedirectUri('http://vault.example.com', 'web')).toThrow('HTTPS');
    });

    it('generates high-entropy URL-safe state and nonce values', () => {
        const state = generateDuoOpaqueValue();
        const nonce = generateDuoOpaqueValue();
        expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(state).not.toBe(nonce);
    });
});

describe('Duo Universal Prompt protocol', () => {
    it('creates an upstream-compatible HS512 authorization request with state and nonce', async () => {
        const state = generateDuoOpaqueValue();
        const nonce = generateDuoOpaqueValue();
        const redirectUri = 'https://vault.example.com/duo-redirect-connector.html?client=web';
        const authorizationUrl = await createDuoAuthorizationUrl(config, {
            username: 'user@example.com', state, nonce, redirectUri,
        }, now);
        const url = new URL(authorizationUrl);
        expect(url.origin + url.pathname).toBe(`https://${config.host}/oauth/v1/authorize`);
        expect(url.searchParams.get('response_type')).toBe('code');
        expect(url.searchParams.get('client_id')).toBe(config.clientId);
        expect(url.searchParams.get('redirect_uri')).toBe(redirectUri);
        expect(url.searchParams.get('scope')).toBe('openid');

        const requestJwt = url.searchParams.get('request')!;
        const { payload, protectedHeader } = await jwtVerify(
            requestJwt,
            new TextEncoder().encode(config.clientSecret),
            { algorithms: ['HS512'], audience: `https://${config.host}`, issuer: config.clientId },
        );
        expect(protectedHeader.alg).toBe('HS512');
        expect(payload).toMatchObject({
            response_type: 'code', scope: 'openid', client_id: config.clientId,
            redirect_uri: redirectUri, state, nonce, duo_uname: 'user@example.com',
        });
        expect(payload).not.toHaveProperty('code_challenge');
        // Bitwarden clients consume the callback's `code` parameter. Omitting
        // use_duo_code_attribute preserves the upstream C# SDK's false default.
        expect(payload).not.toHaveProperty('use_duo_code_attribute');
    });

    it('performs a bounded non-redirecting health check with a signed client assertion', async () => {
        let redirectMode: RequestInit['redirect'];
        const healthy = await checkDuoHealth(config, {
            now,
            fetch: async (input, init) => {
                expect(input.toString()).toBe(`https://${config.host}/oauth/v1/health_check`);
                redirectMode = init?.redirect;
                const form = new URLSearchParams(String(init?.body));
                const assertion = form.get('client_assertion')!;
                const { payload } = await jwtVerify(assertion, new TextEncoder().encode(config.clientSecret), {
                    issuer: config.clientId,
                    audience: `https://${config.host}/oauth/v1/health_check`,
                    algorithms: ['HS512'],
                });
                expect(payload.sub).toBe(config.clientId);
                expect(payload.jti).toMatch(/^[A-Za-z0-9_-]{43}$/);
                return jsonResponse({ stat: 'OK', response: { timestamp: 1 } });
            },
        });
        expect(healthy).toBe(true);
        expect(redirectMode).toBe('manual');
    });

    it('exchanges code and verifies signature, issuer, audience, username, nonce and allow result', async () => {
        const nonce = generateDuoOpaqueValue();
        const tokenEndpoint = `https://${config.host}/oauth/v1/token`;
        const idToken = await new SignJWT({
            preferred_username: 'USER@example.com',
            nonce,
            auth_result: { result: 'allow', status: 'allow' },
        })
            .setProtectedHeader({ alg: 'HS512' })
            .setIssuer(tokenEndpoint)
            .setAudience(config.clientId)
            .setSubject('USER@example.com')
            .setIssuedAt(Math.floor(now.getTime() / 1000))
            .setExpirationTime(Math.floor(now.getTime() / 1000) + 300)
            .sign(new TextEncoder().encode(config.clientSecret));

        const result = await exchangeDuoAuthorizationCode(config, {
            code: 'duo-code', username: 'user@example.com', nonce,
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=web',
        }, {
            now,
            fetch: async (_input, init) => {
                const form = new URLSearchParams(String(init?.body));
                expect(form.get('grant_type')).toBe('authorization_code');
                expect(form.get('code')).toBe('duo-code');
                expect(decodeJwt(form.get('client_assertion')!).sub).toBe(config.clientId);
                return jsonResponse({ id_token: idToken, access_token: 'unused', expires_in: 300, token_type: 'Bearer' });
            },
        });
        expect(result.auth_result.result).toBe('allow');
        expect(result.preferred_username).toBe('USER@example.com');
    });

    it('fails closed for redirects, oversized bodies and mismatched authentication results', async () => {
        await expect(checkDuoHealth(config, {
            fetch: async () => new Response(null, { status: 302, headers: { location: 'https://evil.example' } }),
        })).rejects.toThrow('HTTP 302');
        await expect(checkDuoHealth(config, {
            maxResponseBytes: 8,
            fetch: async () => jsonResponse({ stat: 'OK' }),
        })).rejects.toThrow('exceeds');

        const nonce = generateDuoOpaqueValue();
        const idToken = await new SignJWT({
            preferred_username: 'attacker@example.com', nonce,
            auth_result: { result: 'allow' },
        })
            .setProtectedHeader({ alg: 'HS512' })
            .setIssuer(`https://${config.host}/oauth/v1/token`)
            .setAudience(config.clientId)
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(new TextEncoder().encode(config.clientSecret));
        await expect(exchangeDuoAuthorizationCode(config, {
            code: 'duo-code', username: 'user@example.com', nonce,
            redirectUri: 'https://vault.example.com/duo-redirect-connector.html?client=web',
        }, {
            fetch: async () => jsonResponse({
                id_token: idToken, access_token: 'unused', expires_in: 300, token_type: 'Bearer',
            }),
        })).rejects.toThrow('invalid');
    });
});
