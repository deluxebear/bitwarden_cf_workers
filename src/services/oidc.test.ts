import { describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';

import {
    createPkceChallenge,
    fetchOidcDiscovery,
    fetchOidcJwks,
    generateOidcNonce,
    generateOidcState,
    generatePkcePair,
    validateOidcIssuer,
    verifyOpaqueValue,
    validateSsoBaseUrl,
    verifyOidcIdToken,
} from './oidc';

const discovery = {
    issuer: 'https://id.example.com/tenant',
    authorization_endpoint: 'https://id.example.com/authorize',
    token_endpoint: 'https://id.example.com/token',
    jwks_uri: 'https://keys.example.com/jwks',
};

function jsonResponse(value: unknown, init: ResponseInit = {}): Response {
    const headers = new Headers(init.headers);
    headers.set('content-type', 'application/json');
    return new Response(JSON.stringify(value), { ...init, headers });
}

describe('OIDC issuer validation', () => {
    it('accepts a public HTTPS issuer and canonicalizes its trailing slash', () => {
        expect(validateOidcIssuer('https://ID.Example.com/tenant/').toString()).toBe('https://id.example.com/tenant');
    });

    it.each([
        'http://id.example.com',
        'file:///etc/passwd',
        'https://localhost',
        'https://service.local',
        'https://127.0.0.1',
        'https://10.0.0.1',
        'https://[::1]',
        'https://user:password@id.example.com',
        'https://id.example.com:8443',
        'https://id.example.com?redirect=https://evil.example',
    ])('rejects unsafe issuer %s', (issuer) => {
        expect(() => validateOidcIssuer(issuer)).toThrow();
    });
});

describe('SSO public origin validation', () => {
    it('accepts only a clean HTTPS origin by default', () => {
        expect(validateSsoBaseUrl('https://vault.example.com/')).toBe('https://vault.example.com');
        expect(() => validateSsoBaseUrl('http://vault.example.com')).toThrow('HTTPS');
        expect(() => validateSsoBaseUrl('https://user@vault.example.com')).toThrow('origin');
        expect(() => validateSsoBaseUrl('https://vault.example.com/sso')).toThrow('origin');
        expect(() => validateSsoBaseUrl('https://vault.example.com?next=evil')).toThrow('origin');
    });

    it('allows insecure localhost only behind the explicit development flag', () => {
        expect(() => validateSsoBaseUrl('http://localhost:8787')).toThrow('HTTPS');
        expect(validateSsoBaseUrl('http://localhost:8787', true)).toBe('http://localhost:8787');
    });
});

describe('OIDC metadata fetching', () => {
    it('fetches discovery with injected fetch and requires an exact issuer match', async () => {
        let requestedUrl = '';
        const result = await fetchOidcDiscovery(discovery.issuer, {
            fetch: async (input) => {
                requestedUrl = input.toString();
                return jsonResponse(discovery);
            },
        });

        expect(requestedUrl).toBe('https://id.example.com/tenant/.well-known/openid-configuration');
        expect(result.jwks_uri).toBe(discovery.jwks_uri);
    });

    it('fails closed for issuer mismatch and unsafe discovered endpoints', async () => {
        await expect(fetchOidcDiscovery(discovery.issuer, {
            fetch: async () => jsonResponse({ ...discovery, issuer: 'https://evil.example.com' }),
        })).rejects.toThrow('does not match');

        await expect(fetchOidcDiscovery(discovery.issuer, {
            fetch: async () => jsonResponse({ ...discovery, jwks_uri: 'http://127.0.0.1/jwks' }),
        })).rejects.toThrow('not a safe HTTPS URL');
    });

    it('rejects redirects, non-JSON and oversized responses', async () => {
        await expect(fetchOidcDiscovery(discovery.issuer, {
            fetch: async () => new Response(null, { status: 302, headers: { location: 'https://evil.example' } }),
        })).rejects.toThrow('HTTP 302');

        await expect(fetchOidcDiscovery(discovery.issuer, {
            fetch: async () => new Response('{}', { headers: { 'content-type': 'text/html' } }),
        })).rejects.toThrow('did not return JSON');

        await expect(fetchOidcDiscovery(discovery.issuer, {
            maxResponseBytes: 10,
            fetch: async () => jsonResponse(discovery),
        })).rejects.toThrow('exceeds');
    });

    it('fetches and validates a JWKS document', async () => {
        const jwks = await fetchOidcJwks(discovery.jwks_uri, {
            fetch: async () => jsonResponse({ keys: [{ kty: 'RSA', kid: 'key-1', n: 'abc', e: 'AQAB' }] }),
        });
        expect(jwks.keys).toHaveLength(1);

        await expect(fetchOidcJwks(discovery.jwks_uri, {
            fetch: async () => jsonResponse({ keys: [] }),
        })).rejects.toThrow('non-empty keys array');
    });
});

describe('OIDC state, nonce, and PKCE', () => {
    it('generates high-entropy URL-safe state and nonce values', () => {
        const state = generateOidcState();
        const nonce = generateOidcNonce();
        expect(state).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(state).not.toBe(nonce);
    });

    it('generates an RFC 7636 S256 pair', async () => {
        await expect(createPkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).resolves.toBe(
            'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
        );
        const pair = await generatePkcePair();
        expect(pair.method).toBe('S256');
        await expect(createPkceChallenge(pair.verifier)).resolves.toBe(pair.challenge);
    });

    it('compares returned state and nonce values without early-exit equality', () => {
        expect(verifyOpaqueValue('expected-state', 'expected-state')).toBe(true);
        expect(verifyOpaqueValue('expected-state', 'unexpected-state')).toBe(false);
        expect(verifyOpaqueValue('short', 'shorter')).toBe(false);
    });
});

describe('OIDC ID token verification', () => {
    it('verifies signature, issuer, audience and nonce and fails closed on mismatch', async () => {
        const { privateKey, publicKey } = await generateKeyPair('RS256');
        const exported = await exportJWK(publicKey);
        if (!exported.kty) throw new Error('Generated JWK is missing kty.');
        const jwk: JWK = { ...exported, kty: exported.kty, kid: 'key-1', alg: 'RS256', use: 'sig' };
        const token = await new SignJWT({ email: 'user@example.com', email_verified: true, nonce: 'expected-nonce' })
            .setProtectedHeader({ alg: 'RS256', kid: 'key-1' })
            .setIssuer(discovery.issuer)
            .setAudience('client-1')
            .setSubject('subject-1')
            .setIssuedAt()
            .setExpirationTime('5m')
            .sign(privateKey);

        await expect(verifyOidcIdToken(token, { keys: [jwk] }, {
            issuer: discovery.issuer,
            audience: 'client-1',
            nonce: 'expected-nonce',
        })).resolves.toEqual(expect.objectContaining({ sub: 'subject-1', email_verified: true }));
        await expect(verifyOidcIdToken(token, { keys: [jwk] }, {
            issuer: discovery.issuer,
            audience: 'wrong-client',
            nonce: 'expected-nonce',
        })).rejects.toThrow();
        await expect(verifyOidcIdToken(token, { keys: [jwk] }, {
            issuer: discovery.issuer,
            audience: 'client-1',
            nonce: 'wrong-nonce',
        })).rejects.toThrow('nonce');
    });
});
