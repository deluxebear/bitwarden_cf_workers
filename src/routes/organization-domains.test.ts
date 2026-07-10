import { describe, expect, it, vi } from 'vitest';

import { BadRequestError } from '../middleware/error';

import {
    dnsTxtRecordsContainToken,
    extractDnsTxtRecords,
    normalizeOrganizationOidcConfig,
    normalizeSsoData,
    resolveDnsTxtRecords,
    validateOrganizationOidcEnable,
    verifyOrganizationDomainDns,
} from './organization-domains';

describe('organization domain DNS TXT verification helpers', () => {
    it('extracts TXT records from DNS-over-HTTPS JSON responses', () => {
        const records = extractDnsTxtRecords({
            Answer: [
                { type: 1, data: '192.0.2.1' },
                { type: 16, data: '"bw=abc123"' },
                { type: 16, data: '"v=spf1 include:example.com ~all"' },
            ],
        });

        expect(records).toEqual(['bw=abc123', 'v=spf1 include:example.com ~all']);
    });

    it('joins split TXT string chunks before comparing', () => {
        const records = extractDnsTxtRecords({
            Answer: [{ type: 16, data: '"bw=abc" "123"' }],
        });

        expect(records).toEqual(['bw=abc123']);
        expect(dnsTxtRecordsContainToken(records, 'bw=abc123')).toBe(true);
    });

    it('requires an exact TXT record match', () => {
        expect(dnsTxtRecordsContainToken(['prefix bw=abc123', 'bw=abc123-extra'], 'bw=abc123')).toBe(false);
        expect(dnsTxtRecordsContainToken(['bw=abc123'], 'bw=abc123')).toBe(true);
    });

    it('queries TXT records through DNS-over-HTTPS', async () => {
        const fetcher = vi.fn(
            async () =>
                new Response(JSON.stringify({ Answer: [{ type: 16, data: '"bw=abc123"' }] }), {
                    status: 200,
                }),
        ) as typeof fetch;

        const records = await resolveDnsTxtRecords('example.com', fetcher, 'https://resolver.example/dns-query');

        expect(records).toEqual(['bw=abc123']);
        expect(fetcher).toHaveBeenCalledWith('https://resolver.example/dns-query?name=example.com&type=TXT', {
            headers: { accept: 'application/dns-json' },
        });
    });

    it('verifies a domain when its exact TXT token exists', async () => {
        const fetcher = vi.fn(
            async () =>
                new Response(JSON.stringify({ Answer: [{ type: 16, data: '"bw=abc123"' }] }), {
                    status: 200,
                }),
        ) as typeof fetch;

        await expect(verifyOrganizationDomainDns(
            { domainName: 'example.com', txt: 'bw=abc123' },
            fetcher,
            'https://resolver.example/dns-query',
        )).resolves.toBe(true);
    });

    it('throws a bad request when the DNS resolver fails', async () => {
        const fetcher = vi.fn(async () => new Response(null, { status: 502 })) as typeof fetch;

        await expect(resolveDnsTxtRecords('example.com', fetcher, 'https://resolver.example/dns-query')).rejects.toBeInstanceOf(
            BadRequestError,
        );
    });

    it('throws a bad request when the DNS resolver cannot be reached', async () => {
        const fetcher = vi.fn(async () => {
            throw new Error('network unavailable');
        }) as typeof fetch;

        await expect(resolveDnsTxtRecords('example.com', fetcher, 'https://resolver.example/dns-query')).rejects.toBeInstanceOf(
            BadRequestError,
        );
    });

    it('throws a bad request when the DNS resolver response is not JSON', async () => {
        const fetcher = vi.fn(async () => new Response('not json', { status: 200 })) as typeof fetch;

        await expect(resolveDnsTxtRecords('example.com', fetcher, 'https://resolver.example/dns-query')).rejects.toBeInstanceOf(
            BadRequestError,
        );
    });
});

describe('organization OIDC configuration', () => {
    const redirectUri = 'https://vault.example.com/oidc-signin';

    it('normalizes legacy authority/clientId fields and preserves a secret binding reference', () => {
        const config = normalizeOrganizationOidcConfig({
            data: {
                authority: 'https://ID.Example.com/tenant/',
                clientId: 'web-vault',
                clientSecretEnv: 'SSO_OIDC_ACME_SECRET',
                claimMapping: { email: ['email', 'preferred_username'] },
            },
        }, redirectUri);

        expect(config).toEqual({
            issuer: 'https://id.example.com/tenant',
            clientId: 'web-vault',
            clientSecretEnv: 'SSO_OIDC_ACME_SECRET',
            redirectUri,
            claimMapping: { email: ['email', 'preferred_username'] },
        });
    });

    it('never retains plaintext clientSecret fields in stored or returned data', () => {
        expect(normalizeSsoData({
            clientSecret: 'top-secret',
            nested: { Client_Secret: 'nested-secret', keep: true },
            clientSecretEnv: 'SSO_OIDC_ACME_SECRET',
        })).toMatchObject({
            nested: { keep: true },
            clientSecretEnv: 'SSO_OIDC_ACME_SECRET',
        });
        expect(JSON.stringify(normalizeSsoData({ clientSecret: 'top-secret' }))).not.toContain('top-secret');

        expect(() => normalizeOrganizationOidcConfig({
            data: { clientSecret: 'must-not-be-persisted' },
        }, redirectUri)).toThrow('Worker secret binding reference');
    });

    it('rejects arbitrary redirect URIs and non-SSO secret binding names', () => {
        expect(() => normalizeOrganizationOidcConfig({
            data: { redirectUri: 'https://evil.example.com/callback' },
        }, redirectUri)).toThrow('must match');

        expect(() => normalizeOrganizationOidcConfig({
            data: { clientSecretEnv: 'JWT_SECRET' },
        }, redirectUri)).toThrow('SSO_OIDC_*');
    });

    it('requires a present secret binding and valid discovery before enabling', async () => {
        const config = normalizeOrganizationOidcConfig({
            data: {
                authority: 'https://id.example.com/tenant',
                clientId: 'web-vault',
                clientSecretEnv: 'SSO_OIDC_ACME_SECRET',
            },
        }, redirectUri);
        const discovery = {
            issuer: config.issuer,
            authorization_endpoint: 'https://id.example.com/authorize',
            token_endpoint: 'https://id.example.com/token',
            jwks_uri: 'https://id.example.com/jwks',
        };
        const fetcher = vi.fn(async () => new Response(JSON.stringify(discovery), {
            headers: { 'content-type': 'application/json' },
        })) as typeof fetch;

        await expect(validateOrganizationOidcEnable(
            config,
            (name) => name === 'SSO_OIDC_ACME_SECRET' ? 'bound-secret' : undefined,
            fetcher,
        )).resolves.toBeUndefined();
        expect(fetcher).toHaveBeenCalledOnce();

        await expect(validateOrganizationOidcEnable(config, () => undefined, fetcher)).rejects.toThrow(
            'secret binding is missing',
        );
        await expect(validateOrganizationOidcEnable(
            config,
            () => 'bound-secret',
            async () => new Response(null, { status: 503 }),
        )).rejects.toThrow('discovery validation failed');
    });
});
