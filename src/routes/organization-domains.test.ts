import { describe, expect, it, vi } from 'vitest';

import { BadRequestError } from '../middleware/error';

import { dnsTxtRecordsContainToken, extractDnsTxtRecords, resolveDnsTxtRecords } from './organization-domains';

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
