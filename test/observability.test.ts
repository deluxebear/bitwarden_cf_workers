import { SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('health and deployment metadata endpoints', () => {
    it('serves lightweight health without exposing bindings', async () => {
        const response = await SELF.fetch('https://example.com/healthz');
        expect(response.status).toBe(200);
        expect(response.headers.get('X-Request-Id')).toBeTruthy();
        await expect(response.json()).resolves.toEqual({ status: 'ok' });
    });

    it('checks D1, KV, R2 and Durable Objects without resource identifiers', async () => {
        const response = await SELF.fetch('https://example.com/healthz/extended', {
            headers: { Authorization: 'Bearer integration-health-check-token' },
        });
        expect(response.status).toBe(200);
        const text = await response.text();
        const body = JSON.parse(text);
        expect(body.status).toBe('ok');
        expect(Object.keys(body.checks)).toEqual(['d1', 'kv', 'r2', 'durableObject']);
        expect(Object.values(body.checks).every((check: unknown) => (
            typeof check === 'object' && check !== null && (check as { ok: boolean }).ok
        ))).toBe(true);
        expect(text).not.toContain('bitwarden-db');
        expect(text).not.toContain('__healthcheck__');
    });

    it('hides the extended health check without its service token', async () => {
        const response = await SELF.fetch('https://example.com/healthz/extended');
        expect(response.status).toBe(404);
    });

    it('uses a safe version fallback when deployment metadata is unavailable', async () => {
        const response = await SELF.fetch('https://example.com/version');
        expect(response.status).toBe(200);
        const body = await response.json<{ version: string; deploymentId: string | null; deployedAt: string | null }>();
        expect(typeof body.version).toBe('string');
        expect(body.version.length).toBeGreaterThan(0);
        expect(body).toHaveProperty('deploymentId');
        expect(body).toHaveProperty('deployedAt');
    });
});
