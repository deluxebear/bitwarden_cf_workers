import { env, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';

describe('Cloudflare Worker runtime', () => {
    it('serves the Hono app through the Worker fetch handler and can query D1', async () => {
        const response = await SELF.fetch('https://example.com/');

        expect(response.status).toBe(200);
        await expect(response.json()).resolves.toEqual({
            status: 'ok',
            service: 'bitwarden-workers',
        });

        const usersTable = await env.DB.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
        )
            .bind('users')
            .first<{ name: string }>();

        expect(usersTable).toEqual({ name: 'users' });
    });

    it('reads and writes attachment objects through the R2 binding', async () => {
        const key = 'integration-tests/r2-smoke.txt';
        const body = 'bitwarden-workers';

        await env.ATTACHMENTS.put(key, body, {
            httpMetadata: { contentType: 'text/plain' },
        });

        const object = await env.ATTACHMENTS.get(key);
        expect(object).not.toBeNull();
        expect(await object?.text()).toBe(body);
        expect(object?.httpMetadata?.contentType).toBe('text/plain');

        await env.ATTACHMENTS.delete(key);
        expect(await env.ATTACHMENTS.head(key)).toBeNull();
    });
});
