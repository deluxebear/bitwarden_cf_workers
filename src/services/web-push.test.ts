import { describe, expect, it } from 'vitest';
import { sendWebPush, type WebPushIdempotencyStore } from './web-push';

function b64url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('base64url');
}

async function fixture() {
    const subscriptionKeys = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    ) as CryptoKeyPair;
    const subscriptionPublic = new Uint8Array(await crypto.subtle.exportKey('raw', subscriptionKeys.publicKey) as ArrayBuffer);
    const vapidKeys = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'],
    ) as CryptoKeyPair;
    const vapid = await crypto.subtle.exportKey('jwk', vapidKeys.privateKey);
    if (vapid instanceof ArrayBuffer) throw new Error('Expected a JWK export.');
    const publicBytes = Buffer.concat([
        Buffer.from([4]), Buffer.from(vapid.x!, 'base64url'), Buffer.from(vapid.y!, 'base64url'),
    ]);
    return {
        subscription: {
            endpoint: 'https://push.example.test/send/subscription-id',
            p256dh: b64url(subscriptionPublic),
            auth: b64url(crypto.getRandomValues(new Uint8Array(16))),
        },
        config: {
            publicKey: b64url(publicBytes),
            privateKey: vapid.d!,
            subject: 'mailto:admin@example.test',
        },
    };
}

class MemoryIdempotency implements WebPushIdempotencyStore {
    readonly keys = new Set<string>();
    async has(key: string) { return this.keys.has(key); }
    async put(key: string) { this.keys.add(key); }
}

describe('Web Push delivery', () => {
    it('sends an RFC8291 aes128gcm request with a VAPID JWT and bounded payload', async () => {
        const { subscription, config } = await fixture();
        let request: Request | undefined;
        const result = await sendWebPush(subscription, { Type: 5 }, 'event-success', config, {
            fetch: async (input, init) => {
                request = new Request(input, init);
                return new Response(null, { status: 201 });
            },
        });
        expect(result).toEqual({ status: 'delivered', statusCode: 201, attempts: 1 });
        expect(request!.redirect).toBe('manual');
        expect(request!.headers.get('content-encoding')).toBe('aes128gcm');
        expect(request!.headers.get('authorization')).toMatch(/^vapid t=[^.]+\.[^.]+\.[^,]+, k=/);
        const encrypted = new Uint8Array(await request!.arrayBuffer());
        expect(encrypted.byteLength).toBeGreaterThan(16 + 4 + 1 + 65 + 16);
        expect(new DataView(encrypted.buffer).getUint32(16)).toBe(4096);
        expect(encrypted[20]).toBe(65);
    });

    it('cleans up expired subscriptions without retrying', async () => {
        const { subscription, config } = await fixture();
        let calls = 0;
        const result = await sendWebPush(subscription, {}, 'event-expired', config, {
            fetch: async () => { calls++; return new Response(null, { status: 410 }); },
        });
        expect(result).toEqual({ status: 'expired', statusCode: 410, attempts: 1 });
        expect(calls).toBe(1);
    });

    it.each([429, 500, 503])('classifies HTTP %s as retryable after a limited retry', async (status) => {
        const { subscription, config } = await fixture();
        let calls = 0;
        const result = await sendWebPush(subscription, {}, `event-${status}`, config, {
            fetch: async () => { calls++; return new Response(null, { status }); },
        });
        expect(result).toEqual({ status: 'retryable', statusCode: status, attempts: 2 });
        expect(calls).toBe(2);
    });

    it('returns a bounded Retry-After hint for queue scheduling', async () => {
        const { subscription, config } = await fixture();
        const result = await sendWebPush(subscription, {}, 'event-rate-limit', config, {
            maxAttempts: 1,
            fetch: async () => new Response(null, { status: 429, headers: { 'Retry-After': '7200' } }),
        });
        expect(result.retryAfterSeconds).toBe(3600);
    });

    it('bounds network timeouts and classifies them as retryable', async () => {
        const { subscription, config } = await fixture();
        let calls = 0;
        const result = await sendWebPush(subscription, {}, 'event-timeout', config, {
            timeoutMs: 5,
            fetch: async (_input, init) => {
                calls++;
                return new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
                });
            },
        });
        expect(result).toEqual({ status: 'retryable', statusCode: undefined, attempts: 2 });
        expect(calls).toBe(2);
    });

    it('suppresses a successfully delivered duplicate event for the same endpoint', async () => {
        const { subscription, config } = await fixture();
        const idempotency = new MemoryIdempotency();
        let calls = 0;
        const options = {
            idempotency,
            fetch: async () => { calls++; return new Response(null, { status: 201 }); },
        };
        expect((await sendWebPush(subscription, {}, 'same-event', config, options)).status).toBe('delivered');
        expect((await sendWebPush(subscription, {}, 'same-event', config, options)).status).toBe('duplicate');
        expect(calls).toBe(1);
    });

    it('rejects insecure endpoints and oversized payloads before fetch', async () => {
        const { subscription, config } = await fixture();
        await expect(sendWebPush({ ...subscription, endpoint: 'http://push.example.test' }, {}, 'event', config))
            .rejects.toThrow('HTTPS');
        await expect(sendWebPush({ ...subscription, endpoint: 'https://127.0.0.1/push' }, {}, 'event', config))
            .rejects.toThrow('HTTPS');
        await expect(sendWebPush(subscription, { body: 'x'.repeat(4_000) }, 'event', config))
            .rejects.toThrow('3072');
    });
});
