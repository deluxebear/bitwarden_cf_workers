import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

describe('durable Web Push retry and idempotency contract', () => {
    const service = readFileSync('./src/services/push-notification.ts', 'utf8');
    const hub = readFileSync('./src/durable-objects/notification-hub.ts', 'utf8');

    it('persists first retry and consumes queue attempts one upstream request at a time', () => {
        expect(service).toContain('WEB_PUSH_QUEUE?: Queue<WebPushQueueMessage>');
        expect(service).toContain('await queue.send(');
        expect(service).toContain('export async function handleWebPushQueue');
        expect(service).toContain('{ maxAttempts: 1 }');
        expect(service).toContain('message.retry({ delaySeconds: Math.max(delay(), result.retryAfterSeconds ?? 0) })');
    });

    it('uses the Durable Object as the atomic claim authority', () => {
        expect(service).toContain('const claim = await claimDelivery(env, claimKey)');
        expect(service).not.toContain('createCacheIdempotencyStore');
        expect(hub).toContain("action === 'claim'");
        expect(hub).toContain('this.state.storage.transaction');
        expect(hub).toContain("current.token !== token");
    });

    it('checks Hub delivery responses and CAS-cleans expired subscriptions', () => {
        expect(service).toContain('if (!response.ok) throw new Error(`NotificationHub rejected notification: HTTP ${response.status}`)');
        expect(service).toContain('eq(devices.webPushAuth, body.serializedSubscription)');
    });

    it('does not release a retry lease until enqueue succeeds and rethrows enqueue failures', () => {
        const sendAt = service.indexOf('await queue.send(');
        const releaseAt = service.indexOf("await finishDelivery(env, 'release', claimKey", sendAt);
        expect(sendAt).toBeGreaterThan(0);
        expect(releaseAt).toBeGreaterThan(sendAt);
        expect(service).toContain('if (enqueueing) throw error');
        expect(service).toContain("claim.status === 'leased'");
        expect(service).toContain('message.retry({ delaySeconds: claim.remainingSeconds })');
    });
});
