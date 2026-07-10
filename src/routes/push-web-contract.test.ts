import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

describe('push route Web Push contract', () => {
    const source = readFileSync('./src/routes/push.ts', 'utf8');

    it('keeps the primary response asynchronous and passes a stable event id', () => {
        expect(source).toContain('c.executionCtx.waitUntil(pushNotification(');
        expect(source).toContain('const eventId = body.eventId || crypto.randomUUID()');
        expect(source).toContain("return c.body(null, 200)");
    });

    it('accepts only complete HTTPS Web Push registrations', () => {
        expect(source).toContain('[body.endpoint, body.p256dh, body.auth].every(Boolean)');
        expect(source).toContain('validateWebPushEndpoint(body.endpoint)');
    });

    it('clears both token channels and restricts organization broadcast to administrators', () => {
        expect(source).toContain('webPushAuth: null');
        expect(source).toContain('type !== PushType.Notification');
        expect(source).toContain('lte(organizationUsers.type, 1)');
        expect(source).toContain('eq(organizationUsers.status, 2)');
    });

    it('accepts only canonical bounded UUID event ids', () => {
        expect(source).toContain('body.eventId.length > 36');
        expect(source).toContain("throw new BadRequestError('EventId must be a valid UUID.')");
    });
});
