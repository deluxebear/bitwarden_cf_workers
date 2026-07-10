import { describe, expect, it } from 'vitest';
import { NotificationHub } from './notification-hub';

function createHub() {
    const values = new Map<string, unknown>();
    const transaction = async <T>(callback: (tx: {
        get<V>(key: string): Promise<V | undefined>;
        put(key: string, value: unknown): Promise<void>;
        delete(key: string): Promise<boolean>;
    }) => Promise<T>) => callback({
        get: async <V>(key: string) => values.get(key) as V | undefined,
        put: async (key, value) => { values.set(key, value); },
        delete: async (key) => values.delete(key),
    });
    const state = {
        getWebSockets: () => [],
        storage: { transaction },
    } as unknown as DurableObjectState;
    return new NotificationHub(state);
}

async function command(hub: NotificationHub, action: string, body: object) {
    const response = await hub.fetch(new Request(`https://do/web-push/${action}`, {
        method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    }));
    return await response.json() as Record<string, unknown>;
}

describe('NotificationHub Web Push fencing', () => {
    it('distinguishes a live lease from a completed delivery', async () => {
        const hub = createHub();
        const first = await command(hub, 'claim', { key: 'event:device', leaseSeconds: 30 });
        expect(first.status).toBe('claimed');
        const leased = await command(hub, 'claim', { key: 'event:device', leaseSeconds: 30 });
        expect(leased.status).toBe('leased');
        expect(leased.remainingSeconds).toBeGreaterThan(0);
        expect((await command(hub, 'complete', { key: 'event:device', token: first.token })).updated).toBe(true);
        expect((await command(hub, 'claim', { key: 'event:device' })).status).toBe('completed');
    });

    it('prevents an old lease token from completing or releasing a newer lease', async () => {
        const hub = createHub();
        const first = await command(hub, 'claim', { key: 'crash:device' });
        await command(hub, 'release', { key: 'crash:device', token: first.token });
        const second = await command(hub, 'claim', { key: 'crash:device' });
        expect((await command(hub, 'complete', { key: 'crash:device', token: first.token })).updated).toBe(false);
        expect((await command(hub, 'release', { key: 'crash:device', token: first.token })).updated).toBe(false);
        expect((await command(hub, 'claim', { key: 'crash:device' })).status).toBe('leased');
        expect((await command(hub, 'release', { key: 'crash:device', token: second.token })).updated).toBe(true);
    });
});
