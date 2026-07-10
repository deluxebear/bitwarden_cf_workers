import { describe, expect, it } from 'vitest';

import { getLoginBackoffMs, isLoginBackoffActive } from './login-security';
import { verifyPassword } from './crypto';

describe('login security helpers', () => {
    it('starts backoff after three failures and caps it at five minutes', () => {
        expect(getLoginBackoffMs(0)).toBe(0);
        expect(getLoginBackoffMs(2)).toBe(0);
        expect(getLoginBackoffMs(3)).toBe(1_000);
        expect(getLoginBackoffMs(4)).toBe(2_000);
        expect(getLoginBackoffMs(30)).toBe(300_000);
    });

    it('reports whether the current backoff window is active', () => {
        const lastFailure = '2026-07-10T00:00:00.000Z';
        const lastFailureMs = Date.parse(lastFailure);

        expect(isLoginBackoffActive(3, lastFailure, lastFailureMs + 999)).toBe(true);
        expect(isLoginBackoffActive(3, lastFailure, lastFailureMs + 1_000)).toBe(false);
    });

    it('does not lock an account when persisted state is incomplete or invalid', () => {
        expect(isLoginBackoffActive(3, null)).toBe(false);
        expect(isLoginBackoffActive(3, 'invalid-date')).toBe(false);
        expect(isLoginBackoffActive(2, '2026-07-10T00:00:00.000Z')).toBe(false);
    });

    it('verifies password hashes without relying on direct string equality', async () => {
        await expect(verifyPassword('stored-hash', 'stored-hash')).resolves.toBe(true);
        await expect(verifyPassword('stored-hash', 'different-hash')).resolves.toBe(false);
    });
});
