import { describe, expect, it } from 'vitest';

import type { Bindings } from '../types';
import { getYubicoValidationConfig } from '../services/yubikey';
import {
    buildYubiKeyProvider,
    getYubiKeyOtps,
    validateYubiKeyRegistration,
} from './two-factor';

const SECRET = 'mG5be6ZJU1qBGz24yPh/ESM3UdU=';
const OTP_1 = 'cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj';
const OTP_2 = 'vvvvvvkdvvulethkhtvkrtbeukiettvfceekurncllcj';

async function sign(fields: Record<string, string>): Promise<string> {
    const canonical = Object.keys(fields).sort().map((key) => `${key}=${fields[key]}`).join('&');
    const rawSecret = Uint8Array.from(atob(SECRET), (character) => character.charCodeAt(0));
    const key = await crypto.subtle.importKey(
        'raw', rawSecret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonical));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function successfulYubicoResponse(input: string | URL | Request): Promise<Response> {
    const url = new URL(String(input));
    const fields = {
        status: 'OK',
        nonce: url.searchParams.get('nonce') ?? '',
        otp: url.searchParams.get('otp') ?? '',
    };
    return new Response(`h=${await sign(fields)}\r\n${Object.entries(fields)
        .map(([key, value]) => `${key}=${value}`).join('\r\n')}`);
}

describe('YubiKey two-factor route helpers', () => {
    const env = {
        YUBICO_CLIENT_ID: '1',
        YUBICO_SECRET: SECRET,
    } as Bindings;

    it('accepts at most five populated slots and rejects oversized arrays', () => {
        expect(getYubiKeyOtps({ key1: OTP_1, key2: '', Key3: OTP_2 })).toEqual([OTP_1, OTP_2]);
        expect(() => getYubiKeyOtps({ keys: Array(6).fill(OTP_1) }))
            .toThrow('A maximum of 5 YubiKeys is allowed.');
    });

    it('fails closed when Yubico credentials are missing or malformed', async () => {
        expect(getYubicoValidationConfig({ YUBICO_CLIENT_ID: 'not-a-number', YUBICO_SECRET: SECRET } as Bindings))
            .toBeNull();
        await expect(validateYubiKeyRegistration([OTP_1], {} as Bindings, successfulYubicoResponse))
            .rejects.toThrow('YubiKey validation is not configured.');
    });

    it('validates every OTP and returns only public IDs suitable for persistence', async () => {
        const requestedOtps: string[] = [];
        const publicIds = await validateYubiKeyRegistration([OTP_1, OTP_2], env, async (input) => {
            requestedOtps.push(new URL(String(input)).searchParams.get('otp') ?? '');
            return successfulYubicoResponse(input);
        });

        expect(requestedOtps).toEqual([OTP_1, OTP_2]);
        expect(publicIds).toEqual(['cccccckdvvul', 'vvvvvvkdvvul']);
        const persistedProvider = buildYubiKeyProvider(publicIds, true);
        expect(persistedProvider).toEqual({
            enabled: true,
            metaData: { Nfc: true, Key1: 'cccccckdvvul', Key2: 'vvvvvvkdvvul' },
        });
        expect(JSON.stringify(persistedProvider)).not.toContain(OTP_1);
        expect(JSON.stringify(persistedProvider)).not.toContain(OTP_2);
    });

    it('rejects duplicate physical keys and provider validation failures', async () => {
        await expect(validateYubiKeyRegistration([OTP_1, OTP_1], env, successfulYubicoResponse))
            .rejects.toThrow('Each YubiKey must be unique.');
        await expect(validateYubiKeyRegistration(
            [OTP_1],
            env,
            async () => new Response('h=invalid\r\nstatus=BAD_OTP'),
        )).rejects.toThrow('Invalid YubiKey OTP.');
    });

    it('preserves only public IDs already registered on the account', async () => {
        const existing = new Set(['cccccckdvvul']);
        await expect(validateYubiKeyRegistration(
            ['cccccckdvvul', OTP_2], env, successfulYubicoResponse, existing,
        )).resolves.toEqual(['cccccckdvvul', 'vvvvvvkdvvul']);

        await expect(validateYubiKeyRegistration(
            ['vvvvvvkdvvul'], env, successfulYubicoResponse, existing,
        )).rejects.toThrow('does not match this account');
    });
});
