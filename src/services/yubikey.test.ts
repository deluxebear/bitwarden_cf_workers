import { describe, expect, it } from 'vitest';

import {
    buildYubicoValidationRequest,
    isYubiKeyPublicId,
    parseYubiKeyOtp,
    parseYubicoResponse,
    verifyYubicoOtp,
} from './yubikey';

const SECRET = 'mG5be6ZJU1qBGz24yPh/ESM3UdU=';
const OTP = 'cccccckdvvulethkhtvkrtbeukiettvfceekurncllcj';
const NONCE = '0123456789abcdef';

async function signResponse(fields: Record<string, string>): Promise<string> {
    const canonical = Object.keys(fields).sort().map((key) => `${key}=${fields[key]}`).join('&');
    const secret = Uint8Array.from(atob(SECRET), (character) => character.charCodeAt(0));
    const key = await crypto.subtle.importKey(
        'raw', secret, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign'],
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(canonical));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function responseBody(status: string, overrides: Record<string, string> = {}): Promise<string> {
    const fields = {
        status,
        t: '2026-07-10T00:00:00Z0000',
        nonce: NONCE,
        otp: OTP,
        sessioncounter: '12',
        sessionuse: '3',
        timestamp: '456',
        ...overrides,
    };
    const h = await signResponse(fields);
    return Object.entries({ h, ...fields }).map(([key, value]) => `${key}=${value}`).join('\r\n');
}

describe('YubiKey OTP parsing', () => {
    it('normalizes modhex and extracts the upstream-compatible 12 character public ID', () => {
        expect(parseYubiKeyOtp(`  ${OTP.toUpperCase()}  `)).toEqual({
            otp: OTP,
            publicId: 'cccccckdvvul',
        });
        expect(isYubiKeyPublicId('cccccckdvvul')).toBe(true);
    });

    it('rejects invalid length, alphabet and public IDs', () => {
        expect(parseYubiKeyOtp('c'.repeat(31))).toBeNull();
        expect(parseYubiKeyOtp('c'.repeat(49))).toBeNull();
        expect(parseYubiKeyOtp(`${'c'.repeat(43)}x`)).toBeNull();
        expect(isYubiKeyPublicId('short')).toBe(false);
    });
});

describe('Yubico validation protocol', () => {
    it('constructs a signed HTTPS GET request using the official HMAC test vector', async () => {
        const request = await buildYubicoValidationRequest(
            'vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft',
            { clientId: '1', secret: SECRET },
            'jrFwbaYFhn0HoxZIsd9LQ6w2ceU',
        );

        expect(request).not.toBeNull();
        const url = new URL(request!.url);
        expect(url.protocol).toBe('https:');
        expect(url.searchParams.get('h')).toBe('+ja8S3IjbX593/LAgTBixwPNGX4=');
        expect(url.searchParams.get('otp')).toBe('vvungrrdhvtklknvrtvuvbbkeidikkvgglrvdgrfcdft');
    });

    it('parses values containing equals signs and rejects duplicate fields', () => {
        expect(parseYubicoResponse('h=abc==\nstatus=OK\n')).toEqual({ h: 'abc==', status: 'OK' });
        expect(parseYubicoResponse('h=one\nh=two\nstatus=OK')).toBeNull();
    });

    it('accepts only a signed response matching both nonce and OTP', async () => {
        const fetchImpl = async () => new Response(await responseBody('OK'), { status: 200 });
        const result = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            fetchImpl,
            { nonce: NONCE },
        );

        expect(result).toMatchObject({
            valid: true,
            kind: 'ok',
            publicId: 'cccccckdvvul',
            replayed: false,
            sessionCounter: 12,
            sessionUse: 3,
            tokenTimestamp: 456,
        });
    });

    it.each([
        ['REPLAYED_OTP', 'replayed_otp'],
        ['REPLAYED_REQUEST', 'replayed_request'],
        ['BAD_OTP', 'invalid_otp'],
        ['BACKEND_ERROR', 'provider_rejected'],
    ])('classifies provider status %s as %s', async (status, kind) => {
        const result = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async () => new Response(await responseBody(status)),
            { nonce: NONCE },
        );

        expect(result.kind).toBe(kind);
        expect(result.valid).toBe(false);
        expect(result.replayed).toBe(status.startsWith('REPLAYED_'));
    });

    it('fails closed for a bad signature or response binding mismatch', async () => {
        const badSignature = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async () => new Response(`${await responseBody('OK')}tampered`),
            { nonce: NONCE },
        );
        expect(badSignature.kind).toBe('invalid_response');

        const wrongNonceBody = await responseBody('OK', { nonce: 'fedcba9876543210' });
        const wrongNonce = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async () => new Response(wrongNonceBody),
            { nonce: NONCE },
        );
        expect(wrongNonce.kind).toBe('invalid_response');
    });

    it('fails closed on timeout, network errors, insecure endpoints and invalid OTPs', async () => {
        const timeout = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET, timeoutMs: 5 },
            () => new Promise<Response>(() => undefined),
            { nonce: NONCE },
        );
        expect(timeout.kind).toBe('timeout');

        const network = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async () => { throw new Error('offline'); },
            { nonce: NONCE },
        );
        expect(network.kind).toBe('network_error');

        const insecure = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET, validationUrl: 'http://example.test/verify' },
            async () => new Response('should not be called'),
            { nonce: NONCE },
        );
        expect(insecure.kind).toBe('configuration_error');

        const malformed = await verifyYubicoOtp(
            'not-an-otp',
            { clientId: '1', secret: SECRET },
            async () => new Response('should not be called'),
        );
        expect(malformed.kind).toBe('invalid_otp');
    });

    it('does not follow redirects and rejects an unbounded oversized response', async () => {
        let redirectMode: RequestInit['redirect'];
        const redirected = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async (_input, init) => {
                redirectMode = init?.redirect;
                return new Response(null, { status: 302, headers: { location: 'https://evil.example' } });
            },
            { nonce: NONCE },
        );
        expect(redirectMode).toBe('manual');
        expect(redirected.kind).toBe('provider_rejected');

        const oversized = await verifyYubicoOtp(
            OTP,
            { clientId: '1', secret: SECRET },
            async () => new Response('x'.repeat(16 * 1024 + 1)),
            { nonce: NONCE },
        );
        expect(oversized.kind).toBe('invalid_response');
    });
});
