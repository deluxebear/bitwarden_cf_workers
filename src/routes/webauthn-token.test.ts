import { describe, expect, it } from 'vitest';
import type { Bindings } from '../types';
import {
    getUserVerificationSecret,
    signWebAuthnToken,
    verifyWebAuthnToken,
} from './webauthn';

describe('WebAuthn login token helpers', () => {
    const env = { JWT_SECRET: 'test-secret' } as Bindings;

    it('round-trips options containing non-ASCII user display names', async () => {
        const options = {
            rp: { name: 'Bitwarden', id: 'vault.example.com' },
            user: {
                id: 'AQIDBA',
                name: 'user@example.com',
                displayName: '熊彦霖',
            },
            challenge: 'c29tZS1jaGFsbGVuZ2U',
            pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
            timeout: 60000,
            excludeCredentials: [],
            authenticatorSelection: {
                requireResidentKey: true,
                residentKey: 'required',
                userVerification: 'required',
            },
            attestation: 'none',
            extensions: {},
        };

        const token = await signWebAuthnToken(
            env,
            'WebAuthnCredentialCreateOptionsToken',
            0,
            options,
        );

        const verifiedOptions = await verifyWebAuthnToken(
            env,
            token,
            'WebAuthnCredentialCreateOptionsToken',
            0,
        );

        expect(verifiedOptions).toEqual(options);
    });

    it('accepts current and legacy user verification field names', () => {
        expect(getUserVerificationSecret({ masterPasswordHash: 'current' })).toBe('current');
        expect(getUserVerificationSecret({ secret: 'legacy' })).toBe('legacy');
        expect(getUserVerificationSecret(null)).toBeUndefined();
    });
});
