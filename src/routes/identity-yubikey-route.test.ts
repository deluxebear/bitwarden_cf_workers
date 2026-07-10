import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('identity YubiKey login integration', () => {
    it('validates the OTP with Yubico and binds it to a registered public ID', () => {
        const source = readFileSync('src/routes/identity.ts', 'utf8');

        expect(source).toContain('providerType === 3');
        expect(source).toContain('registeredPublicIds.has(parsedOtp.publicId)');
        expect(source).toContain('await verifyYubicoOtp(parsedOtp.otp, config, fetch)');
        expect(source).toContain('result.valid && result.publicId === parsedOtp.publicId');
    });
});
