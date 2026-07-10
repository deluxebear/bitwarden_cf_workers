import { describe, expect, it } from 'vitest';
import {
    createSsoPrevalidationToken,
    hasVerifiedOidcEmailClaim,
    validateClientRedirectUri,
    verifySsoPrevalidationToken,
} from './oidc-login';

describe('OIDC login request validation', () => {
    it('signs short-lived organization-bound prevalidation tokens', async () => {
        const token = await createSsoPrevalidationToken('org-1', 'test-secret-that-is-long-enough');
        await expect(verifySsoPrevalidationToken(token, 'test-secret-that-is-long-enough')).resolves.toBe('org-1');
        await expect(verifySsoPrevalidationToken(token, 'wrong-secret')).resolves.toBeNull();
    });

    it('binds each known client id to its exact registered callback', () => {
        expect(validateClientRedirectUri(
            'https://vault.example.com/sso-connector.html',
            'web',
            'https://vault.example.com',
        )).toBe(
            'https://vault.example.com/sso-connector.html',
        );
        expect(validateClientRedirectUri('http://localhost:8065', 'desktop')).toBe('http://localhost:8065/');
        expect(validateClientRedirectUri('bitwarden://sso-callback', 'mobile')).toBe('bitwarden://sso-callback');
        for (const callback of [
            'https://bitwarden.pw/sso-callback',
            'https://bitwarden.com/sso-callback',
            'https://bitwarden.eu/sso-callback',
            'https://bitwarden-gov.com/sso-callback',
        ]) {
            expect(validateClientRedirectUri(callback, 'mobile')).toBe(callback);
        }
        expect(() => validateClientRedirectUri('https://attacker.example/callback', 'web', 'https://vault.example.com')).toThrow();
        expect(() => validateClientRedirectUri('https://bitwarden.com/sso-callback?next=evil', 'mobile')).toThrow();
        expect(() => validateClientRedirectUri('bitwarden://sso-callback', 'unknown')).toThrow();
        expect(() => validateClientRedirectUri('javascript:alert(1)', 'desktop')).toThrow();
        expect(() => validateClientRedirectUri('https://user@example.com/callback', 'web', 'https://vault.example.com')).toThrow();
    });

    it('requires a boolean true verified-email claim, including custom mappings', () => {
        expect(hasVerifiedOidcEmailClaim({ email_verified: true }, {})).toBe(true);
        expect(hasVerifiedOidcEmailClaim({ email_verified: 'true' }, {})).toBe(false);
        expect(hasVerifiedOidcEmailClaim({ custom_verified: true }, { email_verified: ['custom_verified'] })).toBe(true);
        expect(hasVerifiedOidcEmailClaim({}, {})).toBe(false);
    });
});
