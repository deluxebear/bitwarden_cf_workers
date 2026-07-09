import { describe, expect, it } from 'vitest';

import {
    emailMatchesVerifiedDomain,
    getEmailDomain,
    isOrganizationUserClaimedByDomains,
} from './claimed-accounts';

describe('claimed account helpers', () => {
    it('normalizes the email domain', () => {
        expect(getEmailDomain(' Alice@Example.COM ')).toBe('example.com');
        expect(getEmailDomain('invalid')).toBeNull();
        expect(getEmailDomain('@example.com')).toBeNull();
    });

    it('matches only exact verified domains', () => {
        const domains = new Set(['example.com']);

        expect(emailMatchesVerifiedDomain('alice@example.com', domains)).toBe(true);
        expect(emailMatchesVerifiedDomain('alice@sub.example.com', domains)).toBe(false);
        expect(emailMatchesVerifiedDomain('alice@other.com', domains)).toBe(false);
    });

    it('requires a confirmed organization user with a matching verified domain', () => {
        const domains = new Set(['example.com']);

        expect(isOrganizationUserClaimedByDomains({
            userId: 'user-1',
            status: 2,
            email: 'invited@other.com',
        }, domains, { email: 'active@example.com' })).toBe(true);

        expect(isOrganizationUserClaimedByDomains({
            userId: 'user-1',
            status: 1,
            email: 'active@example.com',
        }, domains)).toBe(false);

        expect(isOrganizationUserClaimedByDomains({
            userId: null,
            status: 2,
            email: 'active@example.com',
        }, domains)).toBe(false);
    });
});
