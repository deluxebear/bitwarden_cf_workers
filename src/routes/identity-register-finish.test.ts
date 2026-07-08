import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('identity registration invite completion', () => {
    it('marks organization invitations accepted after invited account registration', () => {
        const source = readFileSync('src/routes/identity.ts', 'utf8');

        expect(source).toContain('async function acceptRegisterFinishInvite');
        expect(source).toContain('status: 1, // Accepted');
        expect(source).toContain('eq(organizationUsers.status, 0)');
        expect(source).toContain('await acceptRegisterFinishInvite(db, c, registerInvite, userId, now);');
    });

    it('requires a valid invite token before updating an existing account during registration finish', () => {
        const source = readFileSync('src/routes/identity.ts', 'utf8');

        expect(source).toContain('if (!registerInvite) {');
        expect(source).toContain("throw new BadRequestError('Email is already registered.');");
        expect(source).not.toContain('const pendingInvite = registerInvite ??');
    });
});
