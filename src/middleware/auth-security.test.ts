import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { signJwtClaims, verifyJwt } from './auth';

describe('authentication security contract', () => {
    it('rejects a token whose signature has been changed', async () => {
        const token = await signJwtClaims({ purpose: 'test' }, 'test-secret', 60);
        const parts = token.split('.');
        const last = parts[2].endsWith('A') ? 'B' : 'A';
        parts[2] = `${parts[2].slice(0, -1)}${last}`;

        await expect(verifyJwt(parts.join('.'), 'test-secret')).resolves.toBeNull();
    });

    it('does not emit authenticated user identifiers in middleware logs', () => {
        const source = readFileSync('src/middleware/auth.ts', 'utf8');
        expect(source).not.toContain('payload.email} (${payload.sub}');
        expect(source).toContain('constantTimeEqual(signature, expectedSignature)');
    });
});
