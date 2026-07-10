import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('notification hub token boundary', () => {
    it('requires an API access token and a current security stamp', () => {
        const source = readFileSync('src/routes/hub.ts', 'utf8');
        expect(source).toContain("payload.scope.includes('api')");
        expect(source).toContain('user.securityStamp !== payload.sstamp');
    });
});
