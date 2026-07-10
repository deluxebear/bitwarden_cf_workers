import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('debug middleware logging contract', () => {
    it('does not log authorization values or request bodies', () => {
        const source = readFileSync('src/middleware/debug.ts', 'utf8');

        expect(source).not.toContain("c.req.header('Authorization')");
        expect(source).not.toContain('c.req.raw.clone()');
        expect(source).not.toContain('Auth: Bearer');
        expect(source).not.toContain('Body (form)');
    });
});
