import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('ciphers route registration order', () => {
    it('registers bulk archive routes before the PUT /:id catch-all route', () => {
        const source = readFileSync('src/routes/ciphers.ts', 'utf8');

        const putById = source.indexOf("ciphersRoute.put('/:id',");
        const archiveMany = source.indexOf("ciphersRoute.put('/archive',");
        const unarchiveMany = source.indexOf("ciphersRoute.put('/unarchive',");

        expect(archiveMany).toBeGreaterThanOrEqual(0);
        expect(unarchiveMany).toBeGreaterThanOrEqual(0);
        expect(putById).toBeGreaterThanOrEqual(0);
        expect(archiveMany).toBeLessThan(putById);
        expect(unarchiveMany).toBeLessThan(putById);
    });
});
