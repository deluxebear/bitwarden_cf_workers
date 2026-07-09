import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('organization data ownership enforcement', () => {
    it('blocks personal folder writes while preserving deletion cleanup', () => {
        const source = readFileSync('src/routes/folders.ts', 'utf8');

        expect(source).toContain("import { assertPersonalVaultWriteAllowed } from '../services/policy-requirements';");
        expect(source.match(/await assertPersonalVaultWriteAllowed\(db, userId\);/g)?.length).toBe(3);
        expect(source).toContain("foldersRoute.delete('/:id'");
    });

    it('blocks personal cipher mutations but keeps organization transfer routes available', () => {
        const source = readFileSync('src/routes/ciphers.ts', 'utf8');

        expect(source).toContain('async function assertCipherPersonalVaultWriteAllowed');
        expect(source).toContain("ciphersRoute.put('/share', shareManyCiphersHandler);");
        expect(source).toContain("ciphersRoute.post('/:id/share', shareCipherHandler);");
        expect(source).toContain("ciphersRoute.delete('/:id'");
        expect(source.match(/await assertCipherPersonalVaultWriteAllowed\(db, userId,/g)?.length).toBeGreaterThanOrEqual(14);
    });

    it('exposes a reusable organization data ownership restriction check', () => {
        const source = readFileSync('src/services/policy-requirements.ts', 'utf8');

        expect(source).toContain('export async function isPersonalVaultWriteRestricted');
        expect(source).toContain('PolicyType.OrganizationDataOwnership');
    });
});
