import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const currentDirectory = dirname(fileURLToPath(import.meta.url));

describe('OIDC migration safety guards', () => {
    it('disables both camelCase and PascalCase legacy plaintext secrets', () => {
        const migration = readFileSync(resolve(currentDirectory, '../../drizzle/0020_sso_oidc_config.sql'), 'utf8');
        expect(migration).toContain("json_extract(`data`, '$.clientSecret')");
        expect(migration).toContain("json_extract(`data`, '$.ClientSecret')");
        expect(migration).toContain('SET `enabled` = 0');
    });

    it('fails closed for duplicate identifiers before creating the unique lower-case index', () => {
        const migration = readFileSync(resolve(currentDirectory, '../../drizzle/0021_oidc_login_runtime.sql'), 'utf8');
        const disableOffset = migration.indexOf('SET `enabled` = 0');
        const deduplicateOffset = migration.indexOf('rowid NOT IN');
        const indexOffset = migration.indexOf('CREATE UNIQUE INDEX `idx_organizations_identifier_lower`');
        expect(disableOffset).toBeGreaterThanOrEqual(0);
        expect(deduplicateOffset).toBeGreaterThan(disableOffset);
        expect(indexOffset).toBeGreaterThan(deduplicateOffset);
    });
});
