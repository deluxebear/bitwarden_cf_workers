import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('organization policies route compatibility', () => {
    it('mounts full organization routes on both API and upstream-style organization paths', () => {
        const source = readFileSync('src/index.ts', 'utf8');

        expect(source).toContain("app.route('/api/organizations', organizationsRoutes);");
        expect(source).toContain("app.route('/organizations', organizationsRoutes);");
    });

    it('returns policy status models from the admin-console policy list endpoint', () => {
        const source = readFileSync('src/routes/organizations.ts', 'utf8');

        expect(source).toContain('function getPolicyStatusList');
        expect(source).toContain('data: getPolicyStatusList(orgId, policyList)');
        expect(source).toContain('CanToggleState: canToggleState');
    });
});
