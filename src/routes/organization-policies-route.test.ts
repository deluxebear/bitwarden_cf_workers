import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { getSavePolicyRequest } from './organizations';

describe('organization policies route compatibility', () => {
    it('mounts full organization routes on both API and upstream-style organization paths', () => {
        const source = readFileSync('src/index.ts', 'utf8');

        expect(source).toContain("app.route('/api/organizations', organizationsRoutes);");
        expect(source).toContain("app.route('/organizations', organizationsRoutes);");
    });

    it('returns policy status models from the admin-console policy list endpoint', () => {
        const source = readFileSync('src/routes/organizations.ts', 'utf8');

        expect(source).toContain('function getPolicyStatusList');
        expect(source).toContain('ensureSingleOrgPolicyForVerifiedDomains(db, orgId)');
        expect(source).toContain('data: getPolicyStatusList(orgId, policyList)');
        expect(source).toContain('CanToggleState: canToggleState');
    });

    it('prevents disabling SingleOrg while verified claimed domains exist', () => {
        const source = readFileSync('src/routes/organizations.ts', 'utf8');

        expect(source).toContain('function assertSingleOrgCanBeDisabledForOrg');
        expect(source).toContain('Single organization policy is required while the organization has verified claimed domains.');
        expect(source).toContain('await assertSingleOrgCanBeDisabledForOrg(db, orgId, policyType, newEnabled);');
    });

    it('accepts the current web vault nested SavePolicyRequest body', () => {
        const request = getSavePolicyRequest({
            policy: {
                enabled: true,
                data: null,
            },
            metadata: null,
        } as any);

        expect(request).toEqual({
            enabled: true,
            data: null,
        });
    });

    it('keeps compatibility with flat legacy policy request bodies', () => {
        const request = getSavePolicyRequest({
            Enabled: true,
            Data: { DisableSend: true },
        });

        expect(request).toEqual({
            enabled: true,
            data: { DisableSend: true },
        });
    });
});
