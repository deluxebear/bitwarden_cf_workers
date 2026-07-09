import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { parseSystemAdminEmails } from './system-admin';

describe('system admin route', () => {
    it('mounts server-level admin routes on admin paths', () => {
        const source = readFileSync('src/index.ts', 'utf8');

        expect(source).toContain("app.route('/api/admin', systemAdminRoutes);");
        expect(source).toContain("app.route('/admin', systemAdminRoutes);");
    });

    it('parses configured administrator emails case-insensitively', () => {
        expect(parseSystemAdminEmails(' Eric@Jetems.com, yan.xiong@mail.com ,, ')).toEqual(new Set([
            'eric@jetems.com',
            'yan.xiong@mail.com',
        ]));
    });

    it('uses the existing account deletion service for full server user removal', () => {
        const source = readFileSync('src/routes/system-admin.ts', 'utf8');

        expect(source).toContain("import { deleteUserAccountData } from '../services/claimed-accounts';");
        expect(source).toContain('await deleteUserAccountData(db, c.env, target.id);');
        expect(source).toContain("throw new BadRequestError('System administrators cannot delete their own account from this endpoint.');");
    });

    it('adds and revokes organization access without deleting the server account', () => {
        const source = readFileSync('src/routes/system-admin.ts', 'utf8');

        expect(source).toContain("import { validateUserCanJoinOrganization } from '../services/policy-requirements';");
        expect(source).toContain("adminRoutes.post('/users/:id/organizations/:orgId'");
        expect(source).toContain("adminRoutes.put('/users/:id/organizations/:orgId/revoke'");
        expect(source).toContain('status: ORG_USER_STATUS_ACCEPTED');
        expect(source).toContain('status: ORG_USER_STATUS_REVOKED');
    });
});
