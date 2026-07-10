import { describe, expect, it } from 'vitest';

import type { StoredDuoConfig } from '../services/duo-storage';
import { buildOrganizationDuoProvider, toOrganizationDuoResponse } from './organizations';

const SECRET = 'o'.repeat(40);
const config: StoredDuoConfig = {
    id: 'organization:org-1',
    organizationId: 'org-1',
    clientId: 'O'.repeat(20),
    clientSecret: SECRET,
    clientSecretPrefix: SECRET.slice(0, 6),
    host: 'api-enterprise.duosecurity.com',
    keyVersion: 1,
    creationDate: '2026-07-10T00:00:00.000Z',
    revisionDate: '2026-07-10T00:00:00.000Z',
};

describe('organization Duo route serialization', () => {
    it('persists ConfigId, ClientId and Host but never a Duo secret', () => {
        const provider = buildOrganizationDuoProvider(config);
        expect(provider.metaData).toEqual({
            ConfigId: 'organization:org-1',
            ClientId: 'O'.repeat(20),
            Host: 'api-enterprise.duosecurity.com',
        });
        expect(JSON.stringify(provider)).not.toContain(SECRET);
        expect(JSON.stringify(provider)).not.toContain('ClientSecret');
    });

    it('builds the compatibility response from D1 and masks the secret prefix', () => {
        const providers = { '6': buildOrganizationDuoProvider(config) };
        expect(toOrganizationDuoResponse(providers, config)).toEqual({
            Enabled: true,
            Host: 'api-enterprise.duosecurity.com',
            ClientSecret: `${SECRET.slice(0, 6)}${'*'.repeat(34)}`,
            ClientId: 'O'.repeat(20),
            object: 'twoFactorDuo',
        });
    });

    it('does not report an enabled provider when its D1 config is unavailable', () => {
        const providers = { '6': buildOrganizationDuoProvider(config) };
        expect(toOrganizationDuoResponse(providers, null)).toMatchObject({
            Enabled: false,
            ClientSecret: null,
        });
    });
});
