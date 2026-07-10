import { describe, expect, it } from 'vitest';

import type { StoredDuoConfig } from '../services/duo-storage';
import { TwoFactorProviderType } from '../types';
import { buildDuoProvider, toDuoResponse } from './two-factor';

const SECRET = 's'.repeat(40);
const config: StoredDuoConfig = {
    id: 'user:user-1',
    userId: 'user-1',
    clientId: 'D'.repeat(20),
    clientSecret: SECRET,
    clientSecretPrefix: SECRET.slice(0, 6),
    host: 'api-example.duosecurity.com',
    keyVersion: 1,
    creationDate: '2026-07-10T00:00:00.000Z',
    revisionDate: '2026-07-10T00:00:00.000Z',
};

describe('personal Duo route serialization', () => {
    it('persists only a non-sensitive config reference in provider JSON', () => {
        const provider = buildDuoProvider(config);
        expect(provider).toEqual({
            enabled: true,
            metaData: {
                ConfigId: 'user:user-1',
                ClientId: 'D'.repeat(20),
                Host: 'api-example.duosecurity.com',
            },
        });
        expect(JSON.stringify(provider)).not.toContain(SECRET);
        expect(JSON.stringify(provider)).not.toContain('ClientSecret');
    });

    it('returns the D1-backed values and masks all but the six-character prefix', () => {
        const providers = { [TwoFactorProviderType.Duo]: buildDuoProvider(config) };
        expect(toDuoResponse(providers, config)).toEqual({
            enabled: true,
            host: 'api-example.duosecurity.com',
            clientSecret: `${SECRET.slice(0, 6)}${'*'.repeat(34)}`,
            clientId: 'D'.repeat(20),
            object: 'twoFactorDuo',
        });
    });

    it('fails closed when provider metadata has no matching D1 configuration', () => {
        const providers = { [TwoFactorProviderType.Duo]: buildDuoProvider(config) };
        expect(toDuoResponse(providers, null)).toMatchObject({ enabled: false, clientSecret: null });
    });
});
