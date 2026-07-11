import { describe, expect, it } from 'vitest';
import config from './config';

describe('config capability declarations', () => {
    it('safely disables incomplete flows and declares both cipher key flag names', async () => {
        const response = await config.request('http://localhost/', undefined, {});
        const body = await response.json() as { featureStates: Record<string, boolean> };

        expect(body.featureStates).toMatchObject({
            'cxp-export-mobile': false,
            'cxp-import-mobile': false,
            'pm-20558-migrate-myvault-to-myitems': false,
            'pm-23995-no-logout-on-kdf-change': false,
            'cipher-key-encryption': true,
            enableCipherKeyEncryption: true,
        });
    });
});
