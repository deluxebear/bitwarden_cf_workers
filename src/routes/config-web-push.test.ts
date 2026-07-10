import { describe, expect, it } from 'vitest';
import { getWebPushServerConfig } from './config';
import type { Bindings } from '../types';

describe('server Web Push capability', () => {
    it('advertises Web Push only when the complete VAPID configuration exists', () => {
        expect(getWebPushServerConfig({
            WEB_PUSH_VAPID_PUBLIC_KEY: 'public-key',
            WEB_PUSH_VAPID_PRIVATE_KEY: 'private-key',
            WEB_PUSH_VAPID_SUBJECT: 'mailto:admin@example.com',
        } as Bindings)).toEqual({ pushTechnology: 1, vapidPublicKey: 'public-key' });

        expect(getWebPushServerConfig({
            WEB_PUSH_VAPID_PUBLIC_KEY: 'public-key',
        } as Bindings)).toEqual({ pushTechnology: 0, vapidPublicKey: null });
    });
});
