import { describe, expect, it } from 'vitest';
import { advertiseOrganizationCapability, serverCapabilities } from './server-capabilities';
import { toOrganizationResponse, toProfileOrganizationResponse } from '../models/organization-responses';

const disabledOrganizationCapabilities = [
    'keyConnector',
    'scim',
    'directory',
    'api',
    'secretsManager',
    'riskInsights',
    'automaticUserConfirmation',
    'phishingBlocker',
] as const;

describe('server capability declarations', () => {
    it('does not advertise unimplemented organization modules even when licensed', () => {
        for (const capability of disabledOrganizationCapabilities) {
            expect(serverCapabilities.organization[capability]).toBe(false);
            expect(advertiseOrganizationCapability(capability, true)).toBe(false);
        }
    });

    it('gates organization, plan and profile fields through the capability matrix', () => {
        const org = Object.fromEntries([
            'useKeyConnector', 'useScim', 'useDirectory', 'useApi', 'useSecretsManager',
            'useRiskInsights', 'useAutomaticUserConfirmation', 'usePhishingBlocker',
        ].map((key) => [key, true]));
        const response = toOrganizationResponse({ id: 'org', name: 'Org', billingEmail: 'a@example.com', ...org });
        const profile = toProfileOrganizationResponse(
            { id: 'org', name: 'Org', ...org },
            { id: 'member', userId: 'user', status: 2, type: 0, accessSecretsManager: true },
        );

        expect(response).toMatchObject({
            useKeyConnector: false, useScim: false, useDirectory: false, useApi: false,
            useSecretsManager: false, useRiskInsights: false,
            useAutomaticUserConfirmation: false, usePhishingBlocker: false,
            plan: { hasDirectory: false, hasApi: false, hasScim: false },
        });
        expect(profile).toMatchObject({
            useKeyConnector: false, useScim: false, useDirectory: false, useApi: false,
            useSecretsManager: false, accessSecretsManager: false, useRiskInsights: false,
            useAutomaticUserConfirmation: false, usePhishingBlocker: false,
        });
    });
});
