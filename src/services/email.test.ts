import { describe, expect, it, vi } from 'vitest';
import { sendOrganizationInvite } from './email';

describe('organization invite email', () => {
    it('sends an invitation through the configured Cloudflare Email binding', async () => {
        const send = vi.fn().mockResolvedValue(undefined);
        const inviteUrl = 'https://vault.example.com/#/accept-organization?token=test-token';

        await sendOrganizationInvite({
            EMAIL: { send } as unknown as SendEmail,
            EMAIL_MODE: 'cloudflare',
            EMAIL_FROM: 'Bitwarden <no-reply@example.com>',
        }, 'USER@example.com', 'Acme Org', inviteUrl);

        expect(send).toHaveBeenCalledWith(expect.objectContaining({
            to: 'user@example.com',
            from: { email: 'no-reply@example.com', name: 'Bitwarden' },
            subject: expect.stringContaining('Acme Org'),
            text: expect.stringContaining(inviteUrl),
            html: expect.stringContaining(inviteUrl),
        }));
    });
});
