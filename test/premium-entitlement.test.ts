import { env } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { canAccessPremium } from '../src/services/premium';

describe('organization premium entitlement', () => {
    beforeAll(async () => {
        const now = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, premium, security_stamp, account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, 0, ?, ?, ?, ?, ?)
            `).bind('premium-org-user', 'premium-org-user@example.com', 'premium-stamp', now, 'premium-api', now, now),
            env.DB.prepare(`
                INSERT INTO users
                    (id, email, premium, security_stamp, account_revision_date, api_key, creation_date, revision_date)
                VALUES (?, ?, 0, ?, ?, ?, ?, ?)
            `).bind('non-premium-org-user', 'non-premium-org-user@example.com', 'non-premium-stamp', now, 'non-premium-api', now, now),
            env.DB.prepare(`
                INSERT INTO organizations
                    (id, name, billing_email, plan_type, users_get_premium, enabled, creation_date, revision_date)
                VALUES (?, ?, ?, 0, 1, 1, ?, ?)
            `).bind('premium-org', 'Premium organization', 'premium-org-user@example.com', now, now),
            env.DB.prepare(`
                INSERT INTO organizations
                    (id, name, billing_email, plan_type, users_get_premium, enabled, creation_date, revision_date)
                VALUES (?, ?, ?, 2, 0, 1, ?, ?)
            `).bind('non-premium-org', 'Non-premium organization', 'non-premium-org-user@example.com', now, now),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 1, 2, ?, ?)
            `).bind(
                'premium-org-membership', 'premium-org', 'premium-org-user',
                'premium-org-user@example.com', now, now,
            ),
            env.DB.prepare(`
                INSERT INTO organization_users
                    (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES (?, ?, ?, ?, 1, 2, ?, ?)
            `).bind(
                'non-premium-org-membership', 'non-premium-org', 'non-premium-org-user',
                'non-premium-org-user@example.com', now, now,
            ),
        ]);
    });

    it('uses usersGetPremium rather than plan type or membership status', async () => {
        await expect(canAccessPremium(
            env.DB,
            { id: 'premium-org-user', premium: false },
            'false',
        )).resolves.toBe(true);
        await expect(canAccessPremium(
            env.DB,
            { id: 'non-premium-org-user', premium: false },
            'false',
        )).resolves.toBe(false);
    });
});
