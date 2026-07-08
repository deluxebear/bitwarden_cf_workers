/**
 * Organization two-factor compatibility routes.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq } from 'drizzle-orm';
import { organizations, organizationUsers, users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { verifyPassword } from '../services/crypto';
import type { Bindings, Variables } from '../types';

const organizationTwoFactor = new Hono<{ Bindings: Bindings; Variables: Variables }>();
organizationTwoFactor.use('/*', authMiddleware);
type OrganizationTwoFactorContext = Context<{ Bindings: Bindings; Variables: Variables }>;

function parsePermissions(permissions: string | null): { managePolicies?: boolean } | null {
    if (!permissions) return null;
    try {
        return JSON.parse(permissions) as { managePolicies?: boolean };
    } catch {
        return null;
    }
}

function canManagePolicies(orgUser: typeof organizationUsers.$inferSelect): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true;
    return parsePermissions(orgUser.permissions)?.managePolicies === true;
}

async function disableOrganizationTwoFactor(c: OrganizationTwoFactorContext) {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');
    const body = await c.req.json<{
        type?: number;
        Type?: number;
        secret?: string;
        masterPasswordHash?: string;
    }>();
    const providerType = body.type ?? body.Type;
    if (providerType == null) throw new BadRequestError('Type is required.');

    const currentUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!currentUser) throw new NotFoundError('User not found.');
    const secret = body.secret ?? body.masterPasswordHash;
    if (!secret || !await verifyPassword(secret, currentUser.masterPassword || '')) {
        throw new BadRequestError('User verification failed.');
    }

    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
        .get();
    if (!orgUser || orgUser.status !== 2 || !canManagePolicies(orgUser)) {
        throw new NotFoundError('Organization not found or access denied.');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new NotFoundError('Organization not found.');

    let providers: Record<string, unknown> = {};
    if (org.twoFactorProviders) {
        try {
            providers = JSON.parse(org.twoFactorProviders) as Record<string, unknown>;
        } catch {
            providers = {};
        }
    }
    delete providers[String(providerType)];

    await db.update(organizations).set({
        twoFactorProviders: JSON.stringify(providers),
        revisionDate: new Date().toISOString(),
    }).where(eq(organizations.id, orgId));

    return c.json({
        type: providerType,
        enabled: false,
        object: 'twoFactorProvider',
    });
}

organizationTwoFactor.put('/:id/two-factor/disable', disableOrganizationTwoFactor);
organizationTwoFactor.post('/:id/two-factor/disable', disableOrganizationTwoFactor);

export default organizationTwoFactor;
