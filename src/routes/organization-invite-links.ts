/**
 * Bitwarden Workers - Organization invite link public routes
 * 对应官方 OrganizationInviteLinksController 的公开端点，以及
 * OrganizationUsersController.AcceptInviteLink。
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, inArray } from 'drizzle-orm';
import {
    organizationInviteLinks,
    organizationUsers,
    organizations,
    policies,
    users,
} from '../db/schema';
import type { OrganizationInviteLinkRow, OrganizationRow, PolicyRow } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, NotFoundError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import { logEvent } from '../services/events';
import { PolicyType } from '../services/policy-validators';
import { pushSyncUser } from '../services/push-notification';
import type { Bindings, Variables } from '../types';
import { PushType } from '../types/push-notification';
import { getDeviceTypeFromRequest } from './events';

const inviteLinks = new Hono<{ Bindings: Bindings; Variables: Variables }>();
type D1Db = ReturnType<typeof drizzle>;

type UsableInviteLink = {
    link: OrganizationInviteLinkRow;
    organization: OrganizationRow;
};

function getBodyString(body: Record<string, unknown>, ...keys: string[]): string | null {
    for (const key of keys) {
        const value = body[key];
        if (typeof value === 'string' && value.trim().length > 0) {
            return value.trim();
        }
    }
    return null;
}

function parseAllowedDomains(link: OrganizationInviteLinkRow): string[] {
    try {
        const parsed = JSON.parse(link.allowedDomains);
        if (!Array.isArray(parsed)) return [];
        return parsed
            .filter((domain): domain is string => typeof domain === 'string')
            .map((domain) => domain.trim().toLowerCase())
            .filter(Boolean);
    } catch {
        return [];
    }
}

function isEmailDomainAllowed(email: string, domains: string[]): boolean {
    const at = email.lastIndexOf('@');
    if (at < 0) return false;
    const domain = email.slice(at + 1).trim().toLowerCase();
    return domains.includes(domain);
}

async function getInviteLinkByCode(db: D1Db, code: string): Promise<OrganizationInviteLinkRow | undefined> {
    return await db.select().from(organizationInviteLinks)
        .where(eq(organizationInviteLinks.code, code))
        .get();
}

async function getUsableInviteLink(db: D1Db, code: string): Promise<UsableInviteLink> {
    const link = await getInviteLinkByCode(db, code);
    if (!link) throw new NotFoundError('Invite link not found.');

    const organization = await db.select().from(organizations)
        .where(eq(organizations.id, link.organizationId))
        .get();
    if (!organization || !organization.enabled || !organization.useInviteLinks) {
        throw new NotFoundError('Invite link not found.');
    }

    return { link, organization };
}

async function getOccupiedSeatCount(db: D1Db, organizationId: string): Promise<number> {
    const rows = await db.select({ id: organizationUsers.id }).from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, organizationId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();
    return rows.length;
}

async function hasAvailableSeat(db: D1Db, organization: OrganizationRow): Promise<boolean> {
    if (organization.seats == null) return true;
    const occupied = await getOccupiedSeatCount(db, organization.id);
    return occupied < organization.seats;
}

function isNoSuchTablePolicies(e: unknown): boolean {
    const msg = e instanceof Error ? e.message : String(e);
    return /no such table:\s*policies/i.test(msg);
}

async function getEnabledPolicies(db: D1Db, organizationId: string): Promise<PolicyRow[]> {
    try {
        return await db.select().from(policies)
            .where(and(eq(policies.organizationId, organizationId), eq(policies.enabled, true)))
            .all();
    } catch (e) {
        if (isNoSuchTablePolicies(e)) return [];
        throw e;
    }
}

function toPolicyResponse(policy: PolicyRow) {
    let data: Record<string, unknown> | null = null;
    if (policy.data) {
        try {
            data = JSON.parse(policy.data);
        } catch {
            data = null;
        }
    }

    return {
        id: policy.id,
        organizationId: policy.organizationId,
        type: policy.type,
        data,
        enabled: policy.enabled,
        revisionDate: policy.revisionDate,
        object: 'policy',
    };
}

function resetPasswordAutoEnrollEnabled(policiesList: PolicyRow[]): boolean {
    const resetPolicy = policiesList.find((policy) => policy.type === PolicyType.ResetPassword && policy.enabled);
    if (!resetPolicy?.data) return false;

    try {
        const data = JSON.parse(resetPolicy.data) as { autoEnrollEnabled?: unknown };
        return data.autoEnrollEnabled === true;
    } catch {
        return false;
    }
}

/**
 * POST /organizations/invite-link/status
 */
inviteLinks.post('/invite-link/status', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<Record<string, unknown>>();
    const code = getBodyString(body, 'code', 'Code');
    if (!code) throw new BadRequestError('Code is required.');

    const { organization } = await getUsableInviteLink(db, code);

    return c.json({
        organizationName: organization.name,
        seatsAvailable: await hasAvailableSeat(db, organization),
        sso: null,
        object: 'inviteLinkStatus',
    });
});

/**
 * POST /organizations/invite-link/policies
 */
inviteLinks.post('/invite-link/policies', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<Record<string, unknown>>();
    const code = getBodyString(body, 'code', 'Code');
    if (!code) throw new BadRequestError('Code is required.');

    const { organization } = await getUsableInviteLink(db, code);
    if (!organization.usePolicies) {
        throw new NotFoundError('Invite link not found.');
    }

    const enabledPolicies = await getEnabledPolicies(db, organization.id);
    return c.json({
        data: enabledPolicies.map(toPolicyResponse),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * POST /organizations/invite-link/validate-email-domain
 */
inviteLinks.post('/invite-link/validate-email-domain', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<Record<string, unknown>>();
    const code = getBodyString(body, 'code', 'Code');
    const email = getBodyString(body, 'email', 'Email');
    if (!code) throw new BadRequestError('Code is required.');
    if (!email) throw new BadRequestError('Email is required.');

    const { link } = await getUsableInviteLink(db, code);
    return c.json({
        isAllowed: isEmailDomainAllowed(email, parseAllowedDomains(link)),
    });
});

/**
 * POST /organizations/users/invite-link/accept
 */
inviteLinks.post('/users/invite-link/accept', authMiddleware, async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<Record<string, unknown>>();
    const code = getBodyString(body, 'code', 'Code');
    const resetPasswordKey = getBodyString(body, 'resetPasswordKey', 'ResetPasswordKey');
    if (!code) throw new BadRequestError('Code is required.');

    const currentUser = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!currentUser) throw new NotFoundError('User not found.');

    const { link, organization } = await getUsableInviteLink(db, code);
    const userEmail = currentUser.email.trim().toLowerCase();
    if (!isEmailDomainAllowed(userEmail, parseAllowedDomains(link))) {
        throw new BadRequestError('Email domain is not allowed for this invite link.');
    }

    const enabledPolicies = await getEnabledPolicies(db, organization.id);
    if (organization.useResetPassword && resetPasswordAutoEnrollEnabled(enabledPolicies) && !resetPasswordKey) {
        throw new BadRequestError('Reset password key is required.');
    }

    const existingMemberships = await db.select().from(organizationUsers)
        .where(eq(organizationUsers.organizationId, organization.id))
        .all();
    const existing = existingMemberships.find((membership) => membership.userId === userId)
        ?? existingMemberships.find((membership) => membership.email.trim().toLowerCase() === userEmail);

    if (existing && (existing.status === -1 || existing.status === 3)) {
        throw new BadRequestError('Your organization access has been revoked.');
    }
    if (existing && (existing.status === 1 || existing.status === 2)) {
        throw new BadRequestError('You are already a member of this organization.');
    }

    if (!existing && !await hasAvailableSeat(db, organization)) {
        throw new BadRequestError('Organization has no seats available.');
    }

    const now = new Date().toISOString();
    let organizationUserId: string;
    if (existing) {
        organizationUserId = existing.id;
        await db.update(organizationUsers).set({
            userId,
            email: userEmail,
            status: 1,
            resetPasswordKey: resetPasswordKey ?? existing.resetPasswordKey,
            revisionDate: now,
        }).where(eq(organizationUsers.id, existing.id));
    } else {
        organizationUserId = generateUuid();
        await db.insert(organizationUsers).values({
            id: organizationUserId,
            organizationId: organization.id,
            userId,
            email: userEmail,
            status: 1,
            type: 2,
            resetPasswordKey,
            creationDate: now,
            revisionDate: now,
        });
    }

    await db.update(users).set({ accountRevisionDate: now }).where(eq(users.id, userId));
    await logEvent(c.env.DB, 1524, {
        userId,
        organizationId: organization.id,
        organizationUserId,
        deviceType: getDeviceTypeFromRequest(c),
    });
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncOrganizations, userId, null));

    return c.body(null, 200);
});

export default inviteLinks;
