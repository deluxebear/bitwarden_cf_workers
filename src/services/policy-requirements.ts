import { and, eq, inArray, sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';
import {
    organizationDomains,
    organizations,
    organizationUsers,
    policies,
    sends,
    users,
} from '../db/schema';
import type { OrganizationUserRow, PolicyRow, UserRow } from '../db/schema';
import { BadRequestError } from '../middleware/error';
import { generateUuid } from './crypto';
import { PolicyType } from './policy-validators';

type D1Db = ReturnType<typeof drizzle>;

const ACTIVE_MEMBER_STATUSES = new Set([1, 2]);
const ACTIVE_OR_REVOKED_MEMBER_STATUSES = new Set([-1, 1, 2, 3]);
const OWNER_OR_ADMIN_TYPES = new Set([0, 1]);

export type MasterPasswordPolicyRequirement = {
    minComplexity?: number;
    minLength?: number;
    requireLower?: boolean;
    requireUpper?: boolean;
    requireNumbers?: boolean;
    requireSpecial?: boolean;
    enforceOnLogin?: boolean;
};

type SendControlsRequirement = {
    disableSend: boolean;
    disableHideEmail: boolean;
    whoCanAccess: number | null;
    allowedDomains: string | null;
    allowedSendTypes: number[] | null;
};

function parsePolicyData(policy: Pick<PolicyRow, 'data'> | null | undefined): Record<string, any> {
    if (!policy?.data) return {};
    try {
        return JSON.parse(policy.data);
    } catch {
        return {};
    }
}

function getDataBoolean(data: Record<string, any>, camel: string, pascal?: string): boolean {
    const value = data[camel] ?? (pascal ? data[pascal] : undefined);
    return value === true || value === 'true';
}

function getDataNumber(data: Record<string, any>, camel: string, pascal?: string): number | null {
    const value = data[camel] ?? (pascal ? data[pascal] : undefined);
    if (value == null || value === '') return null;
    const n = Number(value);
    return Number.isFinite(n) ? n : null;
}

function getDataString(data: Record<string, any>, camel: string, pascal?: string): string | null {
    const value = data[camel] ?? (pascal ? data[pascal] : undefined);
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : null;
}

function getDataNumberArray(data: Record<string, any>, camel: string, pascal?: string): number[] | null {
    const value = data[camel] ?? (pascal ? data[pascal] : undefined);
    if (!Array.isArray(value)) return null;
    const result = value.map((v) => Number(v)).filter((v) => Number.isInteger(v));
    return result.length > 0 ? Array.from(new Set(result)) : null;
}

async function getUserMemberships(db: D1Db, userId: string): Promise<OrganizationUserRow[]> {
    return db.select().from(organizationUsers).where(eq(organizationUsers.userId, userId)).all();
}

function policyAppliesToMembership(type: number, membership: OrganizationUserRow): boolean {
    if (membership.status === -1 || membership.status === 3) return false;

    if (type === PolicyType.MasterPassword) {
        return ACTIVE_MEMBER_STATUSES.has(membership.status);
    }

    if (type === PolicyType.SingleOrg || type === PolicyType.AutomaticUserConfirmation) {
        return ACTIVE_OR_REVOKED_MEMBER_STATUSES.has(membership.status);
    }

    if (OWNER_OR_ADMIN_TYPES.has(membership.type)) return false;
    return ACTIVE_MEMBER_STATUSES.has(membership.status);
}

async function getEnabledPoliciesForUser(db: D1Db, userId: string, type: number): Promise<Array<PolicyRow & { membership: OrganizationUserRow }>> {
    const memberships = (await getUserMemberships(db, userId)).filter((m) => policyAppliesToMembership(type, m));
    if (memberships.length === 0) return [];

    const orgIds = Array.from(new Set(memberships.map((m) => m.organizationId)));
    const policyRows = await db.select().from(policies)
        .where(and(inArray(policies.organizationId, orgIds), eq(policies.type, type), eq(policies.enabled, true)))
        .all();
    const membershipByOrgId = new Map(memberships.map((m) => [m.organizationId, m]));
    return policyRows
        .map((policy) => ({ ...policy, membership: membershipByOrgId.get(policy.organizationId)! }))
        .filter((policy) => !!policy.membership);
}

export async function getMasterPasswordPolicyForUser(db: D1Db, userId: string): Promise<MasterPasswordPolicyRequirement | null> {
    const rows = await getEnabledPoliciesForUser(db, userId, PolicyType.MasterPassword);
    if (rows.length === 0) return null;

    const result: MasterPasswordPolicyRequirement = {};
    for (const policy of rows) {
        const data = parsePolicyData(policy);
        const minComplexity = getDataNumber(data, 'minComplexity', 'MinComplexity');
        const minLength = getDataNumber(data, 'minLength', 'MinLength');
        if (minComplexity != null) result.minComplexity = Math.max(result.minComplexity ?? 0, minComplexity);
        if (minLength != null) result.minLength = Math.max(result.minLength ?? 0, minLength);
        result.requireLower = !!result.requireLower || getDataBoolean(data, 'requireLower', 'RequireLower');
        result.requireUpper = !!result.requireUpper || getDataBoolean(data, 'requireUpper', 'RequireUpper');
        result.requireNumbers = !!result.requireNumbers || getDataBoolean(data, 'requireNumbers', 'RequireNumbers');
        result.requireSpecial = !!result.requireSpecial || getDataBoolean(data, 'requireSpecial', 'RequireSpecial');
        result.enforceOnLogin = !!result.enforceOnLogin || getDataBoolean(data, 'enforceOnLogin', 'EnforceOnLogin');
    }

    return Object.keys(result).length > 0 ? result : null;
}

export function userHasTwoFactor(user: Pick<UserRow, 'twoFactorProviders'>): boolean {
    if (!user.twoFactorProviders) return false;
    try {
        const providers = JSON.parse(user.twoFactorProviders);
        if (Array.isArray(providers)) return providers.some((p) => p?.enabled === true);
        if (providers && typeof providers === 'object') {
            return Object.values(providers).some((p: any) => p?.enabled === true);
        }
    } catch {
        return false;
    }
    return false;
}

async function isOrgPolicyEnabled(db: D1Db, orgId: string, type: number): Promise<boolean> {
    const policy = await db.select().from(policies)
        .where(and(eq(policies.organizationId, orgId), eq(policies.type, type)))
        .get();
    return policy?.enabled === true;
}

async function getOrgPolicy(db: D1Db, orgId: string, type: number): Promise<PolicyRow | undefined> {
    return db.select().from(policies)
        .where(and(eq(policies.organizationId, orgId), eq(policies.type, type)))
        .get();
}

export async function validateUserCanJoinOrganization(
    db: D1Db,
    user: UserRow,
    targetOrganizationId: string,
): Promise<{ autoConfirm: boolean; resetPasswordAutoEnroll: boolean }> {
    const memberships = await getUserMemberships(db, user.id);
    const blockingOtherMemberships = memberships.filter((m) =>
        m.organizationId !== targetOrganizationId && ACTIVE_OR_REVOKED_MEMBER_STATUSES.has(m.status)
    );

    const targetHasSingleOrg = await isOrgPolicyEnabled(db, targetOrganizationId, PolicyType.SingleOrg);
    if (targetHasSingleOrg && blockingOtherMemberships.length > 0) {
        throw new BadRequestError('You cannot join this organization because it has the Single Organization policy enabled.');
    }

    const otherOrgIds = Array.from(new Set(blockingOtherMemberships.map((m) => m.organizationId)));
    if (otherOrgIds.length > 0) {
        const singleOrgPolicies = await db.select().from(policies)
            .where(and(inArray(policies.organizationId, otherOrgIds), eq(policies.type, PolicyType.SingleOrg), eq(policies.enabled, true)))
            .all();
        if (singleOrgPolicies.length > 0) {
            throw new BadRequestError('You cannot join another organization because one of your organizations has the Single Organization policy enabled.');
        }
    }

    if (await isOrgPolicyEnabled(db, targetOrganizationId, PolicyType.TwoFactorAuthentication) && !userHasTwoFactor(user)) {
        throw new BadRequestError('You must enable two-step login before joining this organization.');
    }

    const autoConfirm = await isOrgPolicyEnabled(db, targetOrganizationId, PolicyType.AutomaticUserConfirmation);
    if (autoConfirm && blockingOtherMemberships.length > 0) {
        throw new BadRequestError('You cannot join this organization because it automatically confirms users and you already belong to another organization.');
    }

    const resetPasswordPolicy = await getOrgPolicy(db, targetOrganizationId, PolicyType.ResetPassword);
    const resetPasswordData = parsePolicyData(resetPasswordPolicy);
    const resetPasswordAutoEnroll = resetPasswordPolicy?.enabled === true &&
        getDataBoolean(resetPasswordData, 'autoEnrollEnabled', 'AutoEnrollEnabled');

    return { autoConfirm, resetPasswordAutoEnroll };
}

export async function assertAutomaticUserConfirmationCanBeEnabled(db: D1Db, orgId: string): Promise<void> {
    const targetMemberships = await db.select().from(organizationUsers)
        .where(eq(organizationUsers.organizationId, orgId))
        .all();
    const userIds = Array.from(new Set(targetMemberships
        .filter((m) => m.userId && ACTIVE_OR_REVOKED_MEMBER_STATUSES.has(m.status))
        .map((m) => m.userId)
        .filter((id): id is string => !!id)));
    if (userIds.length === 0) return;

    const allMemberships = await db.select().from(organizationUsers)
        .where(inArray(organizationUsers.userId, userIds))
        .all();
    const hasNonCompliantUser = allMemberships.some((membership) =>
        membership.organizationId !== orgId &&
        membership.userId &&
        ACTIVE_OR_REVOKED_MEMBER_STATUSES.has(membership.status)
    );
    if (hasNonCompliantUser) {
        throw new BadRequestError('The Automatically Confirm Users policy cannot be enabled while organization members belong to another organization.');
    }
}

function parseOrgPermissions(permissions: string | null): { manageUsers?: boolean } | null {
    if (!permissions) return null;
    try {
        return JSON.parse(permissions) as { manageUsers?: boolean };
    } catch {
        return null;
    }
}

export async function getAutoConfirmRecipientUserIds(db: D1Db, orgId: string): Promise<string[]> {
    const members = await db.select().from(organizationUsers)
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            eq(organizationUsers.status, 2),
            sql`${organizationUsers.userId} IS NOT NULL`,
        ))
        .all();
    const ids = members
        .filter((member) =>
            OWNER_OR_ADMIN_TYPES.has(member.type) ||
            (member.type === 4 && parseOrgPermissions(member.permissions)?.manageUsers === true)
        )
        .map((member) => member.userId)
        .filter((id): id is string => !!id);
    return Array.from(new Set(ids));
}

export async function assertCanCreateOrganization(db: D1Db, userId: string): Promise<void> {
    const singleOrgPolicies = await getEnabledPoliciesForUser(db, userId, PolicyType.SingleOrg);
    if (singleOrgPolicies.length > 0) {
        throw new BadRequestError('You cannot create another organization because the Single Organization policy is enabled.');
    }
    const autoConfirmPolicies = await getEnabledPoliciesForUser(db, userId, PolicyType.AutomaticUserConfirmation);
    if (autoConfirmPolicies.length > 0) {
        throw new BadRequestError('You cannot create another organization because an organization automatically confirms users.');
    }
}

export async function assertPersonalVaultWriteAllowed(db: D1Db, userId: string): Promise<void> {
    const rows = await getEnabledPoliciesForUser(db, userId, PolicyType.OrganizationDataOwnership);
    if (rows.length > 0) {
        throw new BadRequestError('Due to an Enterprise Policy, you are restricted from saving items to your individual vault.');
    }
}

function normalizeDomain(domain: string): string {
    return domain.trim().toLowerCase().replace(/^@+/, '');
}

function splitDomains(domains: string | null): string[] {
    if (!domains) return [];
    return domains
        .split(',')
        .map(normalizeDomain)
        .filter(Boolean);
}

function parseEmails(emails: string | null | undefined): string[] {
    if (!emails) return [];
    return emails
        .split(',')
        .map((email) => email.trim().toLowerCase())
        .filter(Boolean);
}

function allEmailsHaveAllowedDomains(emails: string | null | undefined, allowedDomains: string | null): boolean {
    const domains = splitDomains(allowedDomains);
    if (domains.length === 0) return true;
    const emailList = parseEmails(emails);
    if (emailList.length === 0) return false;
    return emailList.every((email) => {
        const at = email.lastIndexOf('@');
        if (at <= 0 || at === email.length - 1) {
            throw new BadRequestError('Invalid Send email recipient.');
        }
        const domain = email.slice(at + 1);
        return domains.some((allowed) => domain === allowed || domain.endsWith(`.${allowed}`));
    });
}

export async function getSendControlsRequirementForUser(db: D1Db, userId: string): Promise<SendControlsRequirement> {
    const result: SendControlsRequirement = {
        disableSend: false,
        disableHideEmail: false,
        whoCanAccess: null,
        allowedDomains: null,
        allowedSendTypes: null,
    };

    const rows = await getUserMemberships(db, userId);
    const applicable = rows.filter((m) => policyAppliesToMembership(PolicyType.SendControls, m));
    if (applicable.length === 0) return result;

    const orgIds = Array.from(new Set(applicable.map((m) => m.organizationId)));
    const policyRows = await db.select().from(policies)
        .where(and(inArray(policies.organizationId, orgIds), inArray(policies.type, [
            PolicyType.DisableSend,
            PolicyType.SendOptions,
            PolicyType.SendControls,
        ])))
        .all();

    for (const policy of policyRows) {
        if (!policy.enabled) continue;
        const data = parsePolicyData(policy);
        if (policy.type === PolicyType.DisableSend) {
            result.disableSend = true;
            continue;
        }
        if (policy.type === PolicyType.SendOptions) {
            result.disableHideEmail = result.disableHideEmail ||
                getDataBoolean(data, 'disableHideEmail', 'DisableHideEmail');
            continue;
        }
        result.disableSend = result.disableSend || getDataBoolean(data, 'disableSend', 'DisableSend');
        result.disableHideEmail = result.disableHideEmail ||
            getDataBoolean(data, 'disableHideEmail', 'DisableHideEmail');
        result.whoCanAccess = result.whoCanAccess ?? getDataNumber(data, 'whoCanAccess', 'WhoCanAccess');
        result.allowedDomains = result.allowedDomains ?? getDataString(data, 'allowedDomains', 'AllowedDomains');
        result.allowedSendTypes = result.allowedSendTypes ?? getDataNumberArray(data, 'allowedSendTypes', 'AllowedSendTypes');
    }

    return result;
}

export async function validateSendCanSave(db: D1Db, userId: string, send: {
    type: number;
    password?: string | null;
    hasPassword?: boolean;
    hideEmail?: boolean | null;
    emails?: string | null;
}): Promise<void> {
    const requirement = await getSendControlsRequirementForUser(db, userId);

    if (requirement.disableSend) {
        throw new BadRequestError('Due to an Enterprise Policy, you are only able to delete an existing Send.');
    }
    if (requirement.disableHideEmail && send.hideEmail === true) {
        throw new BadRequestError('Due to an Enterprise Policy, you are not allowed to hide your email address on Sends.');
    }
    if (requirement.whoCanAccess === 1 && !send.password && !send.hasPassword) {
        throw new BadRequestError('Due to an Enterprise Policy, your Sends must be protected by a password.');
    }
    if (requirement.whoCanAccess === 2) {
        if (!send.emails) {
            throw new BadRequestError('Due to an Enterprise Policy, your Sends must use email verification.');
        }
        if (!allEmailsHaveAllowedDomains(send.emails, requirement.allowedDomains)) {
            throw new BadRequestError(`Due to an Enterprise Policy, your Sends must only allow recipients from: ${requirement.allowedDomains}.`);
        }
    }
    if (requirement.allowedSendTypes && !requirement.allowedSendTypes.includes(Number(send.type))) {
        throw new BadRequestError('Due to an Enterprise Policy, this Send type is not allowed.');
    }
}

function sendIsNonCompliant(send: typeof sends.$inferSelect, data: Record<string, any>, enabled: boolean): boolean {
    if (!enabled) return false;
    if (getDataBoolean(data, 'disableSend', 'DisableSend')) return true;
    if (getDataBoolean(data, 'disableHideEmail', 'DisableHideEmail') && send.hideEmail === true) return true;
    const whoCanAccess = getDataNumber(data, 'whoCanAccess', 'WhoCanAccess');
    if (whoCanAccess === 1 && !send.password) return true;
    if (whoCanAccess === 2) {
        const emails = (send as any).emails ?? null;
        if (!emails) return true;
        try {
            if (!allEmailsHaveAllowedDomains(emails, getDataString(data, 'allowedDomains', 'AllowedDomains'))) return true;
        } catch {
            return true;
        }
    }
    const allowedTypes = getDataNumberArray(data, 'allowedSendTypes', 'AllowedSendTypes');
    if (allowedTypes && !allowedTypes.includes(send.type)) return true;
    return false;
}

async function upsertPolicy(db: D1Db, orgId: string, type: number, enabled: boolean, data: Record<string, any> | null, now: string): Promise<void> {
    const existing = await getOrgPolicy(db, orgId, type);
    if (existing) {
        await db.update(policies).set({
            enabled,
            data: data == null ? existing.data : JSON.stringify(data),
            revisionDate: now,
        }).where(eq(policies.id, existing.id));
        return;
    }
    await db.insert(policies).values({
        id: generateUuid(),
        organizationId: orgId,
        type,
        enabled,
        data: data == null ? null : JSON.stringify(data),
        creationDate: now,
        revisionDate: now,
    });
}

export async function applySendPolicySideEffects(db: D1Db, orgId: string, type: number, policy: PolicyRow, now?: string): Promise<void> {
    const timestamp = now ?? new Date().toISOString();
    let sendControlsData = parsePolicyData(policy);
    let sendControlsEnabled = policy.enabled === true;

    if (type === PolicyType.DisableSend || type === PolicyType.SendOptions) {
        const sendControls = await getOrgPolicy(db, orgId, PolicyType.SendControls);
        sendControlsData = parsePolicyData(sendControls);
        if (type === PolicyType.DisableSend) {
            sendControlsData.DisableSend = policy.enabled === true;
        } else {
            const sendOptionsData = parsePolicyData(policy);
            sendControlsData.DisableHideEmail = getDataBoolean(sendOptionsData, 'disableHideEmail', 'DisableHideEmail');
        }
        sendControlsEnabled = !!sendControlsData.DisableSend ||
            (policy.enabled === true && type === PolicyType.SendOptions) ||
            (sendControls?.enabled === true && type === PolicyType.DisableSend);
        await upsertPolicy(db, orgId, PolicyType.SendControls, sendControlsEnabled, sendControlsData, timestamp);
    } else if (type === PolicyType.SendControls) {
        await upsertPolicy(
            db,
            orgId,
            PolicyType.DisableSend,
            policy.enabled === true && getDataBoolean(sendControlsData, 'disableSend', 'DisableSend'),
            null,
            timestamp,
        );
        await upsertPolicy(
            db,
            orgId,
            PolicyType.SendOptions,
            policy.enabled === true && getDataBoolean(sendControlsData, 'disableHideEmail', 'DisableHideEmail'),
            { DisableHideEmail: getDataBoolean(sendControlsData, 'disableHideEmail', 'DisableHideEmail') },
            timestamp,
        );
    } else {
        return;
    }

    const memberRows = await db.select({ userId: organizationUsers.userId }).from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), sql`${organizationUsers.userId} IS NOT NULL`))
        .all();
    const userIds = Array.from(new Set(memberRows.map((m) => m.userId).filter((id): id is string => !!id)));
    if (userIds.length === 0) return;

    const orgSends = await db.select().from(sends).where(inArray(sends.userId, userIds)).all();
    for (const send of orgSends) {
        const disabled = sendIsNonCompliant(send, sendControlsData, sendControlsEnabled);
        if (send.disabled !== disabled) {
            await db.update(sends).set({ disabled, revisionDate: timestamp }).where(eq(sends.id, send.id));
        }
    }
}

export async function assertClaimedDomainPolicyCanBeEnabled(db: D1Db, orgId: string): Promise<void> {
    const verified = await db.select({ id: organizationDomains.id }).from(organizationDomains)
        .where(and(eq(organizationDomains.organizationId, orgId), sql`${organizationDomains.verifiedDate} IS NOT NULL`))
        .get();
    if (!verified) {
        throw new BadRequestError('At least one verified organization domain is required before blocking account creation for claimed domains.');
    }
}

export async function assertEmailNotBlockedByClaimedDomain(db: D1Db, email: string, allowInvitedUser = false): Promise<void> {
    const normalized = email.trim().toLowerCase();
    const at = normalized.lastIndexOf('@');
    if (at <= 0 || at === normalized.length - 1) return;
    const domain = normalized.slice(at + 1);

    const domainRows = await db.select().from(organizationDomains)
        .where(and(eq(organizationDomains.domainName, domain), sql`${organizationDomains.verifiedDate} IS NOT NULL`))
        .all();
    if (domainRows.length === 0) return;

    const orgIds = domainRows.map((d) => d.organizationId);
    const blockingPolicies = await db.select().from(policies)
        .where(and(
            inArray(policies.organizationId, orgIds),
            eq(policies.type, PolicyType.BlockClaimedDomainAccountCreation),
            eq(policies.enabled, true),
        ))
        .all();
    if (blockingPolicies.length === 0) return;

    if (allowInvitedUser) {
        const invite = await db.select({ id: organizationUsers.id }).from(organizationUsers)
            .where(and(
                inArray(organizationUsers.organizationId, blockingPolicies.map((p) => p.organizationId)),
                eq(organizationUsers.email, normalized),
                eq(organizationUsers.status, 0),
            ))
            .get();
        if (invite) return;
    }

    throw new BadRequestError('Account creation is blocked for this organization domain.');
}

export async function createDefaultUserCollectionForOrganizationDataOwnership(db: D1Db, orgId: string, collectionName: unknown): Promise<void> {
    if (typeof collectionName !== 'string' || collectionName.trim().length === 0) return;
    const org = await db.select({ useMyItems: organizations.useMyItems }).from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org?.useMyItems) return;
    // Current Workers routes already create user-chosen default collections during org creation.
    // This helper is intentionally conservative because migration of existing personal items is out of scope.
}
