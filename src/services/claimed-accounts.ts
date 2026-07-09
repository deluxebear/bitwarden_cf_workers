import { and, eq, inArray, isNotNull } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/d1';

import {
    authRequests,
    ciphers,
    collectionCiphers,
    collectionUsers,
    devices,
    folders,
    groupUsers,
    notifications,
    organizationDomains,
    organizationUsers,
    refreshTokens,
    sends,
    users,
    verificationTokens,
    webAuthnCredentials,
} from '../db/schema';
import type { OrganizationUserRow, UserRow } from '../db/schema';
import { BadRequestError } from '../middleware/error';
import type { Bindings } from '../types';

type D1Db = ReturnType<typeof drizzle>;

export function getEmailDomain(email: string | null | undefined): string | null {
    if (!email) return null;
    const normalized = email.trim().toLowerCase();
    const at = normalized.lastIndexOf('@');
    if (at <= 0 || at === normalized.length - 1) return null;
    return normalized.slice(at + 1);
}

export function emailMatchesVerifiedDomain(email: string | null | undefined, domains: Iterable<string>): boolean {
    const domain = getEmailDomain(email);
    if (!domain) return false;
    for (const claimedDomain of domains) {
        if (domain === claimedDomain.trim().toLowerCase()) return true;
    }
    return false;
}

export async function getVerifiedDomainsForOrganization(db: D1Db, orgId: string): Promise<string[]> {
    const rows = await db.select({ domainName: organizationDomains.domainName })
        .from(organizationDomains)
        .where(and(
            eq(organizationDomains.organizationId, orgId),
            isNotNull(organizationDomains.verifiedDate),
        ))
        .all();

    return rows
        .map((row) => row.domainName.trim().toLowerCase())
        .filter(Boolean);
}

export async function getVerifiedDomainSetForOrganization(db: D1Db, orgId: string): Promise<Set<string>> {
    return new Set(await getVerifiedDomainsForOrganization(db, orgId));
}

export function isOrganizationUserClaimedByDomains(
    orgUser: Pick<OrganizationUserRow, 'userId' | 'status' | 'email'>,
    verifiedDomains: Set<string>,
    user?: Pick<UserRow, 'email'> | null,
): boolean {
    return !!orgUser.userId &&
        orgUser.status === 2 &&
        emailMatchesVerifiedDomain(user?.email ?? orgUser.email, verifiedDomains);
}

export async function isOrganizationUserClaimed(
    db: D1Db,
    orgUser: OrganizationUserRow,
    user?: Pick<UserRow, 'email'> | null,
): Promise<boolean> {
    const verifiedDomains = await getVerifiedDomainSetForOrganization(db, orgUser.organizationId);
    if (verifiedDomains.size === 0) return false;

    let resolvedUser = user;
    if (!resolvedUser && orgUser.userId) {
        resolvedUser = await db.select({ email: users.email })
            .from(users)
            .where(eq(users.id, orgUser.userId))
            .get() ?? null;
    }

    return isOrganizationUserClaimedByDomains(orgUser, verifiedDomains, resolvedUser);
}

export async function getClaimedMembershipsForUser(db: D1Db, userId: string): Promise<OrganizationUserRow[]> {
    const user = await db.select({ email: users.email }).from(users).where(eq(users.id, userId)).get();
    if (!user) return [];

    const memberships = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.userId, userId), eq(organizationUsers.status, 2)))
        .all();
    if (memberships.length === 0) return [];

    const orgIds = Array.from(new Set(memberships.map((membership) => membership.organizationId)));
    const domainRows = await db.select({
        organizationId: organizationDomains.organizationId,
        domainName: organizationDomains.domainName,
    })
        .from(organizationDomains)
        .where(and(
            inArray(organizationDomains.organizationId, orgIds),
            isNotNull(organizationDomains.verifiedDate),
        ))
        .all();

    const verifiedByOrg = new Map<string, Set<string>>();
    for (const row of domainRows) {
        if (!row.domainName) continue;
        if (!verifiedByOrg.has(row.organizationId)) verifiedByOrg.set(row.organizationId, new Set());
        verifiedByOrg.get(row.organizationId)!.add(row.domainName.trim().toLowerCase());
    }

    return memberships.filter((membership) =>
        isOrganizationUserClaimedByDomains(membership, verifiedByOrg.get(membership.organizationId) ?? new Set(), user),
    );
}

export async function isUserClaimedByAnyOrganization(db: D1Db, userId: string): Promise<boolean> {
    return (await getClaimedMembershipsForUser(db, userId)).length > 0;
}

export async function assertUserNotClaimedForAccountAction(
    db: D1Db,
    userId: string,
    message: string,
): Promise<void> {
    if (await isUserClaimedByAnyOrganization(db, userId)) {
        throw new BadRequestError(message);
    }
}

export async function assertOrganizationUserCanLeave(db: D1Db, orgUser: OrganizationUserRow): Promise<void> {
    if (await isOrganizationUserClaimed(db, orgUser)) {
        throw new BadRequestError('Claimed organization accounts cannot leave their organization.');
    }
}

export async function assertClaimedUserCanChangeEmail(
    db: D1Db,
    userId: string,
    newEmail: string,
): Promise<void> {
    const claimedMemberships = await getClaimedMembershipsForUser(db, userId);
    if (claimedMemberships.length === 0) return;

    const newDomain = getEmailDomain(newEmail);
    if (!newDomain) throw new BadRequestError('Invalid email.');

    for (const membership of claimedMemberships) {
        const verifiedDomains = await getVerifiedDomainSetForOrganization(db, membership.organizationId);
        if (verifiedDomains.has(newDomain)) return;
    }

    throw new BadRequestError('Claimed organization accounts cannot change their email address to an unclaimed domain.');
}

export async function deleteUserAccountData(db: D1Db, env: Bindings, userId: string): Promise<void> {
    const personalCiphers = await db.select({ id: ciphers.id, attachments: ciphers.attachments })
        .from(ciphers)
        .where(eq(ciphers.userId, userId))
        .all();
    const cipherIds = personalCiphers.map((cipher) => cipher.id);

    for (const cipher of personalCiphers) {
        await deleteCipherAttachments(env, cipher.id, cipher.attachments);
    }

    const userSends = await db.select({ id: sends.id, type: sends.type, data: sends.data })
        .from(sends)
        .where(eq(sends.userId, userId))
        .all();
    for (const send of userSends) {
        await deleteSendAttachment(env, send);
    }

    const orgUsers = await db.select({ id: organizationUsers.id })
        .from(organizationUsers)
        .where(eq(organizationUsers.userId, userId))
        .all();
    const orgUserIds = orgUsers.map((orgUser) => orgUser.id);

    if (cipherIds.length > 0) {
        await db.delete(collectionCiphers).where(inArray(collectionCiphers.cipherId, cipherIds));
    }

    if (orgUserIds.length > 0) {
        await db.delete(collectionUsers).where(inArray(collectionUsers.organizationUserId, orgUserIds));
        await db.delete(groupUsers).where(inArray(groupUsers.organizationUserId, orgUserIds));
    }

    await db.delete(authRequests).where(eq(authRequests.userId, userId));
    await db.delete(refreshTokens).where(eq(refreshTokens.userId, userId));
    await db.delete(webAuthnCredentials).where(eq(webAuthnCredentials.userId, userId));
    await db.delete(verificationTokens).where(eq(verificationTokens.userId, userId));
    await db.delete(notifications).where(eq(notifications.userId, userId));
    await db.delete(devices).where(eq(devices.userId, userId));
    await db.delete(folders).where(eq(folders.userId, userId));
    await db.delete(sends).where(eq(sends.userId, userId));
    await db.delete(ciphers).where(eq(ciphers.userId, userId));
    await db.delete(organizationUsers).where(eq(organizationUsers.userId, userId));
    await db.delete(users).where(eq(users.id, userId));
}

async function deleteCipherAttachments(env: Bindings, cipherId: string, attachments: string | null): Promise<void> {
    if (!attachments) return;
    try {
        const attachmentList = JSON.parse(attachments);
        if (!Array.isArray(attachmentList)) return;
        await Promise.all(attachmentList.map(async (attachment) => {
            const attachmentId = attachment?.id ?? attachment?.Id;
            if (typeof attachmentId === 'string' && attachmentId.length > 0) {
                await env.ATTACHMENTS.delete(`${cipherId}/${attachmentId}`);
            }
        }));
    } catch {
        return;
    }
}

async function deleteSendAttachment(
    env: Bindings,
    send: { id: string; type: number; data: string | null },
): Promise<void> {
    if (send.type !== 1 || !send.data) return;
    try {
        const data = JSON.parse(send.data);
        const fileId = data?.id ?? data?.Id;
        if (typeof fileId === 'string' && fileId.length > 0) {
            await env.ATTACHMENTS.delete(`sends/${send.id}/${fileId}`);
        }
    } catch {
        return;
    }
}
