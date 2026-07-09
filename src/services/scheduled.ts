// Bitwarden Workers - 定时任务调度模块
// 对应官方 Admin/JobsHostedService.cs + Api/JobsHostedService.cs
// 使用 Cloudflare Workers Cron Triggers 实现
//
// 任务清单:
// - every 5 min  : deleteSends          - 删除到期 Send (DeleteSendsJob)
// - daily 0:00   : deleteTrashedCiphers - 永久删除30天前软删除 Cipher (DeleteCiphersJob)
// - daily 0:00   : verifyOrgDomains     - 持续复验声明域名 TXT
// - fri 22:00    : deleteExpiredTokens  - 清理过期 Refresh Token (DatabaseExpiredGrantsJob)

import { drizzle } from 'drizzle-orm/d1';
import { lte, and, eq, isNotNull, sql } from 'drizzle-orm';
import { sends, ciphers, refreshTokens, collectionCiphers, authRequests, organizationDomains, policies } from '../db/schema';
import type { Bindings } from '../types';
import { generateUuid } from './crypto';
import { PolicyType } from './policy-validators';
import { verifyOrganizationDomainDns } from '../routes/organization-domains';

/**
 * 定时任务调度入口
 */
export async function handleScheduled(cron: string, env: Bindings): Promise<void> {
    console.log(`[Scheduled] Cron triggered: ${cron} at ${new Date().toISOString()}`);

    switch (cron) {
        case '*/5 * * * *':
            await deleteSends(env);
            await deleteExpiredAuthRequests(env);
            break;
        case '0 0 * * *':
            await deleteTrashedCiphers(env);
            await verifyOrganizationDomains(env);
            break;
        case '0 22 * * 5':
            await deleteExpiredRefreshTokens(env);
            break;
        default:
            console.log(`[Scheduled] Unknown cron: ${cron}`);
    }
}

/**
 * 删除到期 Send
 * 对应 Admin/Tools/Jobs/DeleteSendsJob.cs
 * 
 * 官方逻辑：查找 deletionDate <= now() 的 Send，逐个删除
 * Workers 简化：直接批量 DELETE
 */
async function deleteSends(env: Bindings): Promise<void> {
    const db = drizzle(env.DB);
    const now = new Date().toISOString();

    // 先查找要删除的 file 类型 Send，清理 R2 附件
    const expiredFileSends = await db
        .select({ id: sends.id, type: sends.type, data: sends.data })
        .from(sends)
        .where(lte(sends.deletionDate, now));

    if (expiredFileSends.length === 0) {
        console.log('[DeleteSends] No expired sends found.');
        return;
    }

    // 清理 file 类型 Send 的 R2 存储
    for (const send of expiredFileSends) {
        if (send.type === 1 && send.data) {
            // type=1 是 File，data 中包含文件 ID
            try {
                const data = JSON.parse(send.data);
                if (data.id) {
                    await env.ATTACHMENTS.delete(`sends/${send.id}/${data.id}`);
                }
            } catch (e) {
                console.error(`[DeleteSends] Failed to clean R2 for send ${send.id}:`, e);
            }
        }
    }

    // 批量删除过期 Send 记录
    const result = await db
        .delete(sends)
        .where(lte(sends.deletionDate, now));

    console.log(`[DeleteSends] Deleted ${expiredFileSends.length} expired sends.`);
}

/**
 * 永久删除30天前软删除的 Cipher
 * 对应 Admin/Jobs/DeleteCiphersJob.cs
 *
 * 官方逻辑：
 *   deleteDate = DateTime.UtcNow.AddDays(-30)  // 默认30天
 *   cipherRepository.DeleteDeletedAsync(deleteDate)
 */
async function deleteTrashedCiphers(env: Bindings): Promise<void> {
    const db = drizzle(env.DB);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

    // 查找30天前已软删除的 Cipher
    const trashedCiphers = await db
        .select({ id: ciphers.id, attachments: ciphers.attachments })
        .from(ciphers)
        .where(
            and(
                isNotNull(ciphers.deletedDate),
                lte(ciphers.deletedDate, thirtyDaysAgo)
            )
        );

    if (trashedCiphers.length === 0) {
        console.log('[DeleteCiphers] No expired trashed ciphers found.');
        return;
    }

    // 清理 R2 附件
    for (const cipher of trashedCiphers) {
        if (cipher.attachments) {
            try {
                const attachmentList = JSON.parse(cipher.attachments);
                if (Array.isArray(attachmentList)) {
                    for (const att of attachmentList) {
                        const attId = att.id || att.Id;
                        if (attId) {
                            await env.ATTACHMENTS.delete(`${cipher.id}/${attId}`);
                        }
                    }
                }
            } catch (e) {
                console.error(`[DeleteCiphers] Failed to clean R2 for cipher ${cipher.id}:`, e);
            }
        }
    }

    const cipherIds = trashedCiphers.map(c => c.id);

    // 删除 collection_ciphers 关联（cascade 应自动处理，但显式清理更安全）
    for (const id of cipherIds) {
        await db.delete(collectionCiphers).where(
            sql`${collectionCiphers.cipherId} = ${id}`
        );
    }

    // 批量删除 Cipher 记录
    for (const id of cipherIds) {
        await db.delete(ciphers).where(
            sql`${ciphers.id} = ${id}`
        );
    }

    console.log(`[DeleteCiphers] Permanently deleted ${cipherIds.length} trashed ciphers.`);
}

/**
 * 清理过期 Refresh Token
 * 对应 Admin/Auth/Jobs/DatabaseExpiredGrantsJob.cs
 *
 * 官方逻辑：maintenanceRepository.DeleteExpiredGrantsAsync()
 * Workers 简化：直接删除 expiration_date <= now() 的 refresh_tokens
 */
async function deleteExpiredRefreshTokens(env: Bindings): Promise<void> {
    const db = drizzle(env.DB);
    const now = new Date().toISOString();

    const result = await db
        .delete(refreshTokens)
        .where(lte(refreshTokens.expirationDate, now));

    console.log(`[DeleteExpiredTokens] Cleaned up expired refresh tokens.`);
}

/**
 * 删除过期 Auth Requests
 * 对应 Admin/Auth/Jobs/DeleteAuthRequestsJob.cs
 *
 * 官方逻辑：删除 creationDate > 15 分钟的 auth requests
 * AuthRequest.GetExpirationDate() = CreationDate.AddMinutes(15)
 */
async function deleteExpiredAuthRequests(env: Bindings): Promise<void> {
    const db = drizzle(env.DB);
    const fifteenMinutesAgo = new Date(Date.now() - 15 * 60 * 1000).toISOString();

    const result = await db
        .delete(authRequests)
        .where(lte(authRequests.creationDate, fifteenMinutesAgo));

    console.log(`[DeleteAuthRequests] Cleaned up expired auth requests.`);
}

async function ensureSingleOrgPolicyEnabled(db: ReturnType<typeof drizzle>, orgId: string, now: string): Promise<void> {
    const existing = await db.select().from(policies)
        .where(and(eq(policies.organizationId, orgId), eq(policies.type, PolicyType.SingleOrg)))
        .get();

    if (existing) {
        if (existing.enabled !== true) {
            await db.update(policies).set({ enabled: true, revisionDate: now }).where(eq(policies.id, existing.id));
        }
        return;
    }

    await db.insert(policies).values({
        id: generateUuid(),
        organizationId: orgId,
        type: PolicyType.SingleOrg,
        enabled: true,
        data: null,
        creationDate: now,
        revisionDate: now,
    });
}

/**
 * 持续复验组织声明域名。
 *
 * 官方要求 TXT 记录保持存在，并会在声明流程中多次尝试验证；
 * Workers 使用 nextRunDate/jobRunCount 做轻量调度。
 */
async function verifyOrganizationDomains(env: Bindings): Promise<void> {
    const db = drizzle(env.DB);
    const now = new Date();
    const nowIso = now.toISOString();
    const nextRunDate = new Date(now.getTime() + 24 * 60 * 60 * 1000).toISOString();
    const removalCutoff = new Date(now.getTime() - 10 * 24 * 60 * 60 * 1000).toISOString();
    const resolverUrl = (env as { DNS_RESOLVER_URL?: string }).DNS_RESOLVER_URL?.trim();

    const dueDomains = await db.select().from(organizationDomains)
        .where(lte(organizationDomains.nextRunDate, nowIso))
        .all();

    if (dueDomains.length === 0) {
        console.log('[VerifyOrganizationDomains] No due organization domains found.');
        return;
    }

    let verifiedCount = 0;
    let deverifiedCount = 0;
    let removedCount = 0;

    for (const domain of dueDomains) {
        let dnsValid = false;
        try {
            dnsValid = await verifyOrganizationDomainDns(domain, fetch, resolverUrl || undefined);
        } catch (error) {
            console.error(`[VerifyOrganizationDomains] DNS check failed for ${domain.domainName}:`, error);
        }

        if (dnsValid) {
            await db.update(organizationDomains).set({
                verifiedDate: domain.verifiedDate ?? nowIso,
                lastCheckedDate: nowIso,
                jobRunCount: 0,
                nextRunDate,
            }).where(eq(organizationDomains.id, domain.id));
            await ensureSingleOrgPolicyEnabled(db, domain.organizationId, nowIso);
            verifiedCount += 1;
            continue;
        }

        const nextRunCount = Math.min((domain.jobRunCount ?? 0) + 1, 3);
        if (!domain.verifiedDate && nextRunCount >= 3 && domain.creationDate <= removalCutoff) {
            await db.delete(organizationDomains).where(eq(organizationDomains.id, domain.id));
            removedCount += 1;
            continue;
        }

        await db.update(organizationDomains).set({
            verifiedDate: null,
            lastCheckedDate: nowIso,
            jobRunCount: domain.verifiedDate ? 1 : nextRunCount,
            nextRunDate,
        }).where(eq(organizationDomains.id, domain.id));
        if (domain.verifiedDate) deverifiedCount += 1;
    }

    console.log(
        `[VerifyOrganizationDomains] processed=${dueDomains.length} verified=${verifiedCount} deverified=${deverifiedCount} removed=${removedCount}`,
    );
}
