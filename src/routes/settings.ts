/**
 * Bitwarden Workers - Settings 路由
 * 对应原始 Api/Controllers/SettingsController.cs
 * 域名规则：GET/PUT /api/settings/domains
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { NotFoundError } from '../middleware/error';
import type { Bindings, Variables } from '../types';
import { pushSyncUser } from '../services/push-notification';
import { PushType } from '../types/push-notification';

const settings = new Hono<{ Bindings: Bindings; Variables: Variables }>();

settings.use('/*', authMiddleware);

// 与 sync 一致的全局等价域名（Type 与官方 GlobalEquivalentDomainsType 对应）
const GLOBAL_EQUIVALENT_DOMAINS: { type: number; domains: string[] }[] = [
    { type: 0, domains: ['youtube.com', 'google.com', 'gmail.com'] },
    { type: 1, domains: ['apple.com', 'icloud.com'] },
    { type: 2, domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.co.jp', 'amazon.in'] },
    { type: 3, domains: ['live.com', 'microsoft.com', 'microsoftonline.com', 'outlook.com', 'hotmail.com'] },
    { type: 4, domains: ['steam.com', 'steampowered.com', 'steamcommunity.com', 'steamgames.com'] },
];

/**
 * 构建 DomainsResponseModel 兼容的 JSON（PascalCase 供客户端 BaseResponse 解析）
 */
function toDomainsResponse(
    equivalentDomains: string[][] | null,
    excludedGlobalTypes: number[],
    excluded: boolean,
): { EquivalentDomains: string[][] | null; GlobalEquivalentDomains: { Type: number; Domains: string[]; Excluded: boolean }[]; object: string } {
    const globalEquivalentDomains = GLOBAL_EQUIVALENT_DOMAINS.map((g) => ({
        Type: g.type,
        Domains: g.domains,
        Excluded: excluded && excludedGlobalTypes.includes(g.type),
    }));
    return {
        EquivalentDomains: equivalentDomains ?? null,
        GlobalEquivalentDomains: globalEquivalentDomains,
        object: 'domains',
    };
}

/**
 * GET /api/settings/domains
 * 对应 SettingsController.GetDomains
 * 查询参数 excluded 默认为 true：返回全部全局域名，Excluded 标记用户已排除的项
 */
settings.get('/domains', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const excluded = c.req.query('excluded') !== 'false';

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    let equivalentDomains: string[][] | null = null;
    if (user.equivalentDomains) {
        try {
            equivalentDomains = JSON.parse(user.equivalentDomains) as string[][];
        } catch {
            equivalentDomains = null;
        }
    }

    let excludedGlobalTypes: number[] = [];
    if (user.excludedGlobalEquivalentDomains) {
        try {
            excludedGlobalTypes = JSON.parse(user.excludedGlobalEquivalentDomains) as number[];
        } catch {
            excludedGlobalTypes = [];
        }
    }

    return c.json(toDomainsResponse(equivalentDomains, excludedGlobalTypes, excluded));
});

/**
 * PUT /api/settings/domains
 * 对应 SettingsController.PutDomains
 */
settings.put('/domains', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        EquivalentDomains?: string[][];
        ExcludedGlobalEquivalentDomains?: number[];
        equivalentDomains?: string[][];
        excludedGlobalEquivalentDomains?: number[];
    }>().catch(() => ({}));

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const equivalentDomains = body.EquivalentDomains ?? body.equivalentDomains;
    const excludedGlobal = body.ExcludedGlobalEquivalentDomains ?? body.excludedGlobalEquivalentDomains;
    const equivalentDomainsJson = equivalentDomains != null ? JSON.stringify(equivalentDomains) : null;
    const excludedGlobalJson = excludedGlobal != null ? JSON.stringify(excludedGlobal) : null;

    const now = new Date().toISOString();
    await db.update(users).set({
        equivalentDomains: equivalentDomainsJson,
        excludedGlobalEquivalentDomains: excludedGlobalJson,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const updated = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!updated) throw new NotFoundError('User not found.');

    let resEquivalentDomains: string[][] | null = null;
    if (updated.equivalentDomains) {
        try {
            resEquivalentDomains = JSON.parse(updated.equivalentDomains) as string[][];
        } catch {
            resEquivalentDomains = null;
        }
    }
    let resExcludedTypes: number[] = [];
    if (updated.excludedGlobalEquivalentDomains) {
        try {
            resExcludedTypes = JSON.parse(updated.excludedGlobalEquivalentDomains) as number[];
        } catch {
            resExcludedTypes = [];
        }
    }

    const contextId = c.get('jwtPayload')?.device ?? null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncSettings, userId, contextId));

    return c.json(toDomainsResponse(resEquivalentDomains, resExcludedTypes, true));
});

/**
 * POST /api/settings/domains (deprecated, 同 PUT)
 */
settings.post('/domains', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json<{
        EquivalentDomains?: string[][];
        ExcludedGlobalEquivalentDomains?: number[];
        equivalentDomains?: string[][];
        excludedGlobalEquivalentDomains?: number[];
    }>().catch(() => ({}));

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    const equivalentDomains = body.EquivalentDomains ?? body.equivalentDomains;
    const excludedGlobal = body.ExcludedGlobalEquivalentDomains ?? body.excludedGlobalEquivalentDomains;
    const equivalentDomainsJson = equivalentDomains != null ? JSON.stringify(equivalentDomains) : null;
    const excludedGlobalJson = excludedGlobal != null ? JSON.stringify(excludedGlobal) : null;

    const now = new Date().toISOString();
    await db.update(users).set({
        equivalentDomains: equivalentDomainsJson,
        excludedGlobalEquivalentDomains: excludedGlobalJson,
        revisionDate: now,
        accountRevisionDate: now,
    }).where(eq(users.id, userId));

    const updated = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!updated) throw new NotFoundError('User not found.');

    let resEquivalentDomains: string[][] | null = null;
    if (updated.equivalentDomains) {
        try {
            resEquivalentDomains = JSON.parse(updated.equivalentDomains) as string[][];
        } catch {
            resEquivalentDomains = null;
        }
    }
    let resExcludedTypes: number[] = [];
    if (updated.excludedGlobalEquivalentDomains) {
        try {
            resExcludedTypes = JSON.parse(updated.excludedGlobalEquivalentDomains) as number[];
        } catch {
            resExcludedTypes = [];
        }
    }

    const contextId = c.get('jwtPayload')?.device ?? null;
    c.executionCtx.waitUntil(pushSyncUser(c.env, PushType.SyncSettings, userId, contextId));

    return c.json(toDomainsResponse(resEquivalentDomains, resExcludedTypes, true));
});

export default settings;
