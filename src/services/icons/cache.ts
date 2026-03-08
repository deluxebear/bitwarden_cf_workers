import type { IconCacheConfig, CachedIconMeta, FetchedIcon } from './types';

export interface IconCacheKeys {
    meta: string;
    data: string;
}

export function buildCacheKeys(mappedDomain: string): IconCacheKeys {
    return {
        meta: `icon:v1:${mappedDomain}:meta`,
        data: `icon:v1:${mappedDomain}:data`,
    };
}

export async function readCachedMeta(kv: KVNamespace | undefined, keys: IconCacheKeys): Promise<CachedIconMeta | null> {
    if (!kv) {
        return null;
    }
    const raw = await kv.get(keys.meta);
    if (!raw) {
        return null;
    }
    try {
        const parsed = JSON.parse(raw) as CachedIconMeta;
        if (parsed.version !== 1) {
            return null;
        }
        return parsed;
    } catch {
        return null;
    }
}

export async function readCachedIcon(kv: KVNamespace | undefined, keys: IconCacheKeys): Promise<FetchedIcon | null> {
    if (!kv) {
        return null;
    }
    const meta = await readCachedMeta(kv, keys);
    if (!meta || meta.status !== 'ok' || !meta.contentType || !meta.dataKey) {
        return null;
    }

    const bytes = await kv.get(meta.dataKey, { type: 'arrayBuffer' });
    if (!bytes) {
        return null;
    }

    return {
        image: bytes,
        contentType: meta.contentType,
    };
}

export async function readNegativeCache(kv: KVNamespace | undefined, keys: IconCacheKeys): Promise<boolean> {
    if (!kv) {
        return false;
    }
    const meta = await readCachedMeta(kv, keys);
    return !!meta && meta.status === 'not_found' && meta.expiresAt > Date.now();
}

export async function writeSuccessCache(
    kv: KVNamespace | undefined,
    keys: IconCacheKeys,
    mappedDomain: string,
    icon: FetchedIcon,
    config: IconCacheConfig,
): Promise<void> {
    if (!kv) {
        return;
    }
    const now = Date.now();
    const meta: CachedIconMeta = {
        version: 1,
        status: 'ok',
        domain: mappedDomain,
        contentType: icon.contentType,
        dataKey: keys.data,
        fetchedAt: now,
        expiresAt: 0,
    };

    await Promise.all([
        kv.put(keys.data, icon.image),
        kv.put(keys.meta, JSON.stringify(meta)),
    ]);
}

export async function writeNegativeCache(
    kv: KVNamespace | undefined,
    keys: IconCacheKeys,
    mappedDomain: string,
    config: IconCacheConfig,
): Promise<void> {
    if (!kv) {
        return;
    }
    const now = Date.now();
    const expiresAt = now + config.negativeTtlSeconds * 1000;
    const meta: CachedIconMeta = {
        version: 1,
        status: 'not_found',
        domain: mappedDomain,
        contentType: null,
        dataKey: null,
        fetchedAt: now,
        expiresAt,
    };
    await kv.put(keys.meta, JSON.stringify(meta), { expirationTtl: config.negativeTtlSeconds });
}
