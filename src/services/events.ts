import { drizzle } from 'drizzle-orm/d1';
import { events } from '../db/schema';
import { generateUuid } from './crypto';

export interface EventContext {
    userId?: string;
    organizationId?: string;
    cipherId?: string;
    collectionId?: string;
    actingUserId?: string;
    deviceType?: number;
    ipAddress?: string;
    systemUser?: number;
}

export async function logEvent(
    dbEnv: D1Database,
    type: number,
    context: EventContext,
    date?: string
) {
    const db = drizzle(dbEnv);
    const now = date || new Date().toISOString();

    await db.insert(events).values({
        id: generateUuid(),
        type: type,
        userId: context.userId || null,
        organizationId: context.organizationId || null,
        cipherId: context.cipherId || null,
        collectionId: context.collectionId || null,
        actingUserId: context.actingUserId || null,
        date: now,
        deviceType: context.deviceType || null,
        ipAddress: context.ipAddress || null,
        systemUser: context.systemUser || null,
    }).run();
}
