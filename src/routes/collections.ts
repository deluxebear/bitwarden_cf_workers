/**
 * Bitwarden Workers - Collections 查询路由
 * 仅保留用户的全局集合查询
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, inArray } from 'drizzle-orm';
import { collections, organizationUsers } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { NotFoundError } from '../middleware/error';
import type { Bindings, Variables } from '../types';

const cols = new Hono<{ Bindings: Bindings; Variables: Variables }>();
cols.use('/*', authMiddleware);

/**
 * GET /api/collections
 * 获取用户所属的所有组织下的集合
 */
cols.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');

    // 简单实现：获取用户所在组织，然后获取这些组织的所有集合
    const userOrgs = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.userId, userId), eq(organizationUsers.status, 2))).all();

    const orgIds = userOrgs.map(ou => ou.organizationId);

    let accessibleCols: any[] = [];
    if (orgIds.length > 0) {
        accessibleCols = await db.select().from(collections).where(inArray(collections.organizationId, orgIds)).all();
    }

    return c.json({
        data: accessibleCols.map(col => ({
            id: col.id,
            organizationId: col.organizationId,
            name: col.name,
            externalId: col.externalId,
            object: 'collectionDetails'
        })),
        object: 'list',
        continuationToken: null
    });
});

/**
 * GET /api/collections/:id
 */
cols.get('/:id', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const collectionId = c.req.param('id');

    const col = await db.select().from(collections).where(eq(collections.id, collectionId)).get();
    if (!col) throw new NotFoundError('Collection not found.');

    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, col.organizationId), eq(organizationUsers.userId, userId))).get();

    if (!orgUser || orgUser.status !== 2) throw new NotFoundError('Collection not found.');

    return c.json({
        id: col.id,
        organizationId: col.organizationId,
        name: col.name,
        externalId: col.externalId,
        object: 'collectionDetails',
    });
});

export default cols;
