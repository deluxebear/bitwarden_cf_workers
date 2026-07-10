import type { Bindings } from '../types';
import { generateUuid } from './crypto';
import { pushNotification } from './push-notification';
import { PushType } from '../types/push-notification';

export const SecurityTaskStatus = { Pending: 0, Completed: 1 } as const;
export const SecurityTaskType = { UpdateAtRiskCredential: 0 } as const;

export type SecurityTaskRow = {
    id: string;
    organization_id: string;
    cipher_id: string | null;
    type: number;
    status: number;
    revision: number;
    completed_by_user_id: string | null;
    completed_date: string | null;
    creation_date: string;
    revision_date: string;
};

type Membership = { id: string; type: number; permissions: string | null };
type TaskCreate = { type: number; cipherId: string | null };

function accessReports(permissions: string | null): boolean {
    if (!permissions) return false;
    try {
        const value = JSON.parse(permissions) as Record<string, unknown>;
        return value.accessReports === true || value.AccessReports === true;
    } catch {
        return false;
    }
}

export function toSecurityTaskResponse(row: SecurityTaskRow) {
    return {
        id: row.id,
        organizationId: row.organization_id,
        cipherId: row.cipher_id,
        type: row.type,
        status: row.status,
        creationDate: row.creation_date,
        revisionDate: row.revision_date,
        object: 'securityTask',
    };
}

async function membership(db: D1Database, userId: string, organizationId: string): Promise<Membership | null> {
    return await db.prepare(`
        SELECT id, type, permissions FROM organization_users
        WHERE user_id = ? AND organization_id = ? AND status = 2
    `).bind(userId, organizationId).first<Membership>();
}

function isTaskAdmin(member: Membership): boolean {
    return member.type === 0 || member.type === 1 || (member.type === 4 && accessReports(member.permissions));
}

export async function canAdminSecurityTasks(db: D1Database, userId: string, organizationId: string): Promise<boolean> {
    const member = await membership(db, userId, organizationId);
    return member !== null && isTaskAdmin(member);
}

export async function canEditTaskCipher(
    db: D1Database,
    userId: string,
    organizationId: string,
    cipherId: string | null,
): Promise<boolean> {
    if (!cipherId) return false;
    const member = await membership(db, userId, organizationId);
    if (!member) return false;
    if (isTaskAdmin(member)) {
        const cipher = await db.prepare('SELECT id FROM ciphers WHERE id = ? AND organization_id = ?')
            .bind(cipherId, organizationId).first();
        return cipher !== null;
    }

    const access = await db.prepare(`
        SELECT 1 AS allowed
        FROM collection_ciphers cc
        WHERE cc.cipher_id = ? AND (
            EXISTS (
                SELECT 1 FROM collection_users cu
                WHERE cu.collection_id = cc.collection_id
                  AND cu.organization_user_id = ? AND COALESCE(cu.read_only, 0) = 0
            ) OR EXISTS (
                SELECT 1 FROM collection_groups cg
                JOIN group_users gu ON gu.group_id = cg.group_id
                WHERE cg.collection_id = cc.collection_id
                  AND gu.organization_user_id = ? AND COALESCE(cg.read_only, 0) = 0
            )
        ) LIMIT 1
    `).bind(cipherId, member.id, member.id).first();
    return access !== null;
}

export async function listTasksForOrganization(
    db: D1Database,
    organizationId: string,
    status: number | null,
): Promise<SecurityTaskRow[]> {
    const query = status === null
        ? db.prepare('SELECT * FROM security_tasks WHERE organization_id = ? ORDER BY creation_date DESC').bind(organizationId)
        : db.prepare('SELECT * FROM security_tasks WHERE organization_id = ? AND status = ? ORDER BY creation_date DESC').bind(organizationId, status);
    return (await query.all<SecurityTaskRow>()).results;
}

export async function listTasksForUser(
    db: D1Database,
    userId: string,
    status: number | null,
): Promise<SecurityTaskRow[]> {
    const rows = (await db.prepare(`
        SELECT st.* FROM security_tasks st
        JOIN organization_users ou ON ou.organization_id = st.organization_id
          AND ou.user_id = ? AND ou.status = 2
        WHERE (? IS NULL OR st.status = ?)
        ORDER BY st.creation_date DESC
    `).bind(userId, status, status).all<SecurityTaskRow>()).results;

    const permitted: SecurityTaskRow[] = [];
    for (const row of rows) {
        if (await canEditTaskCipher(db, userId, row.organization_id, row.cipher_id)) permitted.push(row);
    }
    return permitted;
}

export async function getSecurityTask(db: D1Database, id: string): Promise<SecurityTaskRow | null> {
    return await db.prepare('SELECT * FROM security_tasks WHERE id = ?').bind(id).first<SecurityTaskRow>();
}

async function notificationUserIds(db: D1Database, organizationId: string, cipherId: string): Promise<string[]> {
    const rows = (await db.prepare(`
        SELECT DISTINCT ou.user_id AS user_id
        FROM organization_users ou
        WHERE ou.organization_id = ? AND ou.status = 2 AND ou.user_id IS NOT NULL AND (
            ou.type IN (0, 1) OR
            (ou.type = 4 AND (
                json_extract(COALESCE(ou.permissions, '{}'), '$.accessReports') = 1 OR
                json_extract(COALESCE(ou.permissions, '{}'), '$.AccessReports') = 1
            )) OR EXISTS (
                SELECT 1 FROM collection_users cu
                JOIN collection_ciphers cc ON cc.collection_id = cu.collection_id
                WHERE cu.organization_user_id = ou.id AND cc.cipher_id = ? AND COALESCE(cu.read_only, 0) = 0
            ) OR EXISTS (
                SELECT 1 FROM group_users gu
                JOIN collection_groups cg ON cg.group_id = gu.group_id
                JOIN collection_ciphers cc ON cc.collection_id = cg.collection_id
                WHERE gu.organization_user_id = ou.id AND cc.cipher_id = ? AND COALESCE(cg.read_only, 0) = 0
            )
        )
    `).bind(organizationId, cipherId, cipherId).all<{ user_id: string }>()).results;
    return rows.map((row) => row.user_id);
}

async function createNotifications(env: Bindings, tasks: SecurityTaskRow[]): Promise<void> {
    const pushedUsers = new Set<string>();
    for (const task of tasks) {
        if (!task.cipher_id) continue;
        const userIds = await notificationUserIds(env.DB, task.organization_id, task.cipher_id);
        for (const userId of userIds) {
            const now = new Date().toISOString();
            await env.DB.prepare(`
                INSERT OR IGNORE INTO notifications
                    (id, user_id, organization_id, priority, global, client_type, title, body, task_id, creation_date, revision_date)
                VALUES (?, ?, ?, 0, 0, 0, ?, ?, ?, ?, ?)
            `).bind(generateUuid(), userId, task.organization_id, 'Security task',
                'An at-risk credential requires an update.', task.id, now, now).run();
            pushedUsers.add(userId);
        }
    }
    for (const userId of pushedUsers) {
        await pushNotification(env, 'user', userId, PushType.RefreshSecurityTasks, null, null);
    }
}

export async function bulkCreateSecurityTasks(
    env: Bindings,
    organizationId: string,
    requests: TaskCreate[],
): Promise<SecurityTaskRow[]> {
    const results: SecurityTaskRow[] = [];
    for (const request of requests) {
        if (request.type !== SecurityTaskType.UpdateAtRiskCredential || !request.cipherId) {
            throw new Error('INVALID_SECURITY_TASK');
        }
        const now = new Date().toISOString();
        await env.DB.prepare(`
            INSERT OR IGNORE INTO security_tasks
                (id, organization_id, cipher_id, type, status, revision, creation_date, revision_date)
            SELECT ?, ?, ?, ?, 0, 1, ?, ?
            WHERE EXISTS (SELECT 1 FROM ciphers WHERE id = ? AND organization_id = ?)
        `).bind(generateUuid(), organizationId, request.cipherId, request.type, now, now,
            request.cipherId, organizationId).run();
        const row = await env.DB.prepare(`
            SELECT * FROM security_tasks
            WHERE organization_id = ? AND cipher_id = ? AND status = 0
        `).bind(organizationId, request.cipherId).first<SecurityTaskRow>();
        if (!row) throw new Error('INVALID_SECURITY_TASK_CIPHER');
        results.push(row);
    }
    const unique = [...new Map(results.map((task) => [task.id, task])).values()];
    await createNotifications(env, unique);
    return unique;
}

export async function refreshSecurityTaskUsers(env: Bindings, taskId: string): Promise<void> {
    const affected = (await env.DB.prepare('SELECT DISTINCT user_id FROM notifications WHERE task_id = ?')
        .bind(taskId).all<{ user_id: string }>()).results;
    const now = new Date().toISOString();
    await env.DB.prepare(`
        UPDATE notifications SET deleted_date = ?, revision_date = ?
        WHERE task_id = ? AND deleted_date IS NULL
          AND EXISTS (SELECT 1 FROM security_tasks WHERE id = ? AND status = 1)
    `).bind(now, now, taskId, taskId).run();
    for (const row of affected) {
        await pushNotification(env, 'user', row.user_id, PushType.RefreshSecurityTasks, null, null);
    }
}

export async function completeSecurityTask(env: Bindings, task: SecurityTaskRow, userId: string): Promise<void> {
    const now = new Date().toISOString();
    const affected = (await env.DB.prepare(`
        SELECT DISTINCT user_id FROM notifications WHERE task_id = ? AND deleted_date IS NULL
    `).bind(task.id).all<{ user_id: string }>()).results;
    const [result] = await env.DB.batch([
        env.DB.prepare(`
            UPDATE security_tasks SET status = 1, revision = revision + 1,
              completed_by_user_id = ?, completed_date = ?, revision_date = ?
            WHERE id = ? AND revision = ? AND status = 0
        `).bind(userId, now, now, task.id, task.revision),
        env.DB.prepare(`
            UPDATE notifications SET deleted_date = ?, revision_date = ?
            WHERE task_id = ? AND deleted_date IS NULL
              AND EXISTS (SELECT 1 FROM security_tasks WHERE id = ? AND status = 1)
        `).bind(now, now, task.id, task.id),
    ]);
    if ((result.meta.changes ?? 0) !== 1) throw new Error('SECURITY_TASK_CONFLICT');

    for (const row of affected) {
        await pushNotification(env, 'user', row.user_id, PushType.RefreshSecurityTasks, null, null);
    }
}

export async function deleteSecurityTask(env: Bindings, task: SecurityTaskRow): Promise<void> {
    const affected = (await env.DB.prepare('SELECT DISTINCT user_id FROM notifications WHERE task_id = ?')
        .bind(task.id).all<{ user_id: string }>()).results;
    const [result] = await env.DB.batch([
        env.DB.prepare('DELETE FROM security_tasks WHERE id = ? AND revision = ?')
            .bind(task.id, task.revision),
        env.DB.prepare(`
            DELETE FROM notifications
            WHERE task_id = ?
              AND NOT EXISTS (SELECT 1 FROM security_tasks WHERE id = ?)
        `).bind(task.id, task.id),
    ]);
    if ((result.meta.changes ?? 0) !== 1) throw new Error('SECURITY_TASK_CONFLICT');

    // 客户端收到 refresh 时，任务和关联通知必须已经原子提交为不可见。
    for (const row of affected) {
        await pushNotification(env, 'user', row.user_id, PushType.RefreshSecurityTasks, null, null);
    }
}
