/** Bitwarden SecurityTaskController compatible routes. */
import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { authMiddleware } from '../middleware/auth';
import {
    bulkCreateSecurityTasks,
    canAdminSecurityTasks,
    canEditTaskCipher,
    completeSecurityTask,
    deleteSecurityTask,
    getSecurityTask,
    listTasksForOrganization,
    listTasksForUser,
    refreshSecurityTaskUsers,
    toSecurityTaskResponse,
} from '../services/security-tasks';
import type { Bindings, Variables } from '../types';

const tasks = new Hono<{ Bindings: Bindings; Variables: Variables }>();
tasks.use('/*', authMiddleware);

function parseStatus(value: string | undefined): number | null {
    if (value === undefined || value === '') return null;
    const status = Number(value);
    if (status !== 0 && status !== 1) throw new HTTPException(400, { message: 'Invalid task status.' });
    return status;
}

function listResponse(rows: Awaited<ReturnType<typeof listTasksForUser>>) {
    return { data: rows.map(toSecurityTaskResponse), object: 'list', continuationToken: null };
}

tasks.get('/', async (c) => {
    const rows = await listTasksForUser(c.env.DB, c.get('userId'), parseStatus(c.req.query('status')));
    return c.json(listResponse(rows));
});

tasks.get('/organization', async (c) => {
    const organizationId = c.req.query('organizationId');
    if (!organizationId) throw new HTTPException(400, { message: 'Organization id is required.' });
    if (!await canAdminSecurityTasks(c.env.DB, c.get('userId'), organizationId)) {
        throw new HTTPException(403, { message: 'Forbidden.' });
    }
    return c.json(listResponse(await listTasksForOrganization(c.env.DB, organizationId, parseStatus(c.req.query('status')))));
});

tasks.get('/:organizationId/metrics', async (c) => {
    const organizationId = c.req.param('organizationId');
    if (!await canAdminSecurityTasks(c.env.DB, c.get('userId'), organizationId)) {
        throw new HTTPException(403, { message: 'Forbidden.' });
    }
    const row = await c.env.DB.prepare(`
        SELECT COUNT(*) AS totalTasks,
          COALESCE(SUM(CASE WHEN status = 1 THEN 1 ELSE 0 END), 0) AS completedTasks
        FROM security_tasks WHERE organization_id = ?
    `).bind(organizationId).first<{ totalTasks: number; completedTasks: number }>();
    return c.json({ completedTasks: row?.completedTasks ?? 0, totalTasks: row?.totalTasks ?? 0 });
});

tasks.post('/:organizationId/bulk-create', async (c) => {
    const organizationId = c.req.param('organizationId');
    const userId = c.get('userId');
    if (!await canAdminSecurityTasks(c.env.DB, userId, organizationId)) {
        throw new HTTPException(403, { message: 'Forbidden.' });
    }
    const body = await c.req.json().catch(() => null) as {
        tasks?: Array<{ type?: unknown; cipherId?: unknown }>;
    } | null;
    if (!body?.tasks?.length) throw new HTTPException(400, { message: 'No tasks provided.' });
    const requested = body.tasks.map((task) => ({
        type: Number(task.type),
        cipherId: typeof task.cipherId === 'string' ? task.cipherId : null,
    }));
    for (const task of requested) {
        if (!await canEditTaskCipher(c.env.DB, userId, organizationId, task.cipherId)) {
            throw new HTTPException(403, { message: 'Forbidden.' });
        }
    }
    try {
        return c.json(listResponse(await bulkCreateSecurityTasks(c.env, organizationId, requested)));
    } catch (error) {
        if ((error as Error).message.startsWith('INVALID_SECURITY_TASK')) {
            throw new HTTPException(400, { message: 'Invalid security task.' });
        }
        throw error;
    }
});

// 详情与删除为 Workers 管理扩展；官方客户端使用列表、完成和 bulk-create。
tasks.get('/:taskId', async (c) => {
    const task = await getSecurityTask(c.env.DB, c.req.param('taskId'));
    if (!task || !await canEditTaskCipher(c.env.DB, c.get('userId'), task.organization_id, task.cipher_id)) {
        throw new HTTPException(404, { message: 'Task not found.' });
    }
    return c.json(toSecurityTaskResponse(task));
});

tasks.patch('/:taskId/complete', async (c) => {
    const task = await getSecurityTask(c.env.DB, c.req.param('taskId'));
    const userId = c.get('userId');
    if (!task || !await canEditTaskCipher(c.env.DB, userId, task.organization_id, task.cipher_id)) {
        throw new HTTPException(404, { message: 'Task not found.' });
    }
    if (task.status === 1) {
        // 前一次更新可能已提交但实时推送失败；幂等重试必须重新投递 refresh。
        await refreshSecurityTaskUsers(c.env, task.id);
        return c.body(null, 204);
    }
    try {
        await completeSecurityTask(c.env, task, userId);
    } catch (error) {
        if ((error as Error).message === 'SECURITY_TASK_CONFLICT') {
            throw new HTTPException(409, { message: 'Task was modified.' });
        }
        throw error;
    }
    return c.body(null, 204);
});

tasks.delete('/:taskId', async (c) => {
    const task = await getSecurityTask(c.env.DB, c.req.param('taskId'));
    if (!task) throw new HTTPException(404, { message: 'Task not found.' });
    if (!await canAdminSecurityTasks(c.env.DB, c.get('userId'), task.organization_id)) {
        throw new HTTPException(403, { message: 'Forbidden.' });
    }
    try {
        await deleteSecurityTask(c.env, task);
    } catch (error) {
        if ((error as Error).message === 'SECURITY_TASK_CONFLICT') {
            throw new HTTPException(409, { message: 'Task was modified.' });
        }
        throw error;
    }
    return c.body(null, 204);
});

export default tasks;
