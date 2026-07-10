import { env, SELF } from 'cloudflare:test';
import { beforeAll, describe, expect, it } from 'vitest';
import { signJwt } from '../src/middleware/auth';

type User = { id: string; token: string };

async function makeUser(id: string): Promise<User> {
    const now = new Date().toISOString();
    const email = `${id}@example.com`;
    const stamp = `stamp-${id}`;
    await env.DB.prepare(`
        INSERT INTO users (id, email, security_stamp, account_revision_date, api_key, creation_date, revision_date)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(id, email, stamp, now, `api-${id}`, now, now).run();
    const token = await signJwt({
        sub: id, email, email_verified: true, name: id, premium: true, sstamp: stamp,
        device: `device-${id}`, scope: ['api'], amr: ['Application'],
    }, env.JWT_SECRET, 3600);
    return { id, token };
}

function call(user: User, path: string, init?: RequestInit) {
    const headers = new Headers(init?.headers);
    headers.set('Authorization', `Bearer ${user.token}`);
    if (init?.body) headers.set('Content-Type', 'application/json');
    return SELF.fetch(`https://example.com/api/tasks${path}`, { ...init, headers });
}

function nextWebSocketMessage(socket: WebSocket): Promise<MessageEvent> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Timed out waiting for push notification')), 2_000);
        socket.addEventListener('message', (event) => {
            clearTimeout(timeout);
            resolve(event);
        }, { once: true });
    });
}

describe('Security Tasks D1 lifecycle', () => {
    let owner: User;
    let editor: User;
    let outsider: User;
    let taskId: string;

    beforeAll(async () => {
        owner = await makeUser('security-task-owner');
        editor = await makeUser('security-task-editor');
        outsider = await makeUser('security-task-outsider');
        const now = new Date().toISOString();
        await env.DB.batch([
            env.DB.prepare(`INSERT INTO organizations
                (id, name, billing_email, use_risk_insights, creation_date, revision_date)
                VALUES ('security-task-org', 'Security Tasks', 'owner@example.com', 1, ?, ?)`
            ).bind(now, now),
            env.DB.prepare(`INSERT INTO organization_users
                (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES ('security-task-owner-membership', 'security-task-org', ?, 'owner@example.com', 2, 0, ?, ?)`
            ).bind(owner.id, now, now),
            env.DB.prepare(`INSERT INTO organization_users
                (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES ('security-task-editor-membership', 'security-task-org', ?, 'editor@example.com', 2, 2, ?, ?)`
            ).bind(editor.id, now, now),
            env.DB.prepare(`INSERT INTO organization_users
                (id, organization_id, user_id, email, status, type, creation_date, revision_date)
                VALUES ('security-task-outsider-membership', 'security-task-org', ?, 'outsider@example.com', 2, 2, ?, ?)`
            ).bind(outsider.id, now, now),
            env.DB.prepare(`INSERT INTO ciphers
                (id, organization_id, type, data, creation_date, revision_date)
                VALUES ('security-task-cipher', 'security-task-org', 1, '{}', ?, ?)`
            ).bind(now, now),
            env.DB.prepare(`INSERT INTO collections
                (id, organization_id, name, creation_date, revision_date)
                VALUES ('security-task-collection', 'security-task-org', 'collection', ?, ?)`
            ).bind(now, now),
            env.DB.prepare(`INSERT INTO collection_ciphers (collection_id, cipher_id)
                VALUES ('security-task-collection', 'security-task-cipher')`),
            env.DB.prepare(`INSERT INTO collection_users
                (collection_id, organization_user_id, read_only)
                VALUES ('security-task-collection', 'security-task-editor-membership', 0)`),
        ]);
    });

    it('creates once for duplicate source events and writes Notification Center records', async () => {
        const body = JSON.stringify({ tasks: [
            { type: 0, cipherId: 'security-task-cipher' },
            { type: 0, cipherId: 'security-task-cipher' },
        ] });
        const response = await call(owner, '/security-task-org/bulk-create', { method: 'POST', body });
        expect(response.status).toBe(200);
        const payload = await response.json<any>();
        taskId = payload.data[0].id;
        expect(new Set(payload.data.map((task: { id: string }) => task.id))).toEqual(new Set([taskId]));

        const replay = await call(owner, '/security-task-org/bulk-create', { method: 'POST', body });
        expect(replay.status).toBe(200);
        const concurrent = await Promise.all(Array.from({ length: 8 }, () =>
            call(owner, '/security-task-org/bulk-create', { method: 'POST', body })));
        expect(concurrent.every((response) => response.status === 200)).toBe(true);
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM security_tasks').first())
            .resolves.toEqual({ count: 1 });
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM notifications WHERE task_id = ?')
            .bind(taskId).first()).resolves.toEqual({ count: 2 });
    });

    it('enforces user, organization and detail authorization', async () => {
        const editorList = await call(editor, '?status=0');
        expect(editorList.status).toBe(200);
        await expect(editorList.json()).resolves.toEqual(expect.objectContaining({
            data: [expect.objectContaining({ id: taskId, status: 0, object: 'securityTask' })],
        }));
        await expect((await call(outsider, '?status=0')).json()).resolves.toEqual(expect.objectContaining({ data: [] }));
        expect((await call(outsider, `/${taskId}`)).status).toBe(404);
        expect((await call(editor, '/organization?organizationId=security-task-org')).status).toBe(403);
        expect((await call(owner, '/organization?organizationId=security-task-org')).status).toBe(200);
        expect((await call(editor, `/${taskId}`)).status).toBe(200);
    });

    it('completes with revision metadata, deletes notifications and reports metrics', async () => {
        await env.DB.prepare(`
            CREATE TRIGGER security_task_atomicity_test
            BEFORE UPDATE OF deleted_date ON notifications
            WHEN NEW.task_id = '${taskId}' AND NEW.deleted_date IS NOT NULL
            BEGIN SELECT RAISE(ABORT, 'forced notification cleanup failure'); END
        `).run();
        expect((await call(editor, `/${taskId}/complete`, { method: 'PATCH' })).status).toBe(500);
        await expect(env.DB.prepare('SELECT status, revision FROM security_tasks WHERE id = ?')
            .bind(taskId).first()).resolves.toEqual({ status: 0, revision: 1 });
        await env.DB.prepare('DROP TRIGGER security_task_atomicity_test').run();

        const completed = await call(editor, `/${taskId}/complete`, { method: 'PATCH' });
        expect(completed.status).toBe(204);
        await expect(env.DB.prepare(`SELECT status, revision, completed_by_user_id, completed_date
            FROM security_tasks WHERE id = ?`).bind(taskId).first()).resolves.toEqual(expect.objectContaining({
            status: 1, revision: 2, completed_by_user_id: editor.id,
            completed_date: expect.any(String),
        }));
        await expect(env.DB.prepare(`SELECT COUNT(*) AS count FROM notifications
            WHERE task_id = ? AND deleted_date IS NOT NULL`).bind(taskId).first()).resolves.toEqual({ count: 2 });

        const metrics = await call(owner, '/security-task-org/metrics');
        expect(metrics.status).toBe(200);
        await expect(metrics.json()).resolves.toEqual({ completedTasks: 1, totalTasks: 1 });

        const now = new Date().toISOString();
        await env.DB.prepare(`INSERT INTO notifications
            (id, user_id, organization_id, priority, global, client_type, title, body, task_id, creation_date, revision_date)
            VALUES ('security-task-residual-notification', ?, 'security-task-org', 0, 0, 0,
              'residual', 'residual', ?, ?, ?)`)
            .bind(editor.id, taskId, now, now).run();
        expect((await call(editor, `/${taskId}/complete`, { method: 'PATCH' })).status).toBe(204);
        await expect(env.DB.prepare(`SELECT deleted_date FROM notifications WHERE id = 'security-task-residual-notification'`)
            .first()).resolves.toEqual({ deleted_date: expect.any(String) });
    });

    it('restricts deletion to administrators and removes task-linked notifications', async () => {
        expect((await call(editor, `/${taskId}`, { method: 'DELETE' })).status).toBe(403);

        const upgrade = await SELF.fetch(`https://example.com/notifications/hub?access_token=${editor.token}`, {
            headers: { Upgrade: 'websocket' },
        });
        expect(upgrade.status).toBe(101);
        const socket = upgrade.webSocket!;
        socket.accept();
        const handshake = nextWebSocketMessage(socket);
        socket.send('{"protocol":"messagepack","version":1}\u001e');
        await handshake;

        const pushed = nextWebSocketMessage(socket);
        const deletion = call(owner, `/${taskId}`, { method: 'DELETE' });
        await pushed;
        // 删除请求尚未返回，但 Push 已到达；此刻持久化状态必须已经提交为不可见。
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM security_tasks WHERE id = ?')
            .bind(taskId).first()).resolves.toEqual({ count: 0 });
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM notifications WHERE task_id = ?')
            .bind(taskId).first()).resolves.toEqual({ count: 0 });
        expect((await deletion).status).toBe(204);
        socket.close(1000, 'test complete');
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM security_tasks WHERE id = ?')
            .bind(taskId).first()).resolves.toEqual({ count: 0 });
        await expect(env.DB.prepare('SELECT COUNT(*) AS count FROM notifications WHERE task_id = ?')
            .bind(taskId).first()).resolves.toEqual({ count: 0 });
    });
});
