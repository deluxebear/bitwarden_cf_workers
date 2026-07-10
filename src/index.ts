/**
 * Bitwarden Workers - 主入口
 * Cloudflare Workers + Hono 应用
 *
 * 路由结构：
 * /identity/* - 认证（Prelogin、Register、Token）
 * /api/accounts/* - 用户账户管理
 * /api/ciphers/* - 密码条目 CRUD
 * /api/folders/* - 文件夹 CRUD
 * /api/sends/* - Send 安全分享
 * /api/sync - 全量同步
 * /api/config - 服务端配置
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { errorHandler, globalErrorHandler } from './middleware/error';
import { debugMiddleware } from './middleware/debug';
import identityRoutes, { handleOidcCallback } from './routes/identity';
import accountsRoutes from './routes/accounts';
import accountBillingRoutes from './routes/account-billing';
import billingRoutes from './routes/billing';
import ciphersRoutes from './routes/ciphers';
import foldersRoutes from './routes/folders';
import sendsRoutes from './routes/sends';
import twoFactorRoutes from './routes/two-factor';
import organizationLicensesRoutes from './routes/organization-licenses';
import organizationInviteLinksRoutes from './routes/organization-invite-links';
import organizationDomainsRoutes from './routes/organization-domains';
import organizationTwoFactorRoutes from './routes/organization-two-factor';
import organizationAuthRequestsRoutes from './routes/organization-auth-requests';
import organizationsRoutes from './routes/organizations';
import usersRoutes from './routes/users';
import tasksRoutes from './routes/tasks';
import pushRoutes from './routes/push';
import notificationsRoutes, { notificationSendRoutes } from './routes/notifications';
import collectionsRoutes from './routes/collections';
import eventsRoutes from './routes/events';
import syncRoutes from './routes/sync';
import configRoutes from './routes/config';
import devicesRoutes from './routes/devices';
import authRequestsRoutes from './routes/auth-requests';
import webauthnRoutes from './routes/webauthn';
import hubRoutes from './routes/hub';
import emergencyAccessRoutes from './routes/emergency-access';
import settingsRoutes from './routes/settings';
import reportsRoutes from './routes/reports';
import iconsRoutes from './routes/icons';
import plansRoutes from './routes/plans';
import setupIntentRoutes from './routes/setup-intent';
import systemAdminRoutes from './routes/system-admin';
import type { Bindings, Variables } from './types';
import { verifyAttachmentDownloadToken } from './services/attachment-token';
import { handleWebPushQueue, type WebPushQueueMessage } from './services/push-notification';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 全局错误处理（捕获子路由异常，防止 Hono 返回默认纯文本 500）
app.onError(globalErrorHandler);

// 全局中间件

// 规范化尾部斜杠：Hono 的 route() 不匹配带尾部 / 的子路由请求，
// 这里在路由匹配前内部重写 URL，保留原始 HTTP 方法和请求体。
app.use('*', async (c, next) => {
    const url = new URL(c.req.url);
    if (url.pathname !== '/' && url.pathname.endsWith('/')) {
        url.pathname = url.pathname.replace(/\/+$/, '');
        const newReq = new Request(url.toString(), c.req.raw);
        return app.fetch(newReq, c.env, c.executionCtx);
    }
    await next();
});

app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Device-Type', 'Bitwarden-Client-Name', 'Bitwarden-Client-Version'],
    exposeHeaders: ['Content-Length', 'X-Request-Id'],
    maxAge: 86400,
}));
app.use('*', debugMiddleware);
app.use('*', errorHandler);

type HealthCheckResult = { ok: boolean; durationMs: number };

async function checkWithTimeout(operation: () => Promise<unknown>, timeoutMs = 1_500): Promise<HealthCheckResult> {
    const startedAt = performance.now();
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
        await Promise.race([
            operation(),
            new Promise<never>((_, reject) => {
                timeout = setTimeout(() => reject(new Error('health check timeout')), timeoutMs);
            }),
        ]);
        return { ok: true, durationMs: Math.max(0, Math.round(performance.now() - startedAt)) };
    } catch {
        return { ok: false, durationMs: Math.max(0, Math.round(performance.now() - startedAt)) };
    } finally {
        if (timeout !== undefined) clearTimeout(timeout);
    }
}

function readDeploymentVersion(env: Bindings): { version: string; deploymentId: string | null; deployedAt: string | null } {
    const explicitVersion = typeof env.WORKER_VERSION === 'string' && env.WORKER_VERSION.trim()
        ? env.WORKER_VERSION.trim()
        : null;
    const metadata = typeof env.CF_VERSION_METADATA === 'object' && env.CF_VERSION_METADATA !== null
        ? env.CF_VERSION_METADATA as Record<string, unknown>
        : null;
    const deploymentId = typeof metadata?.id === 'string' ? metadata.id : null;
    const tag = typeof metadata?.tag === 'string' && metadata.tag.trim() ? metadata.tag.trim() : null;
    const deployedAt = typeof metadata?.timestamp === 'string' ? metadata.timestamp : null;

    return { version: explicitVersion ?? tag ?? deploymentId ?? 'unknown', deploymentId, deployedAt };
}

function constantTimeEqual(left: string, right: string): boolean {
    const encoder = new TextEncoder();
    const leftBytes = encoder.encode(left);
    const rightBytes = encoder.encode(right);
    const length = Math.max(leftBytes.length, rightBytes.length);
    let difference = leftBytes.length ^ rightBytes.length;
    for (let index = 0; index < length; index += 1) {
        difference |= (leftBytes[index] ?? 0) ^ (rightBytes[index] ?? 0);
    }
    return difference === 0;
}

// 轻量存活探针不访问外部资源，可用于高频平台健康检查。
app.get('/', (c) => c.json({ status: 'ok', service: 'bitwarden-workers' }));
app.get('/healthz', (c) => c.json({ status: 'ok' }));

// 深度探针只读取固定哨兵键，不泄露资源 ID 或底层错误。
app.get('/healthz/extended', async (c) => {
    const expectedToken = c.env.HEALTH_CHECK_TOKEN?.trim();
    const authorization = c.req.header('Authorization');
    const suppliedToken = authorization?.startsWith('Bearer ') ? authorization.slice(7) : '';
    // 未配置或鉴权失败均返回 404，避免公开深度探针及其资源消耗面。
    if (!expectedToken || !constantTimeEqual(suppliedToken, expectedToken)) {
        return c.json({ message: 'Not found' }, 404);
    }
    const [d1, kv, r2, durableObject] = await Promise.all([
        checkWithTimeout(() => c.env.DB.prepare('SELECT 1').first()),
        checkWithTimeout(() => c.env.ICONS_CACHE.get('__healthcheck__')),
        checkWithTimeout(() => c.env.ATTACHMENTS.head('__healthcheck__')),
        checkWithTimeout(async () => {
            const id = c.env.NOTIFICATION_HUB.idFromName('__healthcheck__');
            const response = await c.env.NOTIFICATION_HUB.get(id).fetch('https://health.internal/healthz');
            if (response.status !== 404 && !response.ok) throw new Error('durable object unavailable');
        }),
    ]);
    const checks = { d1, kv, r2, durableObject };
    const healthy = Object.values(checks).every((check) => check.ok);
    return c.json({ status: healthy ? 'ok' : 'degraded', checks }, healthy ? 200 : 503);
});

// Info 端点 - 对应 Api/Controllers/InfoController.cs
app.get('/alive', (c) => c.text(new Date().toISOString()));
app.get('/now', (c) => c.text(new Date().toISOString()));
app.get('/version', (c) => c.json(readDeploymentVersion(c.env)));

// 挂载路由
app.on(['GET', 'POST'], '/oidc-signin', handleOidcCallback);
app.route('/identity', identityRoutes);
app.route('/api/accounts', accountsRoutes);
app.route('/api/account', accountBillingRoutes);

// 上游式附件匿名下载入口。必须注册在 /api/ciphers 子路由之前，否则会被认证中间件拦截。
app.get('/api/ciphers/attachment/download', async (c) => {
    const token = c.req.query('token');
    if (!token) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }
    const tokenPayload = await verifyAttachmentDownloadToken(token, c.env.JWT_SECRET);
    if (!tokenPayload) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }

    const file = await c.env.ATTACHMENTS.get(`${tokenPayload.cipherId}/${tokenPayload.attachmentId}`);
    if (!file) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }

    const headers = new Headers();
    headers.set('Content-Type', file.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Length', file.size.toString());
    headers.set('Cache-Control', 'private, max-age=0, no-store');

    return new Response(file.body, { headers });
});

app.route('/api/ciphers', ciphersRoutes);
app.route('/api/folders', foldersRoutes);
app.route('/api/sends', sendsRoutes);
app.route('/api/two-factor', twoFactorRoutes);
app.route('/api/organizations', organizationInviteLinksRoutes);
app.route('/api/organizations', organizationDomainsRoutes);
app.route('/api/organizations', organizationTwoFactorRoutes);
app.route('/api/organizations', organizationAuthRequestsRoutes);
app.route('/api/organizations', organizationsRoutes);
app.route('/api/users', usersRoutes);
app.route('/api/tasks', tasksRoutes);
app.route('/api/push', pushRoutes);
app.route('/api/notifications', notificationsRoutes);
app.route('/api/collections', collectionsRoutes);
app.route('/api/events', eventsRoutes);
app.route('/events', eventsRoutes);
app.route('/api/sync', syncRoutes);
app.route('/api/config', configRoutes);
app.route('/api/devices', devicesRoutes);
app.route('/api/auth-requests', authRequestsRoutes);
app.route('/api/webauthn', webauthnRoutes);
app.route('/api/emergency-access', emergencyAccessRoutes);
app.route('/api/settings', settingsRoutes);
app.route('/api/reports', reportsRoutes);
app.route('/api/plans', plansRoutes);
app.route('/api/billing', billingRoutes);
app.route('/api/setup-intent', setupIntentRoutes);
app.route('/api/admin', systemAdminRoutes);
app.route('/admin', systemAdminRoutes);
app.route('/icons', iconsRoutes);
app.route('/', iconsRoutes);
app.route('/', notificationSendRoutes);

// 自建组织 License 相关端点
// 官方 Web 客户端调用的是 "/organizations/licenses/self-hosted"
// 但 Workers 里其它路由都在 "/api" 下，所以这里同时挂载两条，保证两种路径都兼容。
app.route('/organizations/licenses', organizationLicensesRoutes);
app.route('/api/organizations/licenses', organizationLicensesRoutes);
app.route('/organizations', organizationInviteLinksRoutes);
app.route('/organizations', organizationDomainsRoutes);
app.route('/organizations', organizationTwoFactorRoutes);
app.route('/organizations', organizationAuthRequestsRoutes);
app.route('/organizations', organizationsRoutes);

// 附件文件下载（公开端点，必须携带短期签名 token）
app.get('/attachments/:cipherId/:attachmentId', async (c) => {
    const cipherId = c.req.param('cipherId');
    const attachmentId = c.req.param('attachmentId');
    const token = c.req.query('token');
    if (!token) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }
    const tokenPayload = await verifyAttachmentDownloadToken(token, c.env.JWT_SECRET);
    if (!tokenPayload || tokenPayload.cipherId !== cipherId || tokenPayload.attachmentId !== attachmentId) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }

    const r2Key = `${cipherId}/${attachmentId}`;

    const file = await c.env.ATTACHMENTS.get(r2Key);

    if (!file) {
        return c.json({ message: 'File not found.', object: 'error' }, 404);
    }

    const headers = new Headers();
    headers.set('Content-Type', file.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Length', file.size.toString());
    headers.set('Cache-Control', 'private, max-age=0, no-store');

    return new Response(file.body, { headers });
});

// Hub (SignalR notifications) - WebSocket via Durable Object
// 场景1: 用户只设 base URL → getNotificationsUrl() = base + "/notifications" → 请求 /notifications/hub
// 场景2: config 返回 notifications=origin → getNotificationsUrl() = origin → 请求 /hub
app.route('/notifications', hubRoutes);
app.route('/', hubRoutes);

// 404 处理
app.notFound((c) => {
    return c.json({ message: 'Not Found', object: 'error' }, 404);
});

// 导出 fetch + scheduled 处理器
// fetch: Hono 处理 HTTP 请求
// scheduled: Cloudflare Cron Triggers 处理定时任务
import { handleScheduled } from './services/scheduled';

// 导出 Durable Object
export { NotificationHub } from './durable-objects/notification-hub';

export default {
    fetch: app.fetch,
    async queue(batch: MessageBatch<WebPushQueueMessage>, env: Bindings) {
        await handleWebPushQueue(batch, env);
    },
    async scheduled(controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
        ctx.waitUntil(handleScheduled(controller.cron, env));
    },
};
