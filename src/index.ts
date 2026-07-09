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
import { logger } from 'hono/logger';
import { errorHandler, globalErrorHandler } from './middleware/error';
import { debugMiddleware } from './middleware/debug';
import identityRoutes from './routes/identity';
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
    exposeHeaders: ['Content-Length'],
    maxAge: 86400,
}));
app.use('*', debugMiddleware);
app.use('*', logger());
app.use('*', errorHandler);

// 健康检查
app.get('/', (c) => c.json({ status: 'ok', service: 'bitwarden-workers' }));

// Info 端点 - 对应 Api/Controllers/InfoController.cs
app.get('/alive', (c) => c.text(new Date().toISOString()));
app.get('/now', (c) => c.text(new Date().toISOString()));
app.get('/version', (c) => c.json({ version: '2025.1.0' }));

// 挂载路由
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
    async scheduled(controller: ScheduledController, env: Bindings, ctx: ExecutionContext) {
        ctx.waitUntil(handleScheduled(controller.cron, env));
    },
};
