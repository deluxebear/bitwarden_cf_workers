/**
 * Bitwarden Workers - 主入口
 * Cloudflare Workers + Hono 应用
 *
 * 路由结构：
 * /identity/* - 认证（Prelogin、Register、Token）
 * /api/accounts/* - 用户账户管理
 * /api/ciphers/* - 密码条目 CRUD
 * /api/folders/* - 文件夹 CRUD
 * /api/sync - 全量同步
 * /api/config - 服务端配置
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { errorHandler } from './middleware/error';
import identityRoutes from './routes/identity';
import accountsRoutes from './routes/accounts';
import ciphersRoutes from './routes/ciphers';
import foldersRoutes from './routes/folders';
import syncRoutes from './routes/sync';
import configRoutes from './routes/config';
import type { Bindings, Variables } from './types';

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 全局中间件
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization', 'Accept', 'Device-Type', 'Bitwarden-Client-Name', 'Bitwarden-Client-Version'],
    exposeHeaders: ['Content-Length'],
    maxAge: 86400,
}));
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
app.route('/api/ciphers', ciphersRoutes);
app.route('/api/folders', foldersRoutes);
app.route('/api/sync', syncRoutes);
app.route('/api/config', configRoutes);

// 404 处理
app.notFound((c) => {
    return c.json({ message: 'Not Found', object: 'error' }, 404);
});

export default app;
