/**
 * Bitwarden Workers - Emergency Access 路由
 * 对应原始 Api/Auth/Controllers/EmergencyAccessController.cs
 *
 * 自托管 Workers 版本暂时不实现真正的应急访问数据存储与密钥托管逻辑，
 * 但需要提供与官方 API 兼容的端点结构，避免 Web / 桌面 / 移动客户端在
 * 访问「紧急访问」页面时出现 404 / 500。
 *
 * 设计目标：
 * - 所有端点均存在，路径/方法与官方保持一致；
 * - 对于只读列表类接口，返回空列表；
 * - 对于修改/流程类接口，接受请求并返回 200/204，但不做任何状态变更；
 * - 保证响应结构满足前端模型解码需求（对象字段 & object 类型字段）。
 */

import { Hono } from 'hono';
import { authMiddleware } from '../middleware/auth';
import type { Bindings, Variables } from '../types';

const emergency = new Hono<{ Bindings: Bindings; Variables: Variables }>();

// 所有 Emergency Access 接口都需要登录
emergency.use('/*', authMiddleware);

/**
 * GET /api/emergency-access/trusted
 * 对应 EmergencyAccessController.GetContacts
 * 返回当前用户信任的紧急联系人列表（自托管默认空列表）
 */
emergency.get('/trusted', async (c) => {
    return c.json({
        data: [],
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/emergency-access/granted
 * 对应 EmergencyAccessController.GetGrantees
 * 返回将当前用户设为紧急联系人的授权记录（自托管默认空列表）
 */
emergency.get('/granted', async (c) => {
    return c.json({
        data: [],
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/emergency-access/:id
 * 对应 EmergencyAccessController.Get
 * 自托管暂不支持真实应急访问，返回一个最小的占位对象，保证前端可以正常解码。
 */
emergency.get('/:id', async (c) => {
    const id = c.req.param('id');
    return c.json({
        id,
        grantorId: null,
        granteeId: null,
        email: null,
        type: 0,
        status: 0,
        waitTimeDays: 0,
        key: null,
        publicKey: null,
        object: 'emergencyAccessGranteeDetails',
    });
});

/**
 * GET /api/emergency-access/:id/policies
 * 对应 EmergencyAccessController.Policies
 * 自托管不启用额外策略，返回空列表即可。
 */
emergency.get('/:id/policies', async (c) => {
    return c.json({
        data: [],
        object: 'list',
        continuationToken: null,
    });
});

/**
 * PUT /api/emergency-access/:id
 * POST /api/emergency-access/:id (deprecated)
 * 对应 EmergencyAccessController.Put/Post
 * 自托管场景下仅接受并返回 200，不做状态变更。
 */
emergency.put('/:id', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

emergency.post('/:id', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

/**
 * DELETE /api/emergency-access/:id
 * POST /api/emergency-access/:id/delete (deprecated)
 */
emergency.delete('/:id', async (c) => {
    return c.body(null, 204);
});

emergency.post('/:id/delete', async (c) => {
    return c.body(null, 204);
});

/**
 * POST /api/emergency-access/invite
 * POST /api/emergency-access/:id/reinvite
 */
emergency.post('/invite', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

emergency.post('/:id/reinvite', async (c) => {
    return c.body(null, 200);
});

/**
 * POST /api/emergency-access/:id/accept
 * POST /api/emergency-access/:id/confirm
 * POST /api/emergency-access/:id/initiate
 * POST /api/emergency-access/:id/approve
 * POST /api/emergency-access/:id/reject
 */
emergency.post('/:id/accept', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

emergency.post('/:id/confirm', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

emergency.post('/:id/initiate', async (c) => {
    return c.body(null, 200);
});

emergency.post('/:id/approve', async (c) => {
    return c.body(null, 200);
});

emergency.post('/:id/reject', async (c) => {
    return c.body(null, 200);
});

/**
 * POST /api/emergency-access/:id/takeover
 * 对应 EmergencyAccessController.Takeover
 * 这里返回一个结构兼容 EmergencyAccessTakeoverResponseModel 的占位对象。
 */
emergency.post('/:id/takeover', async (c) => {
    const id = c.req.param('id');
    return c.json({
        id,
        cipherIds: [],
        object: 'emergencyAccessTakeover',
    });
});

/**
 * POST /api/emergency-access/:id/password
 * 对应 EmergencyAccessController.Password
 */
emergency.post('/:id/password', async (c) => {
    await c.req.json().catch(() => ({}));
    return c.body(null, 200);
});

/**
 * POST /api/emergency-access/:id/view
 * 对应 EmergencyAccessController.ViewCiphers
 * 返回一个空的紧急访问视图。
 */
emergency.post('/:id/view', async (c) => {
    const id = c.req.param('id');
    return c.json({
        id,
        ciphers: [],
        object: 'emergencyAccessView',
    });
});

/**
 * GET /api/emergency-access/:id/:cipherId/attachment/:attachmentId
 * 对应 EmergencyAccessController.GetAttachmentData
 * Workers 当前附件下载仍通过通用 `/attachments/:cipherId/:attachmentId` 端点完成，
 * 这里简单返回 404 结构，提示前端无法通过紧急访问单独下载附件。
 */
emergency.get('/:id/:cipherId/attachment/:attachmentId', async (c) => {
    return c.json({
        message: 'Emergency access attachment download is not supported in self-hosted workers.',
        object: 'error',
    }, 404);
});

export default emergency;

