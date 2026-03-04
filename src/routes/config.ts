/**
 * Bitwarden Workers - Config 路由
 * 对应原始项目 Api/Controllers/ConfigController.cs
 * 返回服务端配置信息 - 对齐 ConfigResponseModel.cs
 */

import { Hono } from 'hono';
import type { Bindings, Variables } from '../types';

const config = new Hono<{ Bindings: Bindings; Variables: Variables }>();

/**
 * GET /api/config
 * 对应 ConfigController.Get
 */
config.get('/', async (c) => {
    return c.json({
        version: '2025.1.0',
        gitHash: 'workers',
        server: {
            name: 'bitwarden-workers',
            url: '',
        },
        environment: {
            cloudRegion: 'Self-hosted',
            vault: '',
            api: '',
            identity: '',
            notifications: '',
            sso: '',
        },
        featureStates: {},
        // 新增字段 - 对应 ConfigResponseModel
        push: {
            pushTechnology: 0, // SignalR
            vapidPublicKey: null,
        },
        communication: null,
        settings: {
            disableUserRegistration: false,
        },
        object: 'config',
    });
});

export default config;
