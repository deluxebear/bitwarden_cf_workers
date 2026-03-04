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
        server: null, // null = 官方服务器标志，isOfficialBitwardenServer() 检查此字段
        environment: {
            cloudRegion: 'Self-hosted',
            vault: '',
            api: '',
            identity: '',
            notifications: '',
            sso: '',
        },
        featureStates: {
            // iOS app feature flags
            'pm-19148-innovation-archive': true,    // Archive vault items (premium)
            'cxp-export-mobile': true,              // Credential exchange export
            'cxp-import-mobile': true,              // Credential exchange import
            'cipher-key-encryption': true,          // Individual cipher encryption
            'enableCipherKeyEncryption': true,      // SDK cipher key encryption
            'pm-18021-force-update-kdf-settings': false, // Force KDF updates (keep off)
            'pm-20558-migrate-myvault-to-myitems': true, // My Vault -> My Items
            'pm-23995-no-logout-on-kdf-change': true,   // No logout on KDF change
            'pm-19051-send-email-verification': false,   // Email verification (no email service)
        },
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
