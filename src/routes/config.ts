/**
 * Bitwarden Workers - Config 路由
 * 对应原始项目 Api/Controllers/ConfigController.cs
 * 返回服务端配置信息 - 对齐 ConfigResponseModel.cs
 */

import { Hono } from 'hono';
import type { Bindings, Variables } from '../types';

const config = new Hono<{ Bindings: Bindings; Variables: Variables }>();

function isEmailVerificationEnabled(env: Bindings): boolean {
    return String(env.EMAIL_MODE ?? 'disabled').toLowerCase() !== 'disabled' ||
        String(env.EMAIL_RETURN_TOKENS ?? '').toLowerCase() === 'true';
}

function isUserRegistrationDisabled(env: Bindings): boolean {
    return String(env.SIGNUPS_ALLOWED ?? 'auto').toLowerCase().trim() === 'false';
}

export function getWebPushServerConfig(env: Bindings) {
    const publicKey = env.WEB_PUSH_VAPID_PUBLIC_KEY?.trim();
    const privateKey = env.WEB_PUSH_VAPID_PRIVATE_KEY?.trim();
    const subject = env.WEB_PUSH_VAPID_SUBJECT?.trim();
    return publicKey && privateKey && subject
        ? { pushTechnology: 1, vapidPublicKey: publicKey }
        : { pushTechnology: 0, vapidPublicKey: null };
}

function deploymentVersion(env: Bindings): string {
    const explicit = env.WORKER_VERSION?.trim();
    if (explicit) return explicit;
    const metadata = env.CF_VERSION_METADATA;
    return metadata?.tag?.trim() || metadata?.id || 'unknown';
}

/**
 * GET /api/config
 * 对应 ConfigController.Get
 */
config.get('/', async (c) => {
    // 从请求中推断 notifications URL（与 api 同源）
    const origin = new URL(c.req.url).origin;
    return c.json({
        version: deploymentVersion(c.env),
        gitHash: 'workers',
        server: null, // null = 官方服务器标志，isOfficialBitwardenServer() 检查此字段
        environment: {
            cloudRegion: 'Self-hosted',
            vault: '',
            api: '',
            identity: '',
            notifications: origin,
            sso: '',
        },
        featureStates: {
            // iOS app feature flags
            'pm-19148-innovation-archive': true,    // Archive vault items (premium)
            'cxp-export-mobile': true,              // Credential exchange export
            'cxp-import-mobile': true,              // Credential exchange import
            'cipher-key-encryption': true,          // Individual cipher encryption
            'pm-18021-force-update-kdf-settings': false, // Force KDF updates (keep off)
            'pm-20558-migrate-myvault-to-myitems': true, // My Vault -> My Items
            'pm-23995-no-logout-on-kdf-change': true,   // No logout on KDF change
            'pm-19051-send-email-verification': isEmailVerificationEnabled(c.env),
        },
        // 新增字段 - 对应 ConfigResponseModel
        push: getWebPushServerConfig(c.env),
        communication: null,
        settings: {
            disableUserRegistration: isUserRegistrationDisabled(c.env),
        },
        object: 'config',
    });
});

export default config;
