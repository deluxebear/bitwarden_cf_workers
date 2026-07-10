/**
 * Push Notification Service
 *
 * 对应官方 IPushNotificationService + HubHelpers 的路由逻辑。
 * 业务层调用此服务发送实时通知，内部路由到 NotificationHub Durable Object。
 */

import type { NotificationRequest } from '../durable-objects/notification-hub';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq } from 'drizzle-orm';
import { devices, organizationUsers } from '../db/schema';
import { sendWebPush, type WebPushIdempotencyStore, type WebPushSubscription } from './web-push';
import {
    PushType,
    type PushNotificationData,
    type SyncCipherPushNotification,
    type SyncFolderPushNotification,
    type UserPushNotification,
    type SyncSendPushNotification,
    type AuthRequestPushNotification,
    type LogOutPushNotification,
    type OrganizationStatusPushNotification,
} from '../types/push-notification';

// DO 绑定名称
const DO_BINDING = 'NOTIFICATION_HUB';
// 使用固定 ID，所有连接共享一个 DO 实例（单实例足以处理自建场景的连接数）
const DO_ID_NAME = 'global-notification-hub';

type HubEnv = {
    NOTIFICATION_HUB: DurableObjectNamespace;
    DB?: D1Database;
    [key: string]: unknown;
};

/**
 * 获取 NotificationHub DO stub
 */
function getHubStub(env: { NOTIFICATION_HUB: DurableObjectNamespace }): DurableObjectStub {
    const id = env.NOTIFICATION_HUB.idFromName(DO_ID_NAME);
    return env.NOTIFICATION_HUB.get(id);
}

/**
 * 向 DO 发送推送请求
 */
async function sendToHub(
    env: { NOTIFICATION_HUB: DurableObjectNamespace },
    req: NotificationRequest,
): Promise<void> {
    const stub = getHubStub(env);
    const response = await stub.fetch(new Request('https://do/notify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
    }));
    if (!response.ok) throw new Error(`NotificationHub rejected notification: HTTP ${response.status}`);
}

/**
 * 推送通知到用户
 */
async function pushToUser(
    env: HubEnv,
    userId: string,
    data: PushNotificationData<unknown>,
    contextId: string | null,
    eventId = crypto.randomUUID(),
    idempotency?: WebPushIdempotencyStore,
): Promise<void> {
    await Promise.all([
        sendToHub(env, {
            type: 'push', target: 'user', targetId: userId,
            method: 'ReceiveMessage', data, contextId,
        }),
        pushToRegisteredWebDevices(env, 'user', userId, data, contextId, eventId, idempotency),
    ]);
}

/**
 * 推送通知到组织
 */
async function pushToOrganization(
    env: HubEnv,
    orgId: string,
    data: PushNotificationData<unknown>,
    contextId: string | null,
    eventId = crypto.randomUUID(),
    idempotency?: WebPushIdempotencyStore,
): Promise<void> {
    await Promise.all([
        sendToHub(env, {
            type: 'push', target: 'organization', targetId: orgId,
            method: 'ReceiveMessage', data, contextId,
        }),
        pushToRegisteredWebDevices(env, 'organization', orgId, data, contextId, eventId, idempotency),
    ]);
}

/**
 * 推送 AuthRequestResponse 到匿名 Hub
 */
async function pushToAnonymousToken(
    env: { NOTIFICATION_HUB: DurableObjectNamespace },
    token: string,
    data: PushNotificationData<unknown>,
): Promise<void> {
    await sendToHub(env, {
        type: 'push',
        target: 'anonymous-token',
        targetId: token,
        method: 'AuthRequestResponseRecieved', // 注意：官方拼写错误 Recieved
        data,
        contextId: null,
    });
}

// ============================================================
// 公开 API - 业务层调用
// ============================================================

type RegisteredWebPushAuth = {
    endpoint?: string;
    p256dh?: string;
    auth?: string;
    organizationIds?: string[];
};

export type WebPushQueueMessage = {
    deviceId: string;
    subscription: WebPushSubscription;
    serializedSubscription: string;
    payload: unknown;
    eventId: string;
};

type WebPushEnv = HubEnv & { WEB_PUSH_QUEUE?: Queue<WebPushQueueMessage> };

type ClaimResult = { status: 'claimed'; token: string } |
    { status: 'leased'; remainingSeconds: number } | { status: 'completed' };

async function claimDelivery(env: HubEnv, key: string): Promise<ClaimResult> {
    const response = await getHubStub(env).fetch(new Request('https://do/web-push/claim', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ key, leaseSeconds: 30 }),
    }));
    if (!response.ok) throw new Error(`Web Push idempotency claim failed: HTTP ${response.status}`);
    return await response.json() as ClaimResult;
}

async function finishDelivery(env: HubEnv, action: 'complete' | 'release', key: string, token: string): Promise<boolean> {
    const response = await getHubStub(env).fetch(new Request(`https://do/web-push/${action}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, token }),
    }));
    if (!response.ok) throw new Error(`Web Push idempotency ${action} failed: HTTP ${response.status}`);
    return ((await response.json()) as { updated?: boolean }).updated === true;
}

function binding(env: HubEnv, name: string): string | null {
    const value = env[name];
    return typeof value === 'string' && value.trim() ? value.trim() : null;
}

function webPushConfig(env: HubEnv) {
    const publicKey = binding(env, 'WEB_PUSH_VAPID_PUBLIC_KEY');
    const privateKey = binding(env, 'WEB_PUSH_VAPID_PRIVATE_KEY');
    const subject = binding(env, 'WEB_PUSH_VAPID_SUBJECT');
    return publicKey && privateKey && subject ? { publicKey, privateKey, subject } : null;
}

function parseWebPushAuth(value: string | null): RegisteredWebPushAuth | null {
    if (!value) return null;
    try {
        const parsed = JSON.parse(value) as RegisteredWebPushAuth;
        if (!parsed.endpoint || !parsed.p256dh || !parsed.auth) return null;
        return parsed;
    } catch {
        return null;
    }
}

async function pushToRegisteredWebDevices(
    env: HubEnv,
    target: 'user' | 'organization',
    targetId: string,
    data: PushNotificationData<unknown>,
    contextId: string | null,
    eventId: string,
    idempotency?: WebPushIdempotencyStore,
): Promise<void> {
    const config = webPushConfig(env);
    if (!config || !env.DB) return;
    const db = drizzle(env.DB);
    const rows = target === 'user'
        ? await db.select({ id: devices.id, auth: devices.webPushAuth }).from(devices)
            .where(and(eq(devices.userId, targetId), eq(devices.active, true))).all()
        : await db.select({ id: devices.id, auth: devices.webPushAuth }).from(devices)
            .innerJoin(organizationUsers, eq(organizationUsers.userId, devices.userId))
            .where(and(
                eq(organizationUsers.organizationId, targetId),
                eq(organizationUsers.status, 2),
                eq(devices.active, true),
            )).all();

    const uniqueDevices = [...new Map(rows.map((device) => [device.id, device])).values()];
    await Promise.all(uniqueDevices.map(async (device) => {
        if (device.id === contextId) return;
        const auth = parseWebPushAuth(device.auth);
        if (!auth || (target === 'organization' && !auth.organizationIds?.includes(targetId))) return;
        const claimKey = `${eventId}:${device.id}`;
        let leaseToken: string | null = null;
        let enqueueing = false;
        try {
            const claim = await claimDelivery(env, claimKey);
            if (claim.status !== 'claimed') return;
            leaseToken = claim.token;
            const result = await sendWebPush(auth as Required<Pick<RegisteredWebPushAuth, 'endpoint' | 'p256dh' | 'auth'>>,
                { ...data, EventId: eventId }, eventId, config);
            if (result.status === 'delivered' || result.status === 'duplicate') {
                await finishDelivery(env, 'complete', claimKey, leaseToken);
            }
            if (result.status === 'failed') await finishDelivery(env, 'complete', claimKey, leaseToken);
            if (result.status === 'expired') {
                await db.update(devices).set({ webPushAuth: null, revisionDate: new Date().toISOString() })
                    .where(and(eq(devices.id, device.id), eq(devices.webPushAuth, device.auth!)));
                await finishDelivery(env, 'complete', claimKey, leaseToken);
            }
            if (result.status === 'retryable') {
                const queue = (env as WebPushEnv).WEB_PUSH_QUEUE;
                if (!queue) throw new Error('WEB_PUSH_QUEUE is required for retries.');
                enqueueing = true;
                await queue.send({ deviceId: device.id, subscription: auth as WebPushSubscription,
                    serializedSubscription: device.auth!, payload: { ...data, EventId: eventId }, eventId },
                { delaySeconds: result.retryAfterSeconds ?? 30 });
                enqueueing = false;
                await finishDelivery(env, 'release', claimKey, leaseToken);
                console.warn(JSON.stringify({ event: 'web_push.retryable',
                    statusCode: result.statusCode, attempts: result.attempts }));
            }
        } catch (error) {
            if (!enqueueing && leaseToken) await finishDelivery(env, 'release', claimKey, leaseToken).catch(() => undefined);
            console.error(JSON.stringify({ event: 'web_push.failed',
                errorCode: error instanceof Error ? error.name : 'WEB_PUSH_ERROR' }));
            if (enqueueing) throw error;
        }
    }));
}

export async function handleWebPushQueue(batch: MessageBatch<WebPushQueueMessage>, env: WebPushEnv): Promise<void> {
    const config = webPushConfig(env);
    if (!config || !env.DB) return batch.retryAll({ delaySeconds: 300 });
    const db = drizzle(env.DB);
    await Promise.all(batch.messages.map(async (message) => {
        const body = message.body;
        const key = `${body.eventId}:${body.deviceId}`;
        const delay = () => Math.min(3600, 30 * (2 ** Math.min(Math.max(message.attempts - 1, 0), 7)));
        let leaseToken: string | null = null;
        try {
            const claim = await claimDelivery(env, key);
            if (claim.status === 'completed') return message.ack();
            if (claim.status === 'leased') return message.retry({ delaySeconds: claim.remainingSeconds });
            leaseToken = claim.token;
            const result = await sendWebPush(body.subscription, body.payload, body.eventId, config, { maxAttempts: 1 });
            if (result.status === 'delivered' || result.status === 'duplicate') {
                await finishDelivery(env, 'complete', key, leaseToken); message.ack(); return;
            }
            if (result.status === 'expired') {
                await db.update(devices).set({ webPushAuth: null, revisionDate: new Date().toISOString() })
                    .where(and(eq(devices.id, body.deviceId), eq(devices.webPushAuth, body.serializedSubscription)));
                await finishDelivery(env, 'complete', key, leaseToken); message.ack(); return;
            }
            if (result.status === 'failed') {
                await finishDelivery(env, 'complete', key, leaseToken); message.ack(); return;
            }
            await finishDelivery(env, 'release', key, leaseToken);
            message.retry({ delaySeconds: Math.max(delay(), result.retryAfterSeconds ?? 0) });
        } catch {
            if (leaseToken) await finishDelivery(env, 'release', key, leaseToken).catch(() => undefined);
            message.retry({ delaySeconds: delay() });
        }
    }));
}

/**
 * 通用推送通知。
 * 用于 Push relay 与 Notification Center 这类动态 payload 的端点。
 */
export async function pushNotification(
    env: HubEnv,
    target: 'user' | 'organization',
    targetId: string,
    type: PushType,
    payload: unknown,
    contextId: string | null,
    eventId = crypto.randomUUID(),
    idempotency?: WebPushIdempotencyStore,
): Promise<void> {
    const data: PushNotificationData<unknown> = {
        Type: type,
        Payload: payload,
        ContextId: contextId,
    };

    await (target === 'user'
        ? pushToUser(env, targetId, data, contextId, eventId, idempotency)
        : pushToOrganization(env, targetId, data, contextId, eventId, idempotency));
}

/**
 * Cipher 同步通知
 * 对应 PushSyncCipherCreateAsync / PushSyncCipherUpdateAsync / PushSyncCipherDeleteAsync
 */
export async function pushSyncCipher(
    env: HubEnv,
    type: PushType.SyncCipherCreate | PushType.SyncCipherUpdate | PushType.SyncCipherDelete | PushType.SyncLoginDelete,
    cipherId: string,
    userId: string | null,
    organizationId: string | null,
    collectionIds: string[] | null,
    revisionDate: string,
    contextId: string | null,
): Promise<void> {
    const payload: SyncCipherPushNotification = {
        Id: cipherId,
        UserId: userId,
        OrganizationId: organizationId,
        CollectionIds: collectionIds,
        RevisionDate: revisionDate,
    };
    const data: PushNotificationData<SyncCipherPushNotification> = {
        Type: type,
        Payload: payload,
        ContextId: contextId,
    };

    if (userId) {
        await pushToUser(env, userId, data, contextId);
    } else if (organizationId) {
        await pushToOrganization(env, organizationId, data, contextId);
    }
}

/**
 * Folder 同步通知
 * 对应 PushSyncFolderCreateAsync / PushSyncFolderUpdateAsync / PushSyncFolderDeleteAsync
 */
export async function pushSyncFolder(
    env: HubEnv,
    type: PushType.SyncFolderCreate | PushType.SyncFolderUpdate | PushType.SyncFolderDelete,
    folderId: string,
    userId: string,
    revisionDate: string,
    contextId: string | null,
): Promise<void> {
    const payload: SyncFolderPushNotification = {
        Id: folderId,
        UserId: userId,
        RevisionDate: revisionDate,
    };
    const data: PushNotificationData<SyncFolderPushNotification> = {
        Type: type,
        Payload: payload,
        ContextId: contextId,
    };
    await pushToUser(env, userId, data, contextId);
}

/**
 * 用户级同步通知
 * 对应 PushSyncCiphersAsync / PushSyncVaultAsync / PushSyncOrganizationsAsync /
 *      PushSyncOrgKeysAsync / PushSyncSettingsAsync
 */
export async function pushSyncUser(
    env: HubEnv,
    type: PushType.SyncCiphers | PushType.SyncVault | PushType.SyncOrganizations |
          PushType.SyncOrgKeys | PushType.SyncSettings,
    userId: string,
    contextId: string | null,
): Promise<void> {
    const payload: UserPushNotification = {
        UserId: userId,
        Date: new Date().toISOString(),
    };
    const data: PushNotificationData<UserPushNotification> = {
        Type: type,
        Payload: payload,
        ContextId: contextId,
    };
    await pushToUser(env, userId, data, contextId);
}

/**
 * LogOut 通知
 * 对应 PushLogOutAsync
 */
export async function pushLogOut(
    env: HubEnv,
    userId: string,
    contextId: string | null,
    reason: number | null = null,
): Promise<void> {
    const payload: LogOutPushNotification = {
        UserId: userId,
        Reason: reason,
    };
    const data: PushNotificationData<LogOutPushNotification> = {
        Type: PushType.LogOut,
        Payload: payload,
        ContextId: contextId,
    };
    await pushToUser(env, userId, data, contextId);
}

/**
 * Send 同步通知
 * 对应 PushSyncSendCreateAsync / PushSyncSendUpdateAsync / PushSyncSendDeleteAsync
 */
export async function pushSyncSend(
    env: HubEnv,
    type: PushType.SyncSendCreate | PushType.SyncSendUpdate | PushType.SyncSendDelete,
    sendId: string,
    userId: string,
    revisionDate: string,
    contextId: string | null,
): Promise<void> {
    const payload: SyncSendPushNotification = {
        Id: sendId,
        UserId: userId,
        RevisionDate: revisionDate,
    };
    const data: PushNotificationData<SyncSendPushNotification> = {
        Type: type,
        Payload: payload,
        ContextId: contextId,
    };
    await pushToUser(env, userId, data, contextId);
}

/**
 * AuthRequest 通知
 * 对应 PushAuthRequestAsync
 */
export async function pushAuthRequest(
    env: HubEnv,
    authRequestId: string,
    userId: string,
    contextId: string | null,
): Promise<void> {
    const payload: AuthRequestPushNotification = {
        Id: authRequestId,
        UserId: userId,
    };
    const data: PushNotificationData<AuthRequestPushNotification> = {
        Type: PushType.AuthRequest,
        Payload: payload,
        ContextId: contextId,
    };
    await pushToUser(env, userId, data, contextId);
}

/**
 * AuthRequestResponse 通知（推送到匿名 Hub）
 * 对应 PushAuthRequestResponseAsync
 */
export async function pushAuthRequestResponse(
    env: HubEnv,
    authRequestId: string,
    userId: string,
): Promise<void> {
    const payload: AuthRequestPushNotification = {
        Id: authRequestId,
        UserId: userId,
    };
    const data: PushNotificationData<AuthRequestPushNotification> = {
        Type: PushType.AuthRequestResponse,
        Payload: payload,
        ContextId: null,
    };
    // AuthRequestResponse 推送到匿名 Hub，用 authRequestId 作为 token
    await pushToAnonymousToken(env, authRequestId, data);
    // 同时推送到认证 Hub 的用户
    await pushToUser(env, userId, data, null);
}

/**
 * Organization 状态变更通知
 * 对应 PushSyncOrganizationStatusChangedAsync
 */
export async function pushSyncOrganizationStatus(
    env: HubEnv,
    organizationId: string,
    enabled: boolean,
): Promise<void> {
    const payload: OrganizationStatusPushNotification = {
        OrganizationId: organizationId,
        Enabled: enabled,
    };
    const data: PushNotificationData<OrganizationStatusPushNotification> = {
        Type: PushType.SyncOrganizationStatusChanged,
        Payload: payload,
        ContextId: null,
    };
    await pushToOrganization(env, organizationId, data, null);
}
