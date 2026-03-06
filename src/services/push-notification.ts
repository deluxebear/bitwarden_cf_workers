/**
 * Push Notification Service
 *
 * 对应官方 IPushNotificationService + HubHelpers 的路由逻辑。
 * 业务层调用此服务发送实时通知，内部路由到 NotificationHub Durable Object。
 */

import type { NotificationRequest } from '../durable-objects/notification-hub';
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
    await stub.fetch(new Request('https://do/notify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
    }));
}

/**
 * 推送通知到用户
 */
async function pushToUser(
    env: { NOTIFICATION_HUB: DurableObjectNamespace },
    userId: string,
    data: PushNotificationData<unknown>,
    contextId: string | null,
): Promise<void> {
    await sendToHub(env, {
        type: 'push',
        target: 'user',
        targetId: userId,
        method: 'ReceiveMessage',
        data,
        contextId,
    });
}

/**
 * 推送通知到组织
 */
async function pushToOrganization(
    env: { NOTIFICATION_HUB: DurableObjectNamespace },
    orgId: string,
    data: PushNotificationData<unknown>,
    contextId: string | null,
): Promise<void> {
    await sendToHub(env, {
        type: 'push',
        target: 'organization',
        targetId: orgId,
        method: 'ReceiveMessage',
        data,
        contextId,
    });
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

type HubEnv = { NOTIFICATION_HUB: DurableObjectNamespace };

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
