/**
 * Bitwarden Workers - 推送通知类型定义
 * 对应官方 Core/Enums/PushType.cs + Core/Models/PushNotification.cs
 */

// PushType 枚举 - 完全对齐官方 PushType.cs
export enum PushType {
    SyncCipherUpdate = 0,
    SyncCipherCreate = 1,
    SyncLoginDelete = 2,
    SyncFolderDelete = 3,
    SyncCiphers = 4,
    SyncVault = 5,
    SyncOrgKeys = 6,
    SyncFolderCreate = 7,
    SyncFolderUpdate = 8,
    SyncCipherDelete = 9,
    SyncSettings = 10,
    LogOut = 11,
    SyncSendCreate = 12,
    SyncSendUpdate = 13,
    SyncSendDelete = 14,
    AuthRequest = 15,
    AuthRequestResponse = 16,
    SyncOrganizations = 17,
    SyncOrganizationStatusChanged = 18,
    SyncOrganizationCollectionSettingChanged = 19,
    Notification = 20,
    NotificationStatus = 21,
    RefreshSecurityTasks = 22,
    OrganizationBankAccountVerified = 23,
    ProviderBankAccountVerified = 24,
    PolicyChanged = 25,
    AutoConfirm = 26,
}

// 通知包装 - 对应 PushNotificationData<T>
export interface PushNotificationData<T> {
    Type: PushType;
    Payload: T;
    ContextId: string | null;
}

// Payload 类型 - 对应 Core/Models/PushNotification.cs

export interface SyncCipherPushNotification {
    Id: string;
    UserId: string | null;
    OrganizationId: string | null;
    CollectionIds: string[] | null;
    RevisionDate: string;
}

export interface SyncFolderPushNotification {
    Id: string;
    UserId: string;
    RevisionDate: string;
}

export interface UserPushNotification {
    UserId: string;
    Date: string;
}

export interface SyncSendPushNotification {
    Id: string;
    UserId: string;
    RevisionDate: string;
}

export interface AuthRequestPushNotification {
    Id: string;
    UserId: string;
}

export interface LogOutPushNotification {
    UserId: string;
    Reason: number | null;
}

export interface OrganizationStatusPushNotification {
    OrganizationId: string;
    Enabled: boolean;
}
