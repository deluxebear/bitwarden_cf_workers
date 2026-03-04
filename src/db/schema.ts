/**
 * Bitwarden Workers - D1 数据库 Schema
 * 对应原始项目的 Core/Entities: User, Cipher, Folder, Device
 * 使用 Drizzle ORM 定义
 */

import { sqliteTable, text, integer, index, primaryKey } from 'drizzle-orm/sqlite-core';

// ==================== Users ====================
// 对应 Core/Entities/User.cs
export const users = sqliteTable('users', {
    id: text('id').primaryKey(), // UUID
    name: text('name'),
    email: text('email').notNull().unique(),
    emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
    masterPassword: text('master_password'), // server-side hash
    masterPasswordHint: text('master_password_hint'),
    culture: text('culture').notNull().default('en-US'),
    securityStamp: text('security_stamp').notNull(),
    twoFactorProviders: text('two_factor_providers'), // JSON
    twoFactorRecoveryCode: text('two_factor_recovery_code'),
    equivalentDomains: text('equivalent_domains'), // JSON
    excludedGlobalEquivalentDomains: text('excluded_global_equivalent_domains'), // JSON
    accountRevisionDate: text('account_revision_date').notNull(), // ISO 8601
    // 密钥相关
    key: text('key'), // master-password-sealed user key
    publicKey: text('public_key'),
    privateKey: text('private_key'), // user key wrapped private key
    signedPublicKey: text('signed_public_key'),
    // KDF 参数
    kdf: integer('kdf').notNull().default(0), // 0 = PBKDF2_SHA256, 1 = Argon2id
    kdfIterations: integer('kdf_iterations').notNull().default(600000),
    kdfMemory: integer('kdf_memory'),
    kdfParallelism: integer('kdf_parallelism'),
    // 账户状态
    premium: integer('premium', { mode: 'boolean' }).notNull().default(false),
    forcePasswordReset: integer('force_password_reset', { mode: 'boolean' }).notNull().default(false),
    usesKeyConnector: integer('uses_key_connector', { mode: 'boolean' }).notNull().default(false),
    failedLoginCount: integer('failed_login_count').notNull().default(0),
    lastFailedLoginDate: text('last_failed_login_date'),
    avatarColor: text('avatar_color'),
    apiKey: text('api_key').notNull(),
    // 时间戳
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
    lastPasswordChangeDate: text('last_password_change_date'),
    lastKdfChangeDate: text('last_kdf_change_date'),
    lastKeyRotationDate: text('last_key_rotation_date'),
    lastEmailChangeDate: text('last_email_change_date'),
});

// ==================== Ciphers ====================
// 对应 Core/Vault/Entities/Cipher.cs
export const ciphers = sqliteTable('ciphers', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    organizationId: text('organization_id'),
    type: integer('type').notNull(), // CipherType enum
    data: text('data').notNull(), // JSON - 加密的数据
    favorites: text('favorites'), // JSON - per-user favorites
    folders: text('folders'), // JSON - per-user folder assignments
    attachments: text('attachments'), // JSON
    reprompt: integer('reprompt').default(0),
    key: text('key'), // cipher key
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
    deletedDate: text('deleted_date'),
}, (table) => [
    index('idx_ciphers_user_id').on(table.userId),
    index('idx_ciphers_organization_id').on(table.organizationId),
]);

// ==================== Folders ====================
// 对应 Core/Entities/Folder.cs
export const folders = sqliteTable('folders', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    name: text('name'), // encrypted
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_folders_user_id').on(table.userId),
]);

// ==================== Devices ====================
// 对应 Core/Entities/Device.cs
export const devices = sqliteTable('devices', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    type: integer('type').notNull(), // DeviceType enum
    identifier: text('identifier').notNull(),
    pushToken: text('push_token'),
    encryptedUserKey: text('encrypted_user_key'),
    encryptedPublicKey: text('encrypted_public_key'),
    encryptedPrivateKey: text('encrypted_private_key'),
    active: integer('active', { mode: 'boolean' }).notNull().default(true),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_devices_user_id').on(table.userId),
    index('idx_devices_identifier').on(table.identifier),
]);

// ==================== Refresh Tokens ====================
// 用于 OAuth2 refresh token 持久化
export const refreshTokens = sqliteTable('refresh_tokens', {
    id: text('id').primaryKey(),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    deviceId: text('device_id').references(() => devices.id),
    tokenHash: text('token_hash').notNull(),
    expirationDate: text('expiration_date').notNull(),
    creationDate: text('creation_date').notNull(),
}, (table) => [
    index('idx_refresh_tokens_user_id').on(table.userId),
    index('idx_refresh_tokens_token_hash').on(table.tokenHash),
]);

// ==================== Sends ====================
// 对应 Core/Tools/Entities/Send.cs
export const sends = sqliteTable('sends', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    organizationId: text('organization_id'),
    type: integer('type').notNull(), // 0 = text, 1 = file
    data: text('data'), // JSON - 加密的数据
    key: text('key'), // 加密 key
    password: text('password'), // PBKDF2 hashed
    maxAccessCount: integer('max_access_count'),
    accessCount: integer('access_count').notNull().default(0),
    expirationDate: text('expiration_date'),
    deletionDate: text('deletion_date').notNull(),
    disabled: integer('disabled', { mode: 'boolean' }).notNull().default(false),
    hideEmail: integer('hide_email', { mode: 'boolean' }).default(false),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_sends_user_id').on(table.userId),
]);

// ==================== Organizations ====================
export const organizations = sqliteTable('organizations', {
    id: text('id').primaryKey(),
    name: text('name').notNull(),
    billingEmail: text('billing_email').notNull(),
    email: text('email'),
    key: text('key'), // 加密密钥
    planType: integer('plan_type').default(0), // 0=Free, 1=Premium, 2=Family/Teams
    seats: integer('seats').default(5),
    maxStorageGb: integer('max_storage_gb').default(1),
    useTotp: integer('use_totp', { mode: 'boolean' }).default(false),
    useWebAuthn: integer('use_web_authn', { mode: 'boolean' }).default(false),
    enabled: integer('enabled', { mode: 'boolean' }).default(true),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
});

// ==================== Events ====================
// 对应 Core/Dirt/Entities/Event.cs
export const events = sqliteTable('events', {
    id: text('id').primaryKey(), // UUID
    type: integer('type').notNull(), // EventType enum
    userId: text('user_id'),
    organizationId: text('organization_id'),
    cipherId: text('cipher_id'),
    collectionId: text('collection_id'),
    actingUserId: text('acting_user_id'),
    date: text('date').notNull(), // ISO 8601
    deviceType: integer('device_type'), // DeviceType enum
    ipAddress: text('ip_address'),
    systemUser: integer('system_user'),
});

// ==================== Organization Users ====================
export const organizationUsers = sqliteTable('organization_users', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    key: text('key'), // 加密的 org key
    status: integer('status').notNull().default(2), // 0=Invited,1=Accepted,2=Confirmed,3=Revoked
    type: integer('type').notNull().default(2), // 0=Owner,1=Admin,2=User,3=Manager,4=Custom
    permissions: text('permissions'), // JSON - 权限控制
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_org_users_org_id').on(table.organizationId),
    index('idx_org_users_user_id').on(table.userId),
]);

// ==================== Collections ====================
export const collections = sqliteTable('collections', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(), // encrypted name
    externalId: text('external_id'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_collections_org_id').on(table.organizationId),
]);

// ==================== Collection Ciphers ====================
export const collectionCiphers = sqliteTable('collection_ciphers', {
    collectionId: text('collection_id').notNull().references(() => collections.id, { onDelete: 'cascade' }),
    cipherId: text('cipher_id').notNull().references(() => ciphers.id, { onDelete: 'cascade' }),
}, (table) => [
    primaryKey({ columns: [table.collectionId, table.cipherId] }),
    index('idx_coll_ciphers_cipher_id').on(table.cipherId),
]);

// ==================== Collection Users ====================
export const collectionUsers = sqliteTable('collection_users', {
    collectionId: text('collection_id').notNull().references(() => collections.id, { onDelete: 'cascade' }),
    organizationUserId: text('organization_user_id').notNull().references(() => organizationUsers.id, { onDelete: 'cascade' }),
    readOnly: integer('read_only', { mode: 'boolean' }).default(false),
    hidePasswords: integer('hide_passwords', { mode: 'boolean' }).default(false),
    manage: integer('manage', { mode: 'boolean' }).default(false),
}, (table) => [
    primaryKey({ columns: [table.collectionId, table.organizationUserId] }),
    index('idx_coll_users_org_user_id').on(table.organizationUserId),
]);
