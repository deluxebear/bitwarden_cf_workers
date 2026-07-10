/**
 * Bitwarden Workers - D1 数据库 Schema
 * 对应原始项目的 Core/Entities: User, Cipher, Folder, Device
 * 使用 Drizzle ORM 定义
 */

import { sqliteTable, text, integer, index, uniqueIndex, primaryKey } from 'drizzle-orm/sqlite-core';
import { sql } from 'drizzle-orm';

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

// ==================== Emergency Access ====================
// 密钥由 grantor 客户端使用 grantee 公钥加密；服务端仅保存密文。
export const emergencyAccess = sqliteTable('emergency_access', {
    id: text('id').primaryKey(),
    grantorId: text('grantor_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    granteeId: text('grantee_id').references(() => users.id, { onDelete: 'cascade' }),
    email: text('email'),
    keyEncrypted: text('key_encrypted'),
    type: integer('type').notNull(), // 0 = View, 1 = Takeover
    status: integer('status').notNull(), // EmergencyAccessStatus
    waitTimeDays: integer('wait_time_days').notNull(),
    recoveryInitiatedDate: text('recovery_initiated_date'),
    recoveryRejectedDate: text('recovery_rejected_date'),
    lastNotificationDate: text('last_notification_date'),
    revokedDate: text('revoked_date'),
    revokedByUserId: text('revoked_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_emergency_access_grantor_id').on(table.grantorId),
    index('idx_emergency_access_grantee_id').on(table.granteeId),
    index('idx_emergency_access_email').on(table.email),
    index('idx_emergency_access_status').on(table.status),
    uniqueIndex('idx_emergency_access_active_grantor_email')
        .on(table.grantorId, table.email)
        .where(sql`${table.revokedDate} IS NULL AND ${table.email} IS NOT NULL`),
    uniqueIndex('idx_emergency_access_active_grantor_grantee')
        .on(table.grantorId, table.granteeId)
        .where(sql`${table.revokedDate} IS NULL AND ${table.granteeId} IS NOT NULL`),
]);

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
    archivedDate: text('archived_date'),
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
    webPushAuth: text('web_push_auth'), // JSON: { endpoint, p256dh, auth, organizationIds }
    active: integer('active', { mode: 'boolean' }).notNull().default(true),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_devices_user_id').on(table.userId),
    index('idx_devices_identifier').on(table.identifier),
]);

// ==================== Security Tasks ====================
// 对应 Core/Vault/Entities/SecurityTask.cs。revision 用于 CAS 状态变更；
// pending 唯一索引确保同一组织/密码项的来源事件不会并发创建重复任务。
export const securityTasks = sqliteTable('security_tasks', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    cipherId: text('cipher_id').references(() => ciphers.id, { onDelete: 'cascade' }),
    type: integer('type').notNull(), // 0 = UpdateAtRiskCredential
    status: integer('status').notNull().default(0), // 0 = Pending, 1 = Completed
    revision: integer('revision').notNull().default(1),
    completedByUserId: text('completed_by_user_id').references(() => users.id, { onDelete: 'set null' }),
    completedDate: text('completed_date'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_security_tasks_org_status').on(table.organizationId, table.status),
    index('idx_security_tasks_cipher').on(table.cipherId),
    uniqueIndex('idx_security_tasks_pending_org_cipher').on(table.organizationId, table.cipherId)
        .where(sql`${table.status} = 0 AND ${table.cipherId} IS NOT NULL`),
]);

// ==================== Notifications ====================
// 对应 Core/NotificationCenter 的 Notification + NotificationStatus。
// Workers 版本按用户展开存储，便于 D1 上直接维护每个用户的 read/delete 状态。
export const notifications = sqliteTable('notifications', {
    id: text('id').primaryKey(),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    organizationId: text('organization_id'),
    priority: integer('priority').notNull().default(0),
    global: integer('global', { mode: 'boolean' }).notNull().default(false),
    clientType: integer('client_type').notNull().default(0),
    title: text('title'),
    body: text('body'),
    taskId: text('task_id'),
    data: text('data'),
    readDate: text('read_date'),
    deletedDate: text('deleted_date'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_notifications_user_id').on(table.userId),
    index('idx_notifications_org_id').on(table.organizationId),
    index('idx_notifications_revision_date').on(table.revisionDate),
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

// ==================== Verification Tokens ====================
// 一次性邮件/设备验证 token。明文只通过邮件或本地开发日志输出，数据库只保存 hash。
export const verificationTokens = sqliteTable('verification_tokens', {
    id: text('id').primaryKey(),
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    type: text('type').notNull(),
    tokenHash: text('token_hash').notNull(),
    expiresAt: text('expires_at').notNull(),
    usedAt: text('used_at'),
    creationDate: text('creation_date').notNull(),
}, (table) => [
    index('idx_verification_tokens_email_type').on(table.email, table.type),
    uniqueIndex('idx_verification_tokens_hash').on(table.tokenHash),
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
    emails: text('emails'), // 逗号分隔的邮箱验证收件人
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
// 对应 Core/AdminConsole/Entities/Organization.cs
export const organizations = sqliteTable('organizations', {
    id: text('id').primaryKey(),
    identifier: text('identifier'), // 组织标识符，用于 SSO
    name: text('name').notNull(),
    businessName: text('business_name'),
    businessAddress1: text('business_address1'),
    businessAddress2: text('business_address2'),
    businessAddress3: text('business_address3'),
    businessCountry: text('business_country'),
    businessTaxNumber: text('business_tax_number'),
    billingEmail: text('billing_email').notNull(),
    email: text('email'),
    plan: text('plan').default('Free'),
    planType: integer('plan_type').default(0),
    seats: integer('seats').default(5),
    maxCollections: integer('max_collections'),
    maxStorageGb: integer('max_storage_gb').default(1),
    maxAutoscaleSeats: integer('max_autoscale_seats'),
    // 功能开关 - 对应官方 Organization 实体的 use* 字段
    usePolicies: integer('use_policies', { mode: 'boolean' }).default(false),
    useSso: integer('use_sso', { mode: 'boolean' }).default(false),
    useKeyConnector: integer('use_key_connector', { mode: 'boolean' }).default(false),
    useScim: integer('use_scim', { mode: 'boolean' }).default(false),
    useGroups: integer('use_groups', { mode: 'boolean' }).default(false),
    useDirectory: integer('use_directory', { mode: 'boolean' }).default(false),
    useEvents: integer('use_events', { mode: 'boolean' }).default(true),
    useTotp: integer('use_totp', { mode: 'boolean' }).default(true),
    use2fa: integer('use_2fa', { mode: 'boolean' }).default(true),
    useApi: integer('use_api', { mode: 'boolean' }).default(true),
    useResetPassword: integer('use_reset_password', { mode: 'boolean' }).default(false),
    useSecretsManager: integer('use_secrets_manager', { mode: 'boolean' }).default(false),
    selfHost: integer('self_host', { mode: 'boolean' }).default(true),
    usersGetPremium: integer('users_get_premium', { mode: 'boolean' }).default(true),
    useCustomPermissions: integer('use_custom_permissions', { mode: 'boolean' }).default(false),
    usePasswordManager: integer('use_password_manager', { mode: 'boolean' }).default(true),
    useRiskInsights: integer('use_risk_insights', { mode: 'boolean' }).default(false),
    useOrganizationDomains: integer('use_organization_domains', { mode: 'boolean' }).default(false),
    useAdminSponsoredFamilies: integer('use_admin_sponsored_families', { mode: 'boolean' }).default(false),
    useAutomaticUserConfirmation: integer('use_automatic_user_confirmation', { mode: 'boolean' }).default(false),
    useInviteLinks: integer('use_invite_links', { mode: 'boolean' }).default(false),
    useDisableSmAdsForUsers: integer('use_disable_sm_ads_for_users', { mode: 'boolean' }).default(false),
    usePhishingBlocker: integer('use_phishing_blocker', { mode: 'boolean' }).default(false),
    useMyItems: integer('use_my_items', { mode: 'boolean' }).default(true),
    // 集合管理设置
    limitCollectionCreation: integer('limit_collection_creation', { mode: 'boolean' }).default(false),
    limitCollectionDeletion: integer('limit_collection_deletion', { mode: 'boolean' }).default(false),
    limitItemDeletion: integer('limit_item_deletion', { mode: 'boolean' }).default(false),
    allowAdminAccessToAllCollectionItems: integer('allow_admin_access_to_all_collection_items', { mode: 'boolean' }).default(true),
    // Secrets Manager
    smSeats: integer('sm_seats'),
    smServiceAccounts: integer('sm_service_accounts'),
    maxAutoscaleSmSeats: integer('max_autoscale_sm_seats'),
    maxAutoscaleSmServiceAccounts: integer('max_autoscale_sm_service_accounts'),
    // 密钥 & 状态
    storage: integer('storage'), // bytes
    enabled: integer('enabled', { mode: 'boolean' }).default(true),
    publicKey: text('public_key'),
    privateKey: text('private_key'),
    twoFactorProviders: text('two_factor_providers'), // JSON
    expirationDate: text('expiration_date'),
    licenseKey: text('license_key'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    uniqueIndex('idx_organizations_identifier_lower')
        .on(sql`lower(${table.identifier})`)
        .where(sql`${table.identifier} IS NOT NULL`),
]);

// ==================== Organization Invite Links ====================
// 对应 Core/AdminConsole/Entities/OrganizationInviteLink.cs
export const organizationInviteLinks = sqliteTable('organization_invite_links', {
    id: text('id').primaryKey(),
    code: text('code').notNull(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    allowedDomains: text('allowed_domains').notNull(),
    invite: text('invite').notNull(),
    supportsConfirmation: integer('supports_confirmation', { mode: 'boolean' }).notNull().default(false),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    uniqueIndex('idx_org_invite_links_code').on(table.code),
    uniqueIndex('idx_org_invite_links_org_id').on(table.organizationId),
]);

// ==================== Organization Domains ====================
// 对应 Core/Entities/OrganizationDomain.cs
export const organizationDomains = sqliteTable('organization_domains', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    txt: text('txt').notNull(),
    domainName: text('domain_name').notNull(),
    creationDate: text('creation_date').notNull(),
    nextRunDate: text('next_run_date').notNull(),
    jobRunCount: integer('job_run_count').notNull().default(0),
    verifiedDate: text('verified_date'),
    lastCheckedDate: text('last_checked_date'),
}, (table) => [
    index('idx_org_domains_org_id').on(table.organizationId),
    uniqueIndex('idx_org_domains_org_domain').on(table.organizationId, table.domainName),
]);

// ==================== SSO Configs ====================
// 对应 Core/Auth/Entities/SsoConfig.cs
export const ssoConfigs = sqliteTable('sso_configs', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(false),
    issuer: text('issuer'),
    clientId: text('client_id'),
    clientSecretEnv: text('client_secret_env'),
    redirectUri: text('redirect_uri'),
    claimMapping: text('claim_mapping'),
    data: text('data').notNull(),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    uniqueIndex('idx_sso_configs_org_id').on(table.organizationId),
]);

// ==================== OIDC Login Runtime ====================
// 外部 IdP state 与下游授权码只保存哈希并且单次消费，避免数据库泄露后可直接重放。
export const oidcLoginStates = sqliteTable('oidc_login_states', {
    stateHash: text('state_hash').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    nonce: text('nonce').notNull(),
    providerPkceVerifier: text('provider_pkce_verifier').notNull(),
    clientId: text('client_id').notNull(),
    clientRedirectUri: text('client_redirect_uri').notNull(),
    clientState: text('client_state'),
    clientCodeChallenge: text('client_code_challenge').notNull(),
    creationDate: text('creation_date').notNull(),
    expirationDate: text('expiration_date').notNull(),
    consumedDate: text('consumed_date'),
}, (table) => [
    index('idx_oidc_login_states_expiration').on(table.expirationDate),
]);

export const oidcAuthorizationCodes = sqliteTable('oidc_authorization_codes', {
    codeHash: text('code_hash').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    clientId: text('client_id').notNull(),
    redirectUri: text('redirect_uri').notNull(),
    codeChallenge: text('code_challenge').notNull(),
    creationDate: text('creation_date').notNull(),
    expirationDate: text('expiration_date').notNull(),
    consumedDate: text('consumed_date'),
}, (table) => [
    index('idx_oidc_authorization_codes_expiration').on(table.expirationDate),
]);

export const oidcIdentities = sqliteTable('oidc_identities', {
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    issuer: text('issuer').notNull(),
    subject: text('subject').notNull(),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    primaryKey({ columns: [table.organizationId, table.issuer, table.subject] }),
    uniqueIndex('idx_oidc_identities_org_user').on(table.organizationId, table.userId),
]);

// ==================== Duo Universal Prompt ====================
// Duo client secrets are encrypted with a Worker secret before being written to D1.
// Exactly one of userId/organizationId owns each configuration.
export const duoConfigs = sqliteTable('duo_configs', {
    id: text('id').primaryKey(),
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    organizationId: text('organization_id').references(() => organizations.id, { onDelete: 'cascade' }),
    clientId: text('client_id').notNull(),
    host: text('host').notNull(),
    clientSecretCiphertext: text('client_secret_ciphertext').notNull(),
    clientSecretIv: text('client_secret_iv').notNull(),
    clientSecretPrefix: text('client_secret_prefix').notNull(),
    keyVersion: integer('key_version').notNull().default(1),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    uniqueIndex('idx_duo_configs_user_id').on(table.userId)
        .where(sql`${table.userId} IS NOT NULL`),
    uniqueIndex('idx_duo_configs_organization_id').on(table.organizationId)
        .where(sql`${table.organizationId} IS NOT NULL`),
]);

// Raw state values are returned to the client. D1 stores only SHA-256 hashes and
// consumes each record atomically before exchanging the one-time Duo code.
export const duoLoginStates = sqliteTable('duo_login_states', {
    stateHash: text('state_hash').primaryKey(),
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    providerType: integer('provider_type').notNull(),
    organizationId: text('organization_id').references(() => organizations.id, { onDelete: 'cascade' }),
    configId: text('config_id').notNull().references(() => duoConfigs.id, { onDelete: 'cascade' }),
    configRevision: text('config_revision').notNull(),
    nonce: text('nonce').notNull(),
    redirectUri: text('redirect_uri').notNull(),
    creationDate: text('creation_date').notNull(),
    expirationDate: text('expiration_date').notNull(),
    consumedDate: text('consumed_date'),
}, (table) => [
    index('idx_duo_login_states_user').on(table.userId, table.providerType),
    index('idx_duo_login_states_expiration').on(table.expirationDate),
]);

// ==================== Organization Licenses ====================
// 用于持久化自建组织 license，保持与官方 OrganizationLicense 行为一致
export const organizationLicenses = sqliteTable('organization_licenses', {
    organizationId: text('organization_id')
        .primaryKey()
        .references(() => organizations.id, { onDelete: 'cascade' }),
    licenseKey: text('license_key').notNull(),
    licenseJson: text('license_json').notNull(),
    issued: text('issued'),
    expires: text('expires'),
    selfHost: integer('self_host', { mode: 'boolean' }),
    installationId: text('installation_id'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    uniqueIndex('idx_org_licenses_license_key').on(table.licenseKey),
]);

// ==================== Events ====================
// 对应 Core/Dirt/Entities/Event.cs 与 EventResponseModel
export const events = sqliteTable('events', {
    id: text('id').primaryKey(), // UUID
    type: integer('type').notNull(), // EventType enum
    userId: text('user_id'),
    organizationId: text('organization_id'),
    cipherId: text('cipher_id'),
    collectionId: text('collection_id'),
    groupId: text('group_id'),       // 事件目标群组（如 Group_Created/Updated/Deleted）
    organizationUserId: text('organization_user_id'), // 事件目标组织用户（如 Invited/Confirmed/Updated）
    actingUserId: text('acting_user_id'),
    date: text('date').notNull(), // ISO 8601
    deviceType: integer('device_type'), // DeviceType enum
    ipAddress: text('ip_address'),
    systemUser: integer('system_user'),
}, (table) => [
    index('idx_events_organization_id').on(table.organizationId),
    index('idx_events_date').on(table.date),
]);

// ==================== Organization Users ====================
// 对应 Core/Entities/OrganizationUser.cs
export const organizationUsers = sqliteTable('organization_users', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    userId: text('user_id').references(() => users.id, { onDelete: 'cascade' }),
    email: text('email').notNull(),
    key: text('key'), // 加密的 org key
    resetPasswordKey: text('reset_password_key'), // 密码重置密钥
    status: integer('status').notNull().default(2), // 0=Invited,1=Accepted,2=Confirmed,3=Revoked
    type: integer('type').notNull().default(2), // 0=Owner,1=Admin,2=User,3=Manager,4=Custom
    permissions: text('permissions'), // JSON - 权限控制
    externalId: text('external_id'), // SSO external ID
    accessSecretsManager: integer('access_secrets_manager', { mode: 'boolean' }).default(false),
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

// ==================== Groups ====================
// 对应 Core/AdminConsole/Entities/Group.cs
export const groups = sqliteTable('groups', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    externalId: text('external_id'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_groups_org_id').on(table.organizationId),
]);

// ==================== Group Users ====================
// 对应 Core/AdminConsole/Entities/GroupUser.cs
export const groupUsers = sqliteTable('group_users', {
    groupId: text('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    organizationUserId: text('organization_user_id').notNull().references(() => organizationUsers.id, { onDelete: 'cascade' }),
}, (table) => [
    primaryKey({ columns: [table.groupId, table.organizationUserId] }),
    index('idx_group_users_org_user_id').on(table.organizationUserId),
]);

// ==================== Collection Groups ====================
// 对应 Core/Entities/CollectionGroup.cs
export const collectionGroups = sqliteTable('collection_groups', {
    collectionId: text('collection_id').notNull().references(() => collections.id, { onDelete: 'cascade' }),
    groupId: text('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    readOnly: integer('read_only', { mode: 'boolean' }).default(false),
    hidePasswords: integer('hide_passwords', { mode: 'boolean' }).default(false),
    manage: integer('manage', { mode: 'boolean' }).default(false),
}, (table) => [
    primaryKey({ columns: [table.collectionId, table.groupId] }),
    index('idx_collection_groups_group_id').on(table.groupId),
]);

// ==================== Auth Requests ====================
// 对应 Core/Auth/Entities/AuthRequest.cs
// 用于 Passwordless Login（使用其他设备登录）
export const authRequests = sqliteTable('auth_requests', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    organizationId: text('organization_id').references(() => organizations.id, { onDelete: 'cascade' }),
    type: integer('type').notNull().default(0), // 0=AuthenticateAndUnlock, 1=Unlock, 2=AdminApproval
    requestDeviceIdentifier: text('request_device_identifier').notNull(),
    requestDeviceType: integer('request_device_type').notNull(),
    requestIpAddress: text('request_ip_address'),
    responseDeviceId: text('response_device_id').references(() => devices.id),
    accessCode: text('access_code').notNull(),
    publicKey: text('public_key').notNull(),
    key: text('key'),
    masterPasswordHash: text('master_password_hash'),
    approved: integer('approved', { mode: 'boolean' }), // null=pending, true=approved, false=denied
    creationDate: text('creation_date').notNull(), // ISO 8601
    responseDate: text('response_date'),
    authenticationDate: text('authentication_date'),
}, (table) => [
    index('idx_auth_requests_user_id').on(table.userId),
    index('idx_auth_requests_organization_id').on(table.organizationId),
]);

// ==================== WebAuthn Credentials ====================
// 对应 Core/Auth/Entities/WebAuthnCredential.cs
// 用于 Passkey 登录（非 2FA），独立于 twoFactorProviders
export const webAuthnCredentials = sqliteTable('webauthn_credentials', {
    id: text('id').primaryKey(), // UUID
    userId: text('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    name: text('name').notNull(),
    publicKey: text('public_key').notNull(), // Base64URL encoded COSE public key
    credentialId: text('credential_id').notNull(), // Base64URL encoded credential ID
    counter: integer('counter').notNull().default(0),
    type: text('type').notNull().default('public-key'),
    aaGuid: text('aa_guid'),
    supportsPrf: integer('supports_prf', { mode: 'boolean' }).notNull().default(false),
    encryptedUserKey: text('encrypted_user_key'),
    encryptedPrivateKey: text('encrypted_private_key'),
    encryptedPublicKey: text('encrypted_public_key'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_webauthn_credentials_user_id').on(table.userId),
    index('idx_webauthn_credentials_credential_id').on(table.credentialId),
]);

// ==================== Policies ====================
// 对应 Core/AdminConsole/Entities/Policy.cs
export const policies = sqliteTable('policies', {
    id: text('id').primaryKey(), // UUID
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    type: integer('type').notNull(), // PolicyType enum (0=TwoFactorAuthentication, 1=MasterPassword, ...)
    data: text('data'), // JSON
    enabled: integer('enabled', { mode: 'boolean' }).notNull().default(false),
    creationDate: text('creation_date').notNull(), // ISO 8601
    revisionDate: text('revision_date').notNull(), // ISO 8601
}, (table) => [
    index('idx_policies_organization_id').on(table.organizationId),
]);

// ==================== Organization Reports ====================
// 对应 Core/Dirt/Entities/OrganizationReport.cs
export const organizationReports = sqliteTable('organization_reports', {
    id: text('id').primaryKey(), // UUID
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    reportData: text('report_data').notNull().default(''),
    contentEncryptionKey: text('content_encryption_key').notNull().default(''),
    summaryData: text('summary_data'),
    applicationData: text('application_data'),
    reportFile: text('report_file'),
    applicationCount: integer('application_count'),
    applicationAtRiskCount: integer('application_at_risk_count'),
    criticalApplicationCount: integer('critical_application_count'),
    criticalApplicationAtRiskCount: integer('critical_application_at_risk_count'),
    memberCount: integer('member_count'),
    memberAtRiskCount: integer('member_at_risk_count'),
    criticalMemberCount: integer('critical_member_count'),
    criticalMemberAtRiskCount: integer('critical_member_at_risk_count'),
    passwordCount: integer('password_count'),
    passwordAtRiskCount: integer('password_at_risk_count'),
    criticalPasswordCount: integer('critical_password_count'),
    criticalPasswordAtRiskCount: integer('critical_password_at_risk_count'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_org_reports_org_id').on(table.organizationId),
]);

// ==================== Password Health Report Applications ====================
// 对应 Core/Dirt/Entities/PasswordHealthReportApplication.cs
export const passwordHealthReportApplications = sqliteTable('password_health_report_applications', {
    id: text('id').primaryKey(),
    organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
    uri: text('uri'),
    creationDate: text('creation_date').notNull(),
    revisionDate: text('revision_date').notNull(),
}, (table) => [
    index('idx_pwd_health_apps_org_id').on(table.organizationId),
]);

// ==================== 推断类型（供路由等使用，避免 any） ====================
export type OrganizationUserRow = typeof organizationUsers.$inferSelect;
export type OrganizationRow = typeof organizations.$inferSelect;
export type UserRow = typeof users.$inferSelect;
export type PolicyRow = typeof policies.$inferSelect;
export type OrganizationReportRow = typeof organizationReports.$inferSelect;
export type PasswordHealthReportApplicationRow = typeof passwordHealthReportApplications.$inferSelect;
export type OrganizationInviteLinkRow = typeof organizationInviteLinks.$inferSelect;
export type OrganizationDomainRow = typeof organizationDomains.$inferSelect;
export type SsoConfigRow = typeof ssoConfigs.$inferSelect;
