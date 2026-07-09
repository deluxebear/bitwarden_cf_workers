/**
 * Bitwarden Workers - 类型定义
 * 对应原始项目的 Core/Entities + Core/Enums
 * 已对齐官方 Bitwarden Server 响应模型
 */

// Cloudflare Workers 环境绑定
export type Bindings = {
    DB: D1Database;
    JWT_SECRET: string;
    JWT_EXPIRATION: string;
    JWT_REFRESH_EXPIRATION: string;
    ATTACHMENTS: R2Bucket;
    ICONS_CACHE: KVNamespace;
    NOTIFICATION_HUB: DurableObjectNamespace;
    EMAIL?: SendEmail;
    GLOBAL_PREMIUM?: string;
    /**
     * 可选：用于自建许可证校验的 InstallationId。
     * 如果设置，将与 license.InstallationId 进行比对，保持与官方一致的校验行为。
     */
    INSTALLATION_ID?: string;
    /**
     * 可选：Web Vault 前端地址，用于生成邀请链接。
     * 例如 https://vault.example.com 或 http://localhost:8080（末尾不要 /#）
     * 未设置时邀请链接使用占位符，需管理员自行替换。
     */
    VAULT_BASE_URL?: string;
    /**
     * 可选：设为 "true" 时，邀请链接一律走「注册」流程（finish-signup），被邀请人需设置主密钥。
     * 适用于：被邀请邮箱尚未注册、或希望被邀请人用邀请链接重新设置密码的场景。
     * 不设置或非 "true" 时：若该邮箱已在 users 表存在则走「登录」，否则走「注册」。
     */
    FORCE_INVITE_REGISTER?: string;
    /**
     * 控制开放注册行为。
     * "true"  - 始终允许开放注册
     * "false" - 始终禁止开放注册（仅邀请注册有效）
     * "auto"  - 当系统中尚无用户时允许注册，有用户后自动关闭（默认）
     */
    SIGNUPS_ALLOWED?: string;
    /**
     * 邮件投递模式：
     * "disabled" - 禁用邮件；除非 EMAIL_RETURN_TOKENS=true，否则相关接口返回明确错误
     * "log"      - 本地开发默认，token 写入日志并在响应中回显
     * "cloudflare" - 使用 Cloudflare Email Service send_email binding
     * "provider" - POST 到 EMAIL_PROVIDER_ENDPOINT
     */
    EMAIL_MODE?: string;
    /**
     * EMAIL_MODE=cloudflare 时的发件人，例如 no-reply@example.com 或 "Bitwarden <no-reply@example.com>"。
     * 发件域名必须已在 Cloudflare Email Service 中完成 Email Sending onboarding。
     */
    EMAIL_FROM?: string;
    /**
     * 可选：EMAIL_MODE=cloudflare 时单独指定显示名称。
     */
    EMAIL_FROM_NAME?: string;
    /**
     * 可选：EMAIL_MODE=cloudflare 时的 Reply-To。
     */
    EMAIL_REPLY_TO?: string;
    /**
     * 本地/测试兼容：为 true 时在响应中回显邮件 token。
     */
    EMAIL_RETURN_TOKENS?: string;
    /**
     * EMAIL_MODE=provider 时的通用邮件 provider webhook。
     */
    EMAIL_PROVIDER_ENDPOINT?: string;
    EMAIL_PROVIDER_TOKEN?: string;
    /**
     * Icons 成功缓存 TTL（秒），默认 1209600（14天）
     */
    ICONS_CACHE_SUCCESS_TTL_SECONDS?: string;
    /**
     * Icons 负缓存 TTL（秒），默认 43200（12小时）
     */
    ICONS_CACHE_NEGATIVE_TTL_SECONDS?: string;
    /**
     * 最大可缓存 icon 大小（字节），默认 51200（50KB）
     */
    ICONS_MAX_IMAGE_BYTES?: string;
    /**
     * Email 2FA 投递方式。当前 Workers 内置实现仅支持 "console"：
     * 生成验证码后写入日志，供自托管管理员接入真实邮件服务前调试。
     */
    TWO_FACTOR_EMAIL_DELIVERY?: string;
    /**
     * 兼容开关：设为 "true" 时等价于 TWO_FACTOR_EMAIL_DELIVERY=console。
     */
    TWO_FACTOR_EMAIL_DEBUG?: string;
    /**
     * Notification Center 内部 /send 入口的 Bearer token。
     * 未配置时 /send 返回 404，避免公开暴露通知投递入口。
     */
    NOTIFICATIONS_SEND_TOKEN?: string;
    /**
     * 自部署系统管理员邮箱列表，逗号分隔。
     * 用于服务器级账号管理入口；未设置时使用数据库中最早注册用户作为 bootstrap 管理员。
     */
    SYSTEM_ADMIN_EMAILS?: string;
    /**
     * 兼容旧配置名，语义同 SYSTEM_ADMIN_EMAILS。
     */
    ADMIN_EMAILS?: string;
};

// Hono 应用变量
export type Variables = {
    userId: string;
    email: string;
    jwtPayload: JwtPayload;
    requestId: string;
};

// JWT Payload
export interface JwtPayload {
    sub: string; // user id
    email: string;
    email_verified: boolean;
    name: string;
    premium: boolean;
    iss: string;
    nbf: number;
    exp: number;
    iat: number;
    // Bitwarden specific claims
    sstamp: string; // security stamp
    device: string;
    scope: string[];
    amr: string[];
}

// KDF 类型 - 对应原始 KdfType enum
export enum KdfType {
    PBKDF2_SHA256 = 0,
    Argon2id = 1,
}

// Cipher 类型 - 对应原始 CipherType enum
export enum CipherType {
    Login = 1,
    SecureNote = 2,
    Card = 3,
    Identity = 4,
    SSHKey = 5,
}

// CipherRepromptType
export enum CipherRepromptType {
    None = 0,
    Password = 1,
}

// DeviceType - 对应原始 DeviceType enum
export enum DeviceType {
    Android = 0,
    iOS = 1,
    ChromeExtension = 2,
    FirefoxExtension = 3,
    OperaExtension = 4,
    EdgeExtension = 5,
    WindowsDesktop = 6,
    MacOsDesktop = 7,
    LinuxDesktop = 8,
    ChromeBrowser = 9,
    FirefoxBrowser = 10,
    OperaBrowser = 11,
    EdgeBrowser = 12,
    IEBrowser = 13,
    UnknownBrowser = 14,
    AndroidAmazon = 15,
    UWP = 16,
    SafariBrowser = 17,
    VivaldiBrowser = 18,
    VivaldiExtension = 19,
    SafariExtension = 20,
    SDK = 21,
    Server = 22,
    WindowsCLI = 23,
    MacOsCLI = 24,
    LinuxCLI = 25,
}

// GrantType - OAuth2 grant types Bitwarden 使用的
export enum GrantType {
    Password = 'password',
    RefreshToken = 'refresh_token',
    ClientCredentials = 'client_credentials',
    AuthorizationCode = 'authorization_code',
    WebAuthn = 'webauthn',
    SendAccess = 'send_access',
}

// ------------- API 请求/响应模型 -------------

// Prelogin - 对应 PasswordPreloginResponseModel.cs
export interface PreloginRequest {
    email: string;
}

export interface PreloginResponse {
    kdf: KdfType;
    kdfIterations: number;
    kdfMemory?: number | null;
    kdfParallelism?: number | null;
    // 新版字段
    kdfSettings: KdfSettings;
    salt: string | null;
}

export interface KdfSettings {
    kdfType: KdfType;
    iterations: number;
    memory?: number | null;
    parallelism?: number | null;
}

// Register
export interface RegisterRequest {
    name?: string;
    email: string;
    masterPasswordHash: string;
    masterPasswordHint?: string;
    key: string; // encrypted user key
    keys: {
        publicKey: string;
        encryptedPrivateKey: string;
    };
    kdf: KdfType;
    kdfIterations: number;
    kdfMemory?: number;
    kdfParallelism?: number;
}

// Token (Login)
export interface TokenRequest {
    grant_type: GrantType;
    username?: string;
    password?: string; // master password hash, or access code for auth request flow
    scope?: string;
    client_id?: string;
    deviceType?: number;
    deviceIdentifier?: string;
    deviceName?: string;
    refresh_token?: string;
    code?: string;
    code_verifier?: string;
    redirect_uri?: string;
    authRequest?: string;
    TwoFactorProvider?: number;
    TwoFactorToken?: string;
    TwoFactorRemember?: number;
    twoFactorProvider?: number;
    twoFactorToken?: string;
}

export interface TokenResponse {
    access_token: string;
    expires_in: number;
    token_type: string;
    refresh_token: string;
    Key: string; // encrypted user key
    PrivateKey: string;
    Kdf: KdfType;
    KdfIterations: number;
    KdfMemory?: number | null;
    KdfParallelism?: number | null;
    ResetMasterPassword: boolean;
    ForcePasswordReset: boolean;
    scope: string;
    unofficialServer: boolean;
    UserDecryptionOptions: UserDecryptionOptions;
}

export interface UserDecryptionOptions {
    hasMasterPassword: boolean;
}

// Profile - 对应 ProfileResponseModel.cs
export interface ProfileResponse {
    id: string;
    name: string | null;
    email: string;
    emailVerified: boolean;
    premium: boolean;
    premiumFromOrganization: boolean;
    masterPasswordHint: string | null;
    culture: string;
    twoFactorEnabled: boolean;
    key: string | null;
    privateKey: string | null;
    accountKeys: AccountKeysResponse | null;
    securityStamp: string;
    forcePasswordReset: boolean;
    usesKeyConnector: boolean;
    avatarColor: string | null;
    creationDate: string;
    verifyDevices: boolean;
    object: string;
    organizations: any[];
    providers: any[];
    providerOrganizations: any[];
}

export interface PublicKeyEncryptionKeyPairResponse {
    publicKey: string;
    wrappedPrivateKey: string;
    signedPublicKey: string | null;
}

export interface AccountKeysResponse {
    publicKeyEncryptionKeyPair: PublicKeyEncryptionKeyPairResponse;
    signatureKeyPair: any | null;
    securityState: any | null;
    object: string;
}

// Cipher 请求/响应 - 对应 CipherResponseModel.cs
export interface CipherRequest {
    type: CipherType;
    folderId?: string | null;
    organizationId?: string | null;
    name: string; // encrypted
    notes?: string | null; // encrypted
    favorite?: boolean;
    reprompt?: CipherRepromptType;
    login?: any;
    card?: any;
    identity?: any;
    secureNote?: any;
    sshKey?: any;
    fields?: any[];
    passwordHistory?: any[];
    attachments?: any[] | null;
    key?: string;
    collectionIds?: string[];
}

export interface CipherResponse {
    id: string;
    organizationId: string | null;
    folderId: string | null;
    type: CipherType;
    data: string; // 原始加密 JSON 数据字符串
    name: string;
    notes: string | null;
    favorite: boolean;
    reprompt: CipherRepromptType;
    login?: any;
    card?: any;
    identity?: any;
    secureNote?: any;
    sshKey?: any;
    fields: any[] | null;
    passwordHistory: any[] | null;
    attachments: any[] | null;
    organizationUseTotp: boolean;
    revisionDate: string;
    creationDate: string;
    deletedDate: string | null;
    archivedDate: string | null;
    key: string | null;
    object: string;
    collectionIds: string[];
    edit: boolean;
    viewPassword: boolean;
    permissions: CipherPermissions | null;
}

export interface CipherPermissions {
    delete: boolean;
    restore: boolean;
    edit: boolean;
    viewPassword: boolean;
    manage: boolean;
}

// Folder 请求/响应
export interface FolderRequest {
    name: string; // encrypted
}

export interface FolderResponse {
    id: string;
    name: string;
    revisionDate: string;
    object: string;
}

// Sync 响应 - 对应 SyncResponseModel.cs
export interface SyncResponse {
    profile: ProfileResponse;
    folders: FolderResponse[];
    ciphers: CipherResponse[];
    collections: any[];
    domains: DomainsResponse | null;
    policies: any[];
    sends: SendResponse[];
    userDecryption: UserDecryptionResponse | null;
    object: string;
}

export interface UserDecryptionResponse {
    masterPasswordUnlock: MasterPasswordUnlockResponse | null;
    webAuthnPrfOptions: any[] | null;
    v2UpgradeToken: any | null;
}

export interface MasterPasswordUnlockResponse {
    kdf: KdfSettings;
    masterKeyEncryptedUserKey: string;
    salt: string;
}

export interface DomainsResponse {
    equivalentDomains: string[][] | null;
    globalEquivalentDomains: GlobalEquivalentDomain[];
    object: string;
}

export interface GlobalEquivalentDomain {
    type: number;
    domains: string[];
    excluded: boolean;
}

// ------------- Send 类型 - 对应 Core/Tools/Entities/Send.cs -------------

export enum SendType {
    Text = 0,
    File = 1,
}

export interface SendRequest {
    type: SendType;
    key: string;
    name?: string;
    notes?: string;
    text?: { text: string; hidden: boolean } | null;
    file?: any | null;
    maxAccessCount?: number | null;
    expirationDate?: string | null;
    deletionDate: string;
    password?: string | null;
    emails?: string | null;
    authType?: number | null;
    disabled?: boolean;
    hideEmail?: boolean;
}

export interface SendResponse {
    id: string;
    accessId: string;
    userId: string | null;
    type: SendType;
    authType: number;
    name: string | null;
    notes: string | null;
    text?: { text: string; hidden: boolean } | null;
    file?: { id: string | null; fileName: string | null; size: string | null; sizeName: string | null } | null;
    key: string | null;
    maxAccessCount: number | null;
    accessCount: number;
    revisionDate: string;
    expirationDate: string | null;
    deletionDate: string;
    password: string | null; // 客户端只需知道是否有密码
    emails?: string | null;
    disabled: boolean;
    hideEmail: boolean | null;
    object: string;
}

export interface SendAccessResponse {
    id: string;
    type: SendType;
    name: string | null;
    text?: { text: string; hidden: boolean } | null;
    file?: { id: string | null; fileName: string | null; size: string | null; sizeName: string | null } | null;
    key: string | null;
    expirationDate: string | null;
    creatorIdentifier?: string;
    object: string;
}

// ------------- Auth Request 类型 - 对应 Core/Auth/Enums/AuthRequestType.cs -------------

export enum AuthRequestType {
    AuthenticateAndUnlock = 0,
    Unlock = 1,
    AdminApproval = 2,
}

export interface AuthRequestCreateRequest {
    email: string;
    publicKey: string;
    deviceIdentifier: string;
    accessCode: string;
    type: AuthRequestType;
}

export interface AuthRequestUpdateRequest {
    key?: string;
    masterPasswordHash?: string;
    deviceIdentifier: string;
    requestApproved: boolean;
}

// ------------- 两步验证 (2FA) 类型 -------------

export enum TwoFactorProviderType {
    Authenticator = 0,
    Email = 1,
    Duo = 2,
    YubiKey = 3,
    U2f = 4,
    Remember = 5,
    OrganizationDuo = 6,
    WebAuthn = 7
}

export interface TwoFactorProvider {
    metaData: Record<string, any>;
    enabled: boolean;
}

export interface TwoFactorProviderResponse {
    type: number;
    enabled: boolean;
    object: string;
}

export interface TwoFactorAuthenticatorResponse {
    enabled: boolean;
    key: string;
    userVerificationToken?: string | null;
    object: string;
}

export interface TwoFactorRecoverResponse {
    code: string;
    object: string;
}
