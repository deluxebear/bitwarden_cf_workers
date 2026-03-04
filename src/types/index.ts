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
    password?: string; // master password hash
    scope?: string;
    client_id?: string;
    deviceType?: number;
    deviceIdentifier?: string;
    deviceName?: string;
    refresh_token?: string;
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
    key?: string;
    collectionIds?: string[];
}

export interface CipherResponse {
    id: string;
    organizationId: string | null;
    folderId: string | null;
    type: CipherType;
    data: any; // 原始加密 JSON 数据
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
    file?: { id: string | null; fileName: string | null; size: number | null; sizeName: string | null } | null;
    key: string | null;
    maxAccessCount: number | null;
    accessCount: number;
    revisionDate: string;
    expirationDate: string | null;
    deletionDate: string;
    password: string | null; // 客户端只需知道是否有密码
    disabled: boolean;
    hideEmail: boolean | null;
    object: string;
}

export interface SendAccessResponse {
    id: string;
    type: SendType;
    name: string | null;
    text?: { text: string; hidden: boolean } | null;
    file?: { id: string | null; fileName: string | null; size: number | null; sizeName: string | null } | null;
    key: string | null;
    expirationDate: string | null;
    creatorIdentifier?: string;
    object: string;
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
