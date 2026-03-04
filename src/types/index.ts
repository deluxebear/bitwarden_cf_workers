/**
 * Bitwarden Workers - 类型定义
 * 对应原始项目的 Core/Entities + Core/Enums
 */

// Cloudflare Workers 环境绑定
export type Bindings = {
    DB: D1Database;
    JWT_SECRET: string;
    JWT_EXPIRATION: string;
    JWT_REFRESH_EXPIRATION: string;
};

// Hono 应用变量
export type Variables = {
    userId: string;
    email: string;
    jwtPayload: JwtPayload;
};

// JWT Payload
export interface JwtPayload {
    sub: string; // user id
    email: string;
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

// Prelogin
export interface PreloginRequest {
    email: string;
}

export interface PreloginResponse {
    kdf: KdfType;
    kdfIterations: number;
    kdfMemory?: number | null;
    kdfParallelism?: number | null;
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

// Profile
export interface ProfileResponse {
    id: string;
    name: string | null;
    email: string;
    emailVerified: boolean;
    premium: boolean;
    masterPasswordHint: string | null;
    culture: string;
    twoFactorEnabled: boolean;
    key: string | null;
    privateKey: string | null;
    securityStamp: string;
    forcePasswordReset: boolean;
    usesKeyConnector: boolean;
    avatarColor: string | null;
    creationDate: string;
    object: string;
    organizations: any[];
    providers: any[];
    providerOrganizations: any[];
}

// Cipher 请求/响应
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
    key?: string | null;
}

export interface CipherResponse {
    id: string;
    organizationId: string | null;
    folderId: string | null;
    type: CipherType;
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
    key: string | null;
    object: string;
    edit: boolean;
    viewPassword: boolean;
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

// Sync 响应
export interface SyncResponse {
    profile: ProfileResponse;
    folders: FolderResponse[];
    ciphers: CipherResponse[];
    collections: any[];
    domains: DomainsResponse | null;
    policies: any[];
    sends: any[];
    object: string;
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
