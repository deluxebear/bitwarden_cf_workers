/**
 * Bitwarden Workers - Sync 路由
 * 对应原始项目 Api/Vault/Controllers/SyncController.cs
 * 全量同步端点 - 客户端首次加载或检测到变更后调用
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq } from 'drizzle-orm';
import { users, ciphers, folders } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { NotFoundError } from '../middleware/error';
import type {
    Bindings, Variables, CipherType, CipherRepromptType,
    ProfileResponse, SyncResponse, GlobalEquivalentDomain,
    AccountKeysResponse, UserDecryptionResponse, KdfSettings,
} from '../types';

const sync = new Hono<{ Bindings: Bindings; Variables: Variables }>();

sync.use('/*', authMiddleware);

// Bitwarden 内置的全局等价域名（简化版）
const GLOBAL_EQUIVALENT_DOMAINS: GlobalEquivalentDomain[] = [
    { type: 0, domains: ['youtube.com', 'google.com', 'gmail.com'], excluded: false },
    { type: 1, domains: ['apple.com', 'icloud.com'], excluded: false },
    { type: 2, domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.co.jp', 'amazon.in'], excluded: false },
    { type: 3, domains: ['live.com', 'microsoft.com', 'microsoftonline.com', 'outlook.com', 'hotmail.com'], excluded: false },
    { type: 4, domains: ['steam.com', 'steampowered.com', 'steamcommunity.com', 'steamgames.com'], excluded: false },
];

/**
 * GET /api/sync
 * 对应 SyncController.Get
 * 返回用户的完整密码库数据
 */
sync.get('/', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const excludeDomains = c.req.query('excludeDomains') === 'true';

    const user = await db.select().from(users).where(eq(users.id, userId)).get();
    if (!user) throw new NotFoundError('User not found.');

    // 获取所有文件夹
    const userFolders = await db.select().from(folders).where(eq(folders.userId, userId)).all();

    // 获取所有 ciphers（包括已删除的，客户端需要知道）
    const userCiphers = await db.select().from(ciphers)
        .where(eq(ciphers.userId, userId)).all();

    // 构建 accountKeys
    const accountKeys: AccountKeysResponse | null = (user.publicKey || user.privateKey) ? {
        accountPublicKey: user.publicKey || null,
        accountEncryptedPrivateKey: user.privateKey || null,
        signedPublicKey: user.signedPublicKey || null,
        object: 'accountKeys',
    } : null;

    // 构建 profile - 对应 ProfileResponseModel
    const profile: ProfileResponse = {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        premium: user.premium,
        premiumFromOrganization: false,
        masterPasswordHint: user.masterPasswordHint,
        culture: user.culture,
        twoFactorEnabled: false,
        key: user.key,
        privateKey: user.privateKey,
        accountKeys,
        securityStamp: user.securityStamp,
        forcePasswordReset: user.forcePasswordReset,
        usesKeyConnector: user.usesKeyConnector,
        avatarColor: user.avatarColor,
        creationDate: user.creationDate,
        verifyDevices: true,
        object: 'profile',
        organizations: [],
        providers: [],
        providerOrganizations: [],
    };

    // 构建 ciphers 响应 - 对应 CipherDetailsResponseModel
    const cipherResponses = userCiphers.map((cipher) => {
        const data = JSON.parse(cipher.data || '{}');
        const favorites = cipher.favorites ? JSON.parse(cipher.favorites) : {};
        const foldersMap = cipher.folders ? JSON.parse(cipher.folders) : {};

        return {
            id: cipher.id,
            organizationId: cipher.organizationId,
            folderId: foldersMap[userId] || null,
            type: cipher.type as CipherType,
            data: data, // 原始 JSON - CipherMiniResponseModel 必返回
            name: data.name || '',
            notes: data.notes || null,
            favorite: !!favorites[userId],
            reprompt: (cipher.reprompt ?? 0) as CipherRepromptType,
            login: cipher.type === 1 ? data.login : undefined,
            card: cipher.type === 3 ? data.card : undefined,
            identity: cipher.type === 4 ? data.identity : undefined,
            secureNote: cipher.type === 2 ? data.secureNote : undefined,
            sshKey: cipher.type === 5 ? data.sshKey : undefined,
            fields: data.fields || null,
            passwordHistory: data.passwordHistory || null,
            attachments: null,
            organizationUseTotp: false,
            revisionDate: cipher.revisionDate,
            creationDate: cipher.creationDate,
            deletedDate: cipher.deletedDate,
            archivedDate: null,
            key: cipher.key,
            object: 'cipherDetails',
            collectionIds: [],
            edit: true,
            viewPassword: true,
            permissions: {
                delete: true,
                restore: true,
                edit: true,
                viewPassword: true,
                manage: true,
            },
        };
    });

    // 构建 folders 响应
    const folderResponses = userFolders.map((folder) => ({
        id: folder.id,
        name: folder.name || '',
        revisionDate: folder.revisionDate,
        object: 'folder',
    }));

    // 构建 UserDecryption - 对应 SyncResponseModel 的 UserDecryption 字段
    const kdfSettings: KdfSettings = {
        kdfType: user.kdf as any,
        iterations: user.kdfIterations,
        memory: user.kdfMemory,
        parallelism: user.kdfParallelism,
    };

    const userDecryption: UserDecryptionResponse = {
        masterPasswordUnlock: user.masterPassword ? {
            kdf: kdfSettings,
            masterKeyEncryptedUserKey: user.key || '',
            salt: user.email.toLowerCase(),
        } : null,
        webAuthnPrfOptions: null,
        v2UpgradeToken: null,
    };

    const response: SyncResponse = {
        profile,
        folders: folderResponses,
        ciphers: cipherResponses,
        collections: [],
        domains: excludeDomains ? null : {
            equivalentDomains: user.equivalentDomains ? JSON.parse(user.equivalentDomains) : null,
            globalEquivalentDomains: GLOBAL_EQUIVALENT_DOMAINS,
            object: 'domains',
        },
        policies: [],
        sends: [],
        userDecryption,
        object: 'sync',
    };

    return c.json(response);
});

export default sync;
