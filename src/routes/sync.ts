/**
 * Bitwarden Workers - Sync 路由
 * 对应原始项目 Api/Vault/Controllers/SyncController.cs
 * 全量同步端点 - 客户端首次加载或检测到变更后调用
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, inArray } from 'drizzle-orm';
import { users, ciphers, folders, sends, organizations, organizationUsers, collections, collectionCiphers } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { NotFoundError } from '../middleware/error';
import type {
    Bindings, Variables, CipherType, CipherRepromptType, SendType,
    ProfileResponse, SyncResponse, GlobalEquivalentDomain,
    AccountKeysResponse, UserDecryptionResponse, KdfSettings, SendResponse,
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

    // 获取 sends
    const now = new Date().toISOString();
    const userSends = await db.select().from(sends)
        .where(eq(sends.userId, userId)).all();
    const activeSends = userSends.filter(s => s.deletionDate > now);

    // 构建 accountKeys
    const accountKeys: AccountKeysResponse | null = (user.publicKey && user.privateKey) ? {
        publicKeyEncryptionKeyPair: {
            publicKey: user.publicKey,
            wrappedPrivateKey: user.privateKey,
            signedPublicKey: user.signedPublicKey || null,
        },
        signatureKeyPair: null,
        securityState: null,
        object: 'privateKeys',
    } : null;

    // 计算 twoFactorEnabled
    function hasTwoFactor(u: any): boolean {
        if (!u.twoFactorProviders) return false;
        try {
            const p = JSON.parse(u.twoFactorProviders);
            return Object.values(p).some((v: any) => v.enabled);
        } catch { return false; }
    }

    // 构建 profile - 对应 ProfileResponseModel
    const globalPremium = String(c.env.GLOBAL_PREMIUM).toLowerCase() === 'true';
    const hasPremiumPersonally = user.premium || globalPremium;

    const profile: ProfileResponse = {
        id: user.id,
        name: user.name,
        email: user.email,
        emailVerified: user.emailVerified,
        premium: hasPremiumPersonally,
        premiumFromOrganization: false, // 会在组织查询后更新
        masterPasswordHint: user.masterPasswordHint,
        culture: user.culture,
        twoFactorEnabled: hasTwoFactor(user),
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

    // 查询个人 ciphers 的 collectionIds（个人 cipher 通常无 collection，但确保正确）
    const personalCipherIds = userCiphers.map(c => c.id);
    const personalCipherCollectionMap: Record<string, string[]> = {};
    if (personalCipherIds.length > 0) {
        const personalCipherCollections = await db.select().from(collectionCiphers)
            .where(inArray(collectionCiphers.cipherId, personalCipherIds))
            .all();
        for (const cc of personalCipherCollections) {
            if (!personalCipherCollectionMap[cc.cipherId]) personalCipherCollectionMap[cc.cipherId] = [];
            personalCipherCollectionMap[cc.cipherId].push(cc.collectionId);
        }
    }

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

    // 获取组织信息
    const orgsData = await db
        .select({
            org: organizations,
            orgUser: organizationUsers,
        })
        .from(organizationUsers)
        .innerJoin(organizations, eq(organizations.id, organizationUsers.organizationId))
        .where(eq(organizationUsers.userId, userId))
        .all();

    const profileOrganizations = orgsData.map(d => ({
        id: d.org.id,
        name: d.org.name,
        key: d.orgUser.key,
        status: d.orgUser.status,
        type: d.orgUser.type,
        enabled: d.org.enabled,
        useTotp: d.org.useTotp ?? true,
        use2fa: true,
        useApi: true,
        useSso: false,
        useKeyConnector: false,
        useScim: false,
        useGroups: false,
        useDirectory: false,
        useEvents: true,
        usePolicies: true,
        useResetPassword: false,
        useCustomPermissions: false,
        useActivateAutofillPolicy: false,
        useRiskInsights: false,
        useOrganizationDomains: false,
        useAdminSponsoredFamilies: false,
        useSecretsManager: false,
        usePhishingBlocker: false,
        useDisableSMAdsForUsers: false,
        usePasswordManager: true,
        useMyItems: true,
        useAutomaticUserConfirmation: false,
        usersGetPremium: hasPremiumPersonally || (d.org.planType ?? 0) >= 1,
        keyConnectorEnabled: false,
        maxStorageGb: d.org.maxStorageGb ?? 1,
        seats: d.org.seats ?? 0,
        maxCollections: null,
        accessSecretsManager: false,
        planProductType: d.org.planType ?? 0,
        permissions: d.orgUser.permissions ? JSON.parse(d.orgUser.permissions) : null,
        object: 'profileOrganization',
    }));

    // 如果用户有组织，获取 Collections 和所有相关的 Ciphers
    const myCollections: any[] = [];
    const orgCiphersData: any[] = [];
    // 记录每个 cipher 对应的 collectionIds
    const cipherCollectionMap: Record<string, string[]> = {};
    const orgIds = orgsData.map(o => o.org.id);

    if (orgIds.length > 0) {
        // 支持多组织：用 inArray 查询所有组织的 collections
        const orgCollections = await db.select().from(collections)
            .where(inArray(collections.organizationId, orgIds))
            .all();

        for (const col of orgCollections) {
            myCollections.push({
                id: col.id,
                organizationId: col.organizationId,
                name: col.name,
                revisionDate: col.revisionDate,
                hidePasswords: false,
                readOnly: false,
                object: 'collection',
            });

            const collectionCipherRelations = await db.select().from(collectionCiphers)
                .where(eq(collectionCiphers.collectionId, col.id))
                .all();

            const cipherIdsInCollection = collectionCipherRelations.map(cc => cc.cipherId);

            // 记录 cipher -> collectionIds 映射
            for (const cipherId of cipherIdsInCollection) {
                if (!cipherCollectionMap[cipherId]) cipherCollectionMap[cipherId] = [];
                cipherCollectionMap[cipherId].push(col.id);
            }

            if (cipherIdsInCollection.length > 0) {
                const ciphersInCollection = await db.select().from(ciphers)
                    .where(inArray(ciphers.id, cipherIdsInCollection))
                    .all();
                orgCiphersData.push(...ciphersInCollection);
            }
        }
    }

    profile.organizations = profileOrganizations;

    // 更新 premiumFromOrganization: 如果任何启用的组织授予 premium
    const premiumFromOrg = profileOrganizations.some(o => o.enabled && o.usersGetPremium);
    if (premiumFromOrg) {
        profile.premiumFromOrganization = true;
        profile.premium = true; // 组织授予的 premium 也算 premium
    }

    // 构建组织 useTotp 映射 (用于 cipher 的 organizationUseTotp)
    const orgUseTotpMap: Record<string, boolean> = {};
    for (const o of profileOrganizations) {
        orgUseTotpMap[o.id] = o.useTotp;
    }

    // 合并个人和组织 ciphers，并去重
    const allCiphers = [...userCiphers, ...orgCiphersData];
    const uniqueCipherIds = new Set();
    const reqUrl = new URL(c.req.url);
    const attachmentBaseUrl = `${reqUrl.protocol}//${reqUrl.host}`;
    const formattedCiphers = allCiphers.filter(cipher => {
        if (uniqueCipherIds.has(cipher.id)) {
            return false;
        }
        uniqueCipherIds.add(cipher.id);
        return true;
    }).map((cipher) => {
        const data = JSON.parse(cipher.data || '{}');
        const favorites = cipher.favorites ? JSON.parse(cipher.favorites) : {};
        const foldersMap = cipher.folders ? JSON.parse(cipher.folders) : {};
        const attachmentsMap = cipher.attachments ? JSON.parse(cipher.attachments) : {};
        const attachmentsList = Object.keys(attachmentsMap).map(id => {
            const a = attachmentsMap[id];
            const sizeBytes = parseInt(a.size || '0');
            const sizeName = sizeBytes >= 1048576 ? `${(sizeBytes / 1048576).toFixed(2)} MB` :
                sizeBytes >= 1024 ? `${(sizeBytes / 1024).toFixed(2)} KB` :
                    `${sizeBytes} Bytes`;
            return {
                id,
                fileName: a.fileName,
                key: a.key,
                size: a.size || '0',
                sizeName,
                url: `${attachmentBaseUrl}/attachments/${cipher.id}/${id}`
            };
        });

        return {
            id: cipher.id,
            organizationId: cipher.organizationId,
            folderId: foldersMap[userId] || null,
            type: cipher.type as CipherType,
            data: data,
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
            attachments: attachmentsList.length > 0 ? attachmentsList : null,
            organizationUseTotp: cipher.organizationId ? (orgUseTotpMap[cipher.organizationId] ?? false) : false,
            revisionDate: cipher.revisionDate,
            creationDate: cipher.creationDate,
            deletedDate: cipher.deletedDate,
            archivedDate: null,
            key: cipher.key,
            object: 'cipherDetails',
            collectionIds: cipherCollectionMap[cipher.id] || [],
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

    const formattedFolders = folderResponses; // Renamed for consistency
    const formattedSends = activeSends.map((send): SendResponse => {
        const data = send.data ? JSON.parse(send.data) : null;
        let authType = 2;
        if (send.hideEmail && (send as any).emails) authType = 0;
        if (send.password) authType = 1;

        const baseResponse: any = {
            id: send.id,
            accessId: send.id,
            userId: send.userId,
            type: send.type as SendType,
            authType,
            name: data?.name || '',
            notes: data?.notes || null,
            key: send.key || '',
            maxAccessCount: send.maxAccessCount,
            accessCount: send.accessCount,
            revisionDate: send.revisionDate,
            expirationDate: send.expirationDate,
            deletionDate: send.deletionDate,
            password: send.password ? 'set' : null,
            disabled: send.disabled,
            hideEmail: send.hideEmail,
            object: 'send',
        };

        if (send.type === 0) {
            const textObj = typeof data?.text === 'object' ? data.text : undefined;
            baseResponse.text = {
                text: textObj?.text ?? data?.text ?? '',
                hidden: textObj?.hidden ?? data?.hidden ?? false
            };
        } else if (send.type === 1) {
            baseResponse.file = {
                id: data?.id || null,
                fileName: data?.file?.fileName || '',
                size: data?.file?.size || null,
                sizeName: data?.file?.sizeName || null,
            };
        }
        return baseResponse;
    });

    const response: SyncResponse = {
        profile: profile,
        folders: formattedFolders,
        collections: myCollections,
        policies: [],
        ciphers: formattedCiphers, // 此处我们暂把个人 Ciphers 与组织的合并，稍微简化
        sends: formattedSends,
        domains: excludeDomains ? null : {
            equivalentDomains: user.equivalentDomains ? JSON.parse(user.equivalentDomains) : null,
            globalEquivalentDomains: GLOBAL_EQUIVALENT_DOMAINS,
            object: 'domains',
        },
        userDecryption,
        object: 'sync',
    };

    return c.json(response);
});

export default sync;
