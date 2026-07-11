/**
 * Worker 对外能力矩阵。
 *
 * 对客户端声明的能力必须同时满足：套餐/数据库允许，且 Worker 已完整实现。
 * 未经过目标客户端 CRUD 与副作用验收的能力保持 false，避免客户端展示不可用入口。
 */
export const serverCapabilities = Object.freeze({
    organization: Object.freeze({
        keyConnector: false,
        scim: false,
        directory: false,
        api: false,
        secretsManager: false,
        riskInsights: false,
        automaticUserConfirmation: false,
        phishingBlocker: false,
    }),
    featureStates: Object.freeze({
        archive: true,
        credentialExchangeExportMobile: false,
        credentialExchangeImportMobile: false,
        cipherKeyEncryption: true,
        migrateMyVaultToMyItems: false,
        noLogoutOnKdfChange: false,
    }),
});

export type GatedOrganizationCapability = keyof typeof serverCapabilities.organization;

export function advertiseOrganizationCapability(
    capability: GatedOrganizationCapability,
    licensedOrConfigured: unknown,
): boolean {
    return serverCapabilities.organization[capability] && (licensedOrConfigured === true || licensedOrConfigured === 1);
}
