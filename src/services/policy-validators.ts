/**
 * Policy validation and dependency management
 * 对应官方 Core/AdminConsole/Enums/PolicyType.cs
 *        Core/AdminConsole/OrganizationFeatures/Policies/Implementations/SavePolicyCommand.cs
 *        Core/AdminConsole/Utilities/PolicyDataValidator.cs
 *        Core/AdminConsole/OrganizationFeatures/Policies/PolicyValidators/*
 */

import { BadRequestError } from '../middleware/error';

// 对应 Core/AdminConsole/Enums/PolicyType.cs
export const PolicyType = {
    TwoFactorAuthentication: 0,
    MasterPassword: 1,
    PasswordGenerator: 2,
    SingleOrg: 3,
    RequireSso: 4,
    OrganizationDataOwnership: 5,
    DisableSend: 6,
    SendOptions: 7,
    ResetPassword: 8,
    MaximumVaultTimeout: 9,
    DisablePersonalVaultExport: 10,
    ActivateAutofill: 11,
    AutomaticAppLogIn: 12,
    FreeFamiliesSponsorshipPolicy: 13,
    RemoveUnlockWithPin: 14,
    RestrictedItemTypesPolicy: 15,
    UriMatchDefaults: 16,
    AutotypeDefaultSetting: 17,
    AutomaticUserConfirmation: 18,
    BlockClaimedDomainAccountCreation: 19,
} as const;

export type PolicyTypeValue = (typeof PolicyType)[keyof typeof PolicyType];

// 对应 PolicyTypeExtensions.GetName()
export const POLICY_NAMES: Record<number, string> = {
    [PolicyType.TwoFactorAuthentication]: 'Require two-step login',
    [PolicyType.MasterPassword]: 'Master password requirements',
    [PolicyType.PasswordGenerator]: 'Password generator',
    [PolicyType.SingleOrg]: 'Single organization',
    [PolicyType.RequireSso]: 'Require single sign-on authentication',
    [PolicyType.OrganizationDataOwnership]: 'Enforce organization data ownership',
    [PolicyType.DisableSend]: 'Remove Send',
    [PolicyType.SendOptions]: 'Send options',
    [PolicyType.ResetPassword]: 'Account recovery administration',
    [PolicyType.MaximumVaultTimeout]: 'Vault timeout',
    [PolicyType.DisablePersonalVaultExport]: 'Remove individual vault export',
    [PolicyType.ActivateAutofill]: 'Active auto-fill',
    [PolicyType.AutomaticAppLogIn]: 'Automatic login with SSO',
    [PolicyType.FreeFamiliesSponsorshipPolicy]: 'Remove Free Bitwarden Families sponsorship',
    [PolicyType.RemoveUnlockWithPin]: 'Remove unlock with PIN',
    [PolicyType.RestrictedItemTypesPolicy]: 'Restricted item types',
    [PolicyType.UriMatchDefaults]: 'URI match defaults',
    [PolicyType.AutotypeDefaultSetting]: 'Autotype default setting',
    [PolicyType.AutomaticUserConfirmation]: 'Automatically confirm invited users',
    [PolicyType.BlockClaimedDomainAccountCreation]: 'Block account creation for claimed domains',
};

/**
 * 策略依赖关系表
 * 对应各 PolicyValidator 的 RequiredPolicies 属性
 * Key: 需要依赖的策略类型
 * Value: 该策略启用前必须先启用的策略类型列表
 */
export const POLICY_REQUIRED: Record<number, number[]> = {
    // RequireSsoPolicyValidator: RequiredPolicies => [SingleOrg]
    [PolicyType.RequireSso]: [PolicyType.SingleOrg],
    // ResetPasswordPolicyValidator: RequiredPolicies => [SingleOrg]
    [PolicyType.ResetPassword]: [PolicyType.SingleOrg],
    // MaximumVaultTimeoutPolicyValidator: RequiredPolicies => [SingleOrg]
    [PolicyType.MaximumVaultTimeout]: [PolicyType.SingleOrg],
    // OrganizationDataOwnershipPolicyValidator (implicit via SingleOrg requirement)
    [PolicyType.OrganizationDataOwnership]: [PolicyType.SingleOrg],
};

export interface PolicyRecord {
    type: number;
    enabled: boolean;
    data: string | null;
}

/**
 * 验证 MasterPassword 策略数据
 * 对应 MasterPasswordPolicyData: minComplexity [0,4], minLength [12,128]
 */
function validateMasterPasswordData(data: Record<string, unknown>): void {
    if (data.minComplexity != null) {
        const v = Number(data.minComplexity);
        if (!Number.isInteger(v) || v < 0 || v > 4) {
            throw new BadRequestError(
                'Invalid data for MasterPassword policy: minComplexity must be between 0 and 4.',
            );
        }
    }
    if (data.minLength != null) {
        const v = Number(data.minLength);
        if (!Number.isInteger(v) || v < 12 || v > 128) {
            throw new BadRequestError(
                'Invalid data for MasterPassword policy: minLength must be between 12 and 128.',
            );
        }
    }
}

/**
 * 验证并序列化策略数据
 * 对应 PolicyDataValidator.ValidateAndSerialize
 */
export function validatePolicyData(type: number, data: Record<string, unknown> | null): string | null {
    if (!data || Object.keys(data).length === 0) return null;

    switch (type) {
        case PolicyType.MasterPassword:
            validateMasterPasswordData(data);
            break;
        case PolicyType.SendOptions:
        case PolicyType.ResetPassword:
        case PolicyType.PasswordGenerator:
        case PolicyType.MaximumVaultTimeout:
        case PolicyType.UriMatchDefaults:
            break;
    }

    return JSON.stringify(data);
}

/**
 * 启用策略时检查依赖是否满足
 * 对应 SavePolicyCommand.RunValidatorAsync 中 RequiredPolicies 检查
 */
export function validateDependenciesOnEnable(
    policyType: number,
    allPolicies: PolicyRecord[],
): void {
    const required = POLICY_REQUIRED[policyType];
    if (!required || required.length === 0) return;

    for (const reqType of required) {
        const reqPolicy = allPolicies.find(p => p.type === reqType);
        if (!reqPolicy || !reqPolicy.enabled) {
            const reqName = POLICY_NAMES[reqType] ?? `Policy ${reqType}`;
            const policyName = POLICY_NAMES[policyType] ?? `Policy ${policyType}`;
            throw new BadRequestError(
                `Turn on the ${reqName} policy because it is required for the ${policyName} policy.`,
            );
        }
    }
}

/**
 * 禁用策略时检查是否有其他策略依赖它
 * 对应 SavePolicyCommand.RunValidatorAsync 中 dependent policies 检查
 */
export function validateDependentsOnDisable(
    policyType: number,
    allPolicies: PolicyRecord[],
): void {
    const dependentTypes: number[] = [];

    for (const [depTypeStr, deps] of Object.entries(POLICY_REQUIRED)) {
        const depType = Number(depTypeStr);
        if (deps.includes(policyType)) {
            const depPolicy = allPolicies.find(p => p.type === depType);
            if (depPolicy?.enabled) {
                dependentTypes.push(depType);
            }
        }
    }

    if (dependentTypes.length === 1) {
        const depName = POLICY_NAMES[dependentTypes[0]] ?? `Policy ${dependentTypes[0]}`;
        const policyName = POLICY_NAMES[policyType] ?? `Policy ${policyType}`;
        throw new BadRequestError(
            `Turn off the ${depName} policy because it requires the ${policyName} policy.`,
        );
    }
    if (dependentTypes.length > 1) {
        const policyName = POLICY_NAMES[policyType] ?? `Policy ${policyType}`;
        throw new BadRequestError(
            `Turn off all of the policies that require the ${policyName} policy.`,
        );
    }
}

/**
 * 判断策略是否可以切换状态（用于 PolicyStatusResponseModel.canToggleState）
 * 对应官方 GetSingleOrgPolicyStatusResponseAsync 等特殊逻辑
 */
export function canTogglePolicyState(
    policyType: number,
    currentEnabled: boolean,
    allPolicies: PolicyRecord[],
): boolean {
    if (!currentEnabled) return true;

    // SingleOrg 启用状态下，如有已启用的依赖策略则不可关闭
    if (policyType === PolicyType.SingleOrg) {
        for (const [depTypeStr, deps] of Object.entries(POLICY_REQUIRED)) {
            if (deps.includes(PolicyType.SingleOrg)) {
                const depPolicy = allPolicies.find(p => p.type === Number(depTypeStr));
                if (depPolicy?.enabled) return false;
            }
        }
    }

    return true;
}

/**
 * 判断策略类型是否合法
 */
export function isValidPolicyType(type: number): boolean {
    return Number.isInteger(type) && type >= 0 && type <= 19;
}
