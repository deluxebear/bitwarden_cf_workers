/**
 * 生成一个用于 Workers 自建环境的组织 license JSON。
 *
 * 目标：
 * - 字段结构尽量贴近官方 `OrganizationLicense`
 * - 满足 Workers 侧的所有校验逻辑（validateOrganizationLicense + 唯一性检查）
 * - 不依赖任何私钥或签名（Hash / Signature / Token 置空即可）
 *
 * 用法示例：
 *   npx ts-node scripts/generate-org-license.ts \\
 *     --name "My Org" \\
 *     --email "admin@example.com" \\
 *     --planType 2 \\
 *     --seats 10 \\
 *     --installationId "<your-installation-id>" \\
 *     > bitwarden_organization_license.json
 */

import { randomUUID } from 'crypto';

type Args = {
  name: string;
  email: string;
  planType: number;
  plan: string;
  seats: number;
  maxStorageGb: number;
  installationId?: string;
  selfHost: boolean;
  daysValid: number;
  licenseKey?: string;
  orgId?: string;
};

function parseArgs(): Args {
  const argv = process.argv.slice(2);
  const get = (flag: string): string | undefined => {
    const idx = argv.indexOf(flag);
    if (idx === -1 || idx + 1 >= argv.length) return undefined;
    return argv[idx + 1];
  };

  const name = get('--name') ?? 'Self-Hosted Organization';
  const email = get('--email') ?? 'admin@example.com';
  const planType = Number(get('--planType') ?? '2'); // 默认当作 Teams/Enterprise
  const plan = get('--plan') ?? 'Enterprise Annually 2025';
  const seats = Number(get('--seats') ?? '10');
  const maxStorageGb = Number(get('--maxStorageGb') ?? '10');
  const installationId = get('--installationId');
  const selfHost = (get('--selfHost') ?? 'true').toLowerCase() !== 'false';
  const daysValid = Number(get('--daysValid') ?? '365');
  const licenseKey = get('--licenseKey') ?? randomUUID().replace(/-/g, '');
  const orgId = get('--orgId') ?? randomUUID();

  return {
    name,
    email,
    planType,
    plan,
    seats,
    maxStorageGb,
    installationId,
    selfHost,
    daysValid,
    licenseKey,
    orgId,
  };
}

function main() {
  const args = parseArgs();

  const now = new Date();
  const issued = now.toISOString();
  const expires = new Date(now.getTime() + args.daysValid * 24 * 60 * 60 * 1000).toISOString();

  // 按照 src/Core/Billing/Organizations/Models/OrganizationLicense.cs 的字段结构构造
  const license: Record<string, unknown> = {
    Version: 15,
    LicenseType: 1, // 1 = Organization
    LicenseKey: args.licenseKey,
    InstallationId: args.installationId ?? args.orgId, // 没有安装 ID 时用 orgId 占位
    Id: args.orgId,
    Name: args.name,
    BillingEmail: args.email,
    BusinessName: args.name,
    Enabled: true,
    Plan: args.plan,
    PlanType: args.planType,
    Seats: args.seats,
    MaxCollections: null,
    UsePolicies: false,
    UseSso: false,
    UseKeyConnector: false,
    UseScim: false,
    UseGroups: true,
    UseEvents: true,
    UseDirectory: false,
    UseTotp: true,
    Use2fa: true,
    UseApi: true,
    UseResetPassword: true,
    MaxStorageGb: args.maxStorageGb,
    SelfHost: args.selfHost,
    UsersGetPremium: true,
    UseCustomPermissions: true,
    Issued: issued,
    Refresh: null,
    Expires: expires,
    ExpirationWithoutGracePeriod: expires,
    Trial: false,
    UsePasswordManager: true,
    UseSecretsManager: false,
    SmSeats: null,
    SmServiceAccounts: null,
    UseRiskInsights: false,
    UsePhishingBlocker: false,
    LimitCollectionCreationDeletion: true,
    AllowAdminAccessToAllCollectionItems: true,
    UseOrganizationDomains: false,
    UseAdminSponsoredFamilies: false,
    UseAutomaticUserConfirmation: false,
    UseDisableSmAdsForUsers: false,
    UseMyItems: true,
    // Workers 侧不会验证 Hash / Signature / Token，这里置空即可
    Hash: '',
    Signature: '',
    Token: '',
  };

  // 直接输出到 stdout，由调用者重定向到文件
  // eslint-disable-next-line no-console
  console.log(JSON.stringify(license, null, 2));
}

main();

