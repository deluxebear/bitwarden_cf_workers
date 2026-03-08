#!/usr/bin/env node
/**
 * 生成 Bitwarden 自建组织授权书 JSON（用于 Workers 自建环境上传）
 *
 * 用法：
 *   node scripts/generate-organization-license.js
 *   node scripts/generate-organization-license.js --name=MyOrg --email=admin@example.com --seats=500 --year=2099 --plan=Enterprise
 *
 * 输出：bitwarden_organization_license.json（可改 --output=xxx.json）
 *
 * 若部署时配置了 INSTALLATION_ID，请通过 --installation-id=xxx 传入，否则校验会失败。
 */

import { randomUUID } from 'crypto';
import { writeFileSync } from 'fs';
import { resolve } from 'path';

const args = process.argv.slice(2);
const getArg = (name, def) => {
  const key = `--${name}=`;
  const s = args.find((a) => a.startsWith(key));
  return s ? s.slice(key.length) : def;
};

const organizationName = getArg('name', 'jetems');
const adminEmail = getArg('email', 'eric@jetems.com');
const seats = parseInt(getArg('seats', '1000'), 10) || 1000;
const expiryYear = parseInt(getArg('year', '2099'), 10) || 2099;
const plan = getArg('plan', 'Enterprise'); // Enterprise | Teams
const outputFile = getArg('output', 'bitwarden_organization_license.json');
const installationId = getArg('installation-id', '');

const now = new Date();
const issued = now.toISOString();
const expires = new Date(`${expiryYear}-12-31T23:59:59.000Z`).toISOString();
const refresh = new Date(expiryYear, 11, 1).toISOString(); // 同年 12 月 1 日
const expirationWithoutGracePeriod = expires;

// PlanType: 20 = EnterpriseAnnually, 18 = TeamsAnnually
const planType = plan.toLowerCase().includes('enterprise') ? 20 : 18;

const license = {
  Version: 15,
  LicenseType: 1, // 1 = Organization（个人 Premium 为 0）
  LicenseKey: randomUUID(),
  InstallationId: installationId || randomUUID(),
  Id: randomUUID(),
  Name: organizationName,
  BillingEmail: adminEmail,
  BusinessName: organizationName,
  Enabled: true,
  Plan: plan,
  PlanType: planType,
  Seats: seats,
  MaxCollections: 200,
  MaxStorageGb: 100,
  UsePolicies: true,
  UseSso: true,
  UseKeyConnector: true,
  UseScim: true,
  UseGroups: true,
  UseEvents: true,
  UseDirectory: true,
  UseTotp: true,
  Use2fa: true,
  UseApi: true,
  UseResetPassword: true,
  SelfHost: true,
  UsersGetPremium: true,
  UseCustomPermissions: true,
  UsePasswordManager: true,
  UseSecretsManager: true,
  SmSeats: 100,
  SmServiceAccounts: 50,
  UseRiskInsights: true,
  UseOrganizationDomains: true,
  UseAdminSponsoredFamilies: true,
  UseAutomaticUserConfirmation: true,
  UseDisableSmAdsForUsers: true,
  UsePhishingBlocker: true,
  UseMyItems: true,
  LimitCollectionCreationDeletion: false,
  AllowAdminAccessToAllCollectionItems: true,
  Issued: issued,
  Refresh: refresh,
  Expires: expires,
  ExpirationWithoutGracePeriod: expirationWithoutGracePeriod,
  Trial: false,
  // Workers 不校验 Hash/Signature，占位即可
  Hash: '',
  Signature: '',
};

const outPath = resolve(process.cwd(), outputFile);
writeFileSync(outPath, JSON.stringify(license, null, 2), 'utf8');
console.log(`组织授权书已生成: ${outPath}`);
console.log(`  组织名称: ${organizationName}`);
console.log(`  管理员邮箱: ${adminEmail}`);
console.log(`  用户数: ${seats}`);
console.log(`  有效期至: ${expiryYear}-12-31`);
console.log(`  版本: ${plan}`);
if (installationId) {
  console.log(`  InstallationId: ${installationId}`);
} else {
  console.log(`  InstallationId: ${license.InstallationId} (未指定，若部署配置了 INSTALLATION_ID 请用 --installation-id=xxx 重新生成)`);
}
