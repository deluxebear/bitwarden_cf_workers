/**
 * Bitwarden Workers - Organization domains and SSO base routes.
 *
 * OIDC configuration is validated against provider discovery before it can be
 * enabled. Client secrets are referenced through Worker secret bindings and
 * are never persisted in D1 or returned by this API.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { and, eq, ne, sql } from 'drizzle-orm';
import {
    organizationDomains,
    organizations,
    organizationUsers,
    policies,
    ssoConfigs,
} from '../db/schema';
import type { OrganizationDomainRow, OrganizationRow, OrganizationUserRow, SsoConfigRow } from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { BadRequestError, ConflictError, NotFoundError } from '../middleware/error';
import { generateSecureRandomString, generateUuid } from '../services/crypto';
import { logEvent } from '../services/events';
import { fetchOidcDiscovery, validateOidcIssuer, validateSsoBaseUrl } from '../services/oidc';
import { PolicyType } from '../services/policy-validators';
import type { Bindings, Variables } from '../types';
import { getDeviceTypeFromRequest } from './events';

const organizationDomainsRoutes = new Hono<{ Bindings: Bindings; Variables: Variables }>();
type D1Db = ReturnType<typeof drizzle>;
type OrgDomainContext = Context<{ Bindings: Bindings; Variables: Variables }>;
type Fetcher = typeof fetch;
const DOMAIN_NOT_AVAILABLE_MESSAGE = 'The domain is not available to be claimed.';
const VALID_DOMAIN_NAME_REGEX = /^(?!(http(s)?:\/\/|www\.))([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

interface DnsJsonAnswer {
    type?: number;
    data?: string;
}

interface DnsJsonResponse {
    Answer?: DnsJsonAnswer[];
}

interface OrganizationUserPermissions {
    manageSso?: boolean;
}

export interface OrganizationOidcConfig {
    issuer: string | null;
    clientId: string | null;
    clientSecretEnv: string | null;
    redirectUri: string;
    claimMapping: Record<string, string[]>;
}

interface ExistingOidcConfig {
    issuer?: string | null;
    clientId?: string | null;
    clientSecretEnv?: string | null;
    redirectUri?: string | null;
    claimMapping?: string | null;
    data?: Record<string, unknown>;
}

function parsePermissions(permissions: string | null): OrganizationUserPermissions | null {
    if (!permissions) return null;
    try {
        return JSON.parse(permissions) as OrganizationUserPermissions;
    } catch {
        return null;
    }
}

async function getManageSsoOrgUser(db: D1Db, orgId: string, userId: string): Promise<OrganizationUserRow> {
    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
        .get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    if (orgUser.type === 0 || orgUser.type === 1) return orgUser;

    const permissions = parsePermissions(orgUser.permissions);
    if (permissions?.manageSso === true) return orgUser;

    throw new NotFoundError('Organization not found or access denied.');
}

function normalizeDomainName(value: unknown): string {
    if (typeof value !== 'string') {
        throw new BadRequestError('DomainName is required.');
    }

    const domain = value.trim().toLowerCase();
    if (domain.length === 0 || domain.length > 255 || !VALID_DOMAIN_NAME_REGEX.test(domain)) {
        throw new BadRequestError('Invalid domain name.');
    }

    return domain;
}

function getEmailDomain(email: string): string | null {
    const at = email.lastIndexOf('@');
    if (at < 0) return null;
    const domain = email.slice(at + 1).trim().toLowerCase();
    return domain.length > 0 ? domain : null;
}

function toOrganizationDomainResponse(domain: OrganizationDomainRow) {
    return {
        id: domain.id,
        organizationId: domain.organizationId,
        txt: domain.txt,
        domainName: domain.domainName,
        creationDate: domain.creationDate,
        nextRunDate: domain.nextRunDate,
        jobRunCount: domain.jobRunCount,
        verifiedDate: domain.verifiedDate ?? null,
        lastCheckedDate: domain.lastCheckedDate ?? null,
        object: 'organizationDomain',
    };
}

function normalizeDnsTxtData(data: string): string {
    const chunks = data.match(/"((?:\\.|[^"\\])*)"/g);
    if (!chunks) return data.trim();

    return chunks
        .map((chunk) => chunk.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\'))
        .join('')
        .trim();
}

export function extractDnsTxtRecords(response: unknown): string[] {
    if (!response || typeof response !== 'object') return [];

    const answers = (response as DnsJsonResponse).Answer;
    if (!Array.isArray(answers)) return [];

    return answers
        .filter((answer) => answer.type === 16 && typeof answer.data === 'string')
        .map((answer) => normalizeDnsTxtData(answer.data as string))
        .filter((txt) => txt.length > 0);
}

export async function resolveDnsTxtRecords(
    domainName: string,
    fetcher: Fetcher = fetch,
    resolverUrl = 'https://cloudflare-dns.com/dns-query',
): Promise<string[]> {
    const url = new URL(resolverUrl);
    url.searchParams.set('name', domainName);
    url.searchParams.set('type', 'TXT');

    let response: Response;
    try {
        response = await fetcher(url.toString(), {
            headers: { accept: 'application/dns-json' },
        });
    } catch {
        throw new BadRequestError('Unable to check DNS TXT records.');
    }

    if (!response.ok) {
        throw new BadRequestError('Unable to check DNS TXT records.');
    }

    try {
        return extractDnsTxtRecords(await response.json());
    } catch {
        throw new BadRequestError('Unable to check DNS TXT records.');
    }
}

export function dnsTxtRecordsContainToken(records: string[], expectedTxt: string): boolean {
    return records.some((record) => record === expectedTxt);
}

export async function verifyOrganizationDomainDns(
    domain: Pick<OrganizationDomainRow, 'domainName' | 'txt'>,
    fetcher: Fetcher = fetch,
    resolverUrl?: string,
): Promise<boolean> {
    const records = await resolveDnsTxtRecords(domain.domainName, fetcher, resolverUrl);
    return dnsTxtRecordsContainToken(records, domain.txt);
}

async function verifyDnsTxtRecord(c: OrgDomainContext, domain: OrganizationDomainRow): Promise<boolean> {
    const resolverUrl = (c.env as { DNS_RESOLVER_URL?: string }).DNS_RESOLVER_URL?.trim();
    return verifyOrganizationDomainDns(domain, fetch, resolverUrl || undefined);
}

async function ensureSingleOrgPolicyEnabled(db: D1Db, orgId: string, now: string): Promise<void> {
    const existing = await db.select().from(policies)
        .where(and(eq(policies.organizationId, orgId), eq(policies.type, PolicyType.SingleOrg)))
        .get();

    if (existing) {
        if (existing.enabled !== true) {
            await db.update(policies).set({ enabled: true, revisionDate: now }).where(eq(policies.id, existing.id));
        }
        return;
    }

    await db.insert(policies).values({
        id: generateUuid(),
        organizationId: orgId,
        type: PolicyType.SingleOrg,
        enabled: true,
        data: null,
        creationDate: now,
        revisionDate: now,
    });
}

function getRequestString(body: Record<string, unknown>, ...keys: string[]): string | null {
    for (const key of keys) {
        const value = body[key];
        if (typeof value === 'string' && value.trim().length > 0) {
            return value.trim();
        }
    }
    return null;
}

function getSsoBaseUrl(c: OrgDomainContext): string {
    const envValue = c.env.SSO_BASE_URL?.trim();
    if (envValue) {
        try {
            return validateSsoBaseUrl(
                envValue,
                c.env.SSO_ALLOW_INSECURE_LOCALHOST?.toLowerCase() === 'true',
            );
        } catch (error) {
            throw new BadRequestError(error instanceof Error ? error.message : 'SSO_BASE_URL is invalid.');
        }
    }
    const url = new URL(c.req.url);
    return validateSsoBaseUrl(url.origin, ['localhost', '127.0.0.1', '::1'].includes(url.hostname));
}

function buildSsoUrls(c: OrgDomainContext, orgId: string) {
    const base = getSsoBaseUrl(c);
    const samlBase = `${base}/saml2`;
    const orgSamlBase = `${samlBase}/${orgId}`;
    return {
        callbackPath: `${base}/oidc-signin`,
        signedOutCallbackPath: `${base}/oidc-signedout`,
        spEntityId: orgSamlBase,
        spEntityIdStatic: samlBase,
        spMetadataUrl: orgSamlBase,
        spAcsUrl: `${orgSamlBase}/Acs`,
    };
}

function defaultSsoData() {
    return {
        configType: 0,
        memberDecryptionType: 0,
        keyConnectorUrl: null,
        authority: null,
        clientId: null,
        metadataAddress: null,
        redirectBehavior: 0,
        getClaimsFromUserInfoEndpoint: false,
        additionalScopes: null,
        additionalUserIdClaimTypes: null,
        additionalEmailClaimTypes: null,
        additionalNameClaimTypes: null,
        acrValues: null,
        expectedReturnAcrValue: null,
        idpEntityId: null,
        idpSingleSignOnServiceUrl: null,
        idpSingleLogoutServiceUrl: null,
        idpX509PublicCert: null,
        idpBindingType: 0,
        idpAllowUnsolicitedAuthnResponse: false,
        idpArtifactResolutionServiceUrl: null,
        idpDisableOutboundLogoutRequests: false,
        idpOutboundSigningAlgorithm: null,
        idpWantAuthnRequestsSigned: false,
        spUniqueEntityId: false,
        spNameIdFormat: 0,
        spOutboundSigningAlgorithm: 'rsa-sha256',
        spSigningBehavior: 0,
        spWantAssertionsSigned: false,
        spValidateCertificates: false,
        spMinIncomingSigningAlgorithm: null,
    };
}

function stripClientSecretFields(value: unknown): unknown {
    if (Array.isArray(value)) return value.map(stripClientSecretFields);
    if (!value || typeof value !== 'object') return value;

    const sanitized: Record<string, unknown> = {};
    for (const [key, nestedValue] of Object.entries(value)) {
        if (key.replace(/[-_]/g, '').toLowerCase() === 'clientsecret') continue;
        sanitized[key] = stripClientSecretFields(nestedValue);
    }
    return sanitized;
}

export function normalizeSsoData(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return defaultSsoData();
    }
    const sanitized = stripClientSecretFields(value) as Record<string, unknown>;
    return {
        ...defaultSsoData(),
        ...sanitized,
    };
}

function parseClaimMapping(value: unknown): Record<string, string[]> {
    if (typeof value === 'string') {
        try {
            return parseClaimMapping(JSON.parse(value));
        } catch {
            throw new BadRequestError('OIDC claimMapping must be valid JSON.');
        }
    }
    if (value == null) return {};
    if (typeof value !== 'object' || Array.isArray(value)) {
        throw new BadRequestError('OIDC claimMapping must be an object.');
    }

    const result: Record<string, string[]> = {};
    for (const [target, claims] of Object.entries(value)) {
        if (!/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(target)) {
            throw new BadRequestError('OIDC claimMapping contains an invalid target name.');
        }
        const values = typeof claims === 'string' ? [claims] : claims;
        if (!Array.isArray(values) || values.length === 0 || values.length > 10) {
            throw new BadRequestError('Each OIDC claimMapping target must contain between 1 and 10 claims.');
        }
        result[target] = values.map((claim) => {
            if (typeof claim !== 'string' || claim.trim().length === 0 || claim.length > 256 || /[\u0000-\u001f]/.test(claim)) {
                throw new BadRequestError('OIDC claimMapping contains an invalid claim name.');
            }
            return claim.trim();
        });
    }
    return result;
}

function getNestedSsoData(body: Record<string, unknown>): Record<string, unknown> {
    const value = body.data ?? body.Data;
    return value && typeof value === 'object' && !Array.isArray(value)
        ? value as Record<string, unknown>
        : {};
}

function getOptionalString(...values: unknown[]): string | null {
    for (const value of values) {
        if (typeof value === 'string' && value.trim().length > 0) return value.trim();
    }
    return null;
}

/** Normalizes the OIDC subset while preserving omitted values from older rows. */
export function normalizeOrganizationOidcConfig(
    body: Record<string, unknown>,
    expectedRedirectUri: string,
    existing: ExistingOidcConfig = {},
): OrganizationOidcConfig {
    const data = getNestedSsoData(body);
    const plaintextSecret = body.clientSecret ?? body.ClientSecret ?? data.clientSecret ?? data.ClientSecret;
    if (typeof plaintextSecret === 'string' && plaintextSecret.trim().length > 0) {
        throw new BadRequestError('OIDC clientSecret must be configured as a Worker secret binding reference.');
    }

    const issuerInput = getOptionalString(
        body.issuer,
        body.Issuer,
        data.issuer,
        data.Issuer,
        data.authority,
        data.Authority,
        existing.issuer,
        existing.data?.issuer,
        existing.data?.authority,
    );
    let issuer: string | null = null;
    if (issuerInput) {
        try {
            issuer = validateOidcIssuer(issuerInput).toString();
        } catch (error) {
            throw new BadRequestError(error instanceof Error ? error.message : 'OIDC issuer is invalid.');
        }
    }

    const clientId = getOptionalString(
        body.clientId,
        body.ClientId,
        data.clientId,
        data.ClientId,
        existing.clientId,
        existing.data?.clientId,
    );
    if (clientId && (clientId.length > 255 || /[\u0000-\u001f]/.test(clientId))) {
        throw new BadRequestError('OIDC clientId is invalid.');
    }

    const clientSecretEnv = getOptionalString(
        body.clientSecretEnv,
        body.ClientSecretEnv,
        data.clientSecretEnv,
        data.ClientSecretEnv,
        existing.clientSecretEnv,
        existing.data?.clientSecretEnv,
    );
    if (clientSecretEnv && !/^SSO_OIDC_[A-Z0-9_]{1,119}$/.test(clientSecretEnv)) {
        throw new BadRequestError('OIDC clientSecretEnv must name an SSO_OIDC_* Worker secret binding.');
    }

    const requestedRedirectUri = getOptionalString(
        body.redirectUri,
        body.RedirectUri,
        data.redirectUri,
        data.RedirectUri,
        existing.redirectUri,
        existing.data?.redirectUri,
    );
    if (requestedRedirectUri && requestedRedirectUri !== expectedRedirectUri) {
        throw new BadRequestError('OIDC redirectUri must match this server callback URL.');
    }

    const claimMappingInput = body.claimMapping
        ?? body.ClaimMapping
        ?? data.claimMapping
        ?? data.ClaimMapping
        ?? existing.claimMapping
        ?? existing.data?.claimMapping;

    return {
        issuer,
        clientId,
        clientSecretEnv,
        redirectUri: expectedRedirectUri,
        claimMapping: parseClaimMapping(claimMappingInput),
    };
}

export async function validateOrganizationOidcEnable(
    config: OrganizationOidcConfig,
    secretLookup: (bindingName: string) => unknown,
    fetcher: Fetcher = fetch,
): Promise<void> {
    if (!config.issuer || !config.clientId || !config.clientSecretEnv) {
        throw new BadRequestError('Enabled OIDC requires issuer, clientId, and clientSecretEnv.');
    }
    const secret = secretLookup(config.clientSecretEnv);
    if (typeof secret !== 'string' || secret.trim().length === 0) {
        throw new BadRequestError('The configured OIDC Worker secret binding is missing.');
    }
    try {
        await fetchOidcDiscovery(config.issuer, { fetch: fetcher });
    } catch (error) {
        const reason = error instanceof Error ? error.message : 'unknown provider response';
        throw new BadRequestError(`OIDC discovery validation failed: ${reason}`);
    }
}

function parseSsoConfigData(config: SsoConfigRow | undefined): Record<string, unknown> {
    if (!config?.data) return defaultSsoData();
    try {
        return normalizeSsoData(JSON.parse(config.data));
    } catch {
        return defaultSsoData();
    }
}

function parseStoredClaimMapping(config: SsoConfigRow | undefined): Record<string, string[]> {
    if (!config?.claimMapping) return {};
    try {
        return parseClaimMapping(config.claimMapping);
    } catch {
        return {};
    }
}

function toOrganizationSsoResponse(
    c: OrgDomainContext,
    organization: OrganizationRow,
    config?: SsoConfigRow,
) {
    const data = parseSsoConfigData(config);
    if (config?.issuer) data.authority = config.issuer;
    if (config?.clientId) data.clientId = config.clientId;
    if (config?.clientSecretEnv) data.clientSecretEnv = config.clientSecretEnv;
    if (config?.redirectUri) data.redirectUri = config.redirectUri;
    if (config?.claimMapping) data.claimMapping = parseStoredClaimMapping(config);
    data.clientSecretConfigured = Boolean(config?.clientSecretEnv);
    return {
        enabled: config?.enabled ?? false,
        identifier: organization.identifier ?? null,
        data,
        urls: buildSsoUrls(c, organization.id),
        object: 'organizationSso',
    };
}

async function getOrganizationOrNotFound(db: D1Db, orgId: string): Promise<OrganizationRow> {
    const organization = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!organization) throw new NotFoundError('Organization not found.');
    return organization;
}

async function assertDomainIsNotVerifiedByAnotherOrganization(db: D1Db, orgId: string, domainName: string) {
    const verifiedClaim = await db.select({ id: organizationDomains.id }).from(organizationDomains)
        .where(and(
            eq(organizationDomains.domainName, domainName),
            ne(organizationDomains.organizationId, orgId),
            sql`${organizationDomains.verifiedDate} IS NOT NULL`,
        ))
        .get();
    if (verifiedClaim) {
        throw new ConflictError(DOMAIN_NOT_AVAILABLE_MESSAGE);
    }
}

/**
 * POST /api/organizations/domain/sso/verified
 */
organizationDomainsRoutes.post('/domain/sso/verified', async (c) => {
    const db = drizzle(c.env.DB);
    const body = await c.req.json<Record<string, unknown>>();
    const email = getRequestString(body, 'email', 'Email');
    if (!email) throw new BadRequestError('Email is required.');

    const emailDomain = getEmailDomain(email);
    if (!emailDomain) throw new BadRequestError('Invalid email.');

    const rows = await db.select({
        domainName: organizationDomains.domainName,
        organizationIdentifier: organizations.identifier,
        organizationName: organizations.name,
    })
        .from(organizationDomains)
        .innerJoin(organizations, eq(organizationDomains.organizationId, organizations.id))
        .innerJoin(ssoConfigs, eq(ssoConfigs.organizationId, organizations.id))
        .where(and(
            eq(organizationDomains.domainName, emailDomain),
            sql`${organizationDomains.verifiedDate} IS NOT NULL`,
            eq(organizations.enabled, true),
            eq(organizations.useSso, true),
            eq(ssoConfigs.enabled, true),
        ))
        .all();

    const data = rows
        .filter((row) => row.organizationIdentifier)
        .map((row) => ({
            domainName: row.domainName,
            organizationIdentifier: row.organizationIdentifier,
            organizationName: row.organizationName,
            object: 'verifiedOrganizationDomainSsoDetails',
        }));

    return c.json({
        data,
        object: 'list',
        continuationToken: null,
    });
});

organizationDomainsRoutes.use('/:id/domain/*', authMiddleware);
organizationDomainsRoutes.use('/:id/domain', authMiddleware);
organizationDomainsRoutes.use('/:id/sso', authMiddleware);

/**
 * GET /api/organizations/:id/domain
 */
organizationDomainsRoutes.get('/:id/domain', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    await getOrganizationOrNotFound(db, orgId);

    const domains = await db.select().from(organizationDomains)
        .where(eq(organizationDomains.organizationId, orgId))
        .all();

    return c.json({
        data: domains.map(toOrganizationDomainResponse),
        object: 'list',
        continuationToken: null,
    });
});

/**
 * GET /api/organizations/:id/domain/:domainId
 */
organizationDomainsRoutes.get('/:id/domain/:domainId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const domainId = c.req.param('domainId');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    await getOrganizationOrNotFound(db, orgId);

    const domain = await db.select().from(organizationDomains)
        .where(and(eq(organizationDomains.id, domainId), eq(organizationDomains.organizationId, orgId)))
        .get();
    if (!domain) throw new NotFoundError('Organization domain not found.');

    return c.json(toOrganizationDomainResponse(domain));
});

/**
 * POST /api/organizations/:id/domain
 */
organizationDomainsRoutes.post('/:id/domain', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    const organization = await getOrganizationOrNotFound(db, orgId);
    if (!organization.useOrganizationDomains) {
        throw new BadRequestError("Your organization's plan does not support organization domains.");
    }

    const body = await c.req.json<Record<string, unknown>>();
    const domainName = normalizeDomainName(body.domainName ?? body.DomainName);

    const existingForOrg = await db.select({ id: organizationDomains.id }).from(organizationDomains)
        .where(and(eq(organizationDomains.organizationId, orgId), eq(organizationDomains.domainName, domainName)))
        .get();
    if (existingForOrg) {
        throw new BadRequestError('Domain already exists for this organization.');
    }

    await assertDomainIsNotVerifiedByAnotherOrganization(db, orgId, domainName);

    const now = new Date().toISOString();
    const nextRunDate = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();
    const domainId = generateUuid();
    await db.insert(organizationDomains).values({
        id: domainId,
        organizationId: orgId,
        txt: `bw=${generateSecureRandomString(32)}`,
        domainName,
        creationDate: now,
        nextRunDate,
        jobRunCount: 0,
    });

    const domain = await db.select().from(organizationDomains).where(eq(organizationDomains.id, domainId)).get();
    if (!domain) throw new NotFoundError('Organization domain not found after creation.');

    await logEvent(c.env.DB, 2000, {
        organizationId: orgId,
        actingUserId: userId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    return c.json(toOrganizationDomainResponse(domain), 201);
});

/**
 * DELETE /api/organizations/:id/domain/:domainId
 */
async function removeDomainHandler(c: OrgDomainContext) {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const domainId = c.req.param('domainId');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    await getOrganizationOrNotFound(db, orgId);

    const domain = await db.select().from(organizationDomains)
        .where(and(eq(organizationDomains.id, domainId), eq(organizationDomains.organizationId, orgId)))
        .get();
    if (!domain) throw new NotFoundError('Organization domain not found.');

    await db.delete(organizationDomains).where(eq(organizationDomains.id, domain.id));
    await logEvent(c.env.DB, 2001, {
        organizationId: orgId,
        actingUserId: userId,
        deviceType: getDeviceTypeFromRequest(c),
    });

    return c.body(null, 200);
}

organizationDomainsRoutes.delete('/:id/domain/:domainId', removeDomainHandler);
organizationDomainsRoutes.post('/:id/domain/:domainId/remove', removeDomainHandler);

/**
 * POST /api/organizations/:id/domain/:domainId/verify
 */
organizationDomainsRoutes.post('/:id/domain/:domainId/verify', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const domainId = c.req.param('domainId');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    await getOrganizationOrNotFound(db, orgId);

    const domain = await db.select().from(organizationDomains)
        .where(and(eq(organizationDomains.id, domainId), eq(organizationDomains.organizationId, orgId)))
        .get();
    if (!domain) throw new NotFoundError('Organization domain not found.');

    await assertDomainIsNotVerifiedByAnotherOrganization(db, orgId, domain.domainName);
    const domainVerified = await verifyDnsTxtRecord(c, domain);
    const now = new Date().toISOString();
    if (domainVerified) {
        await assertDomainIsNotVerifiedByAnotherOrganization(db, orgId, domain.domainName);
    }
    await db
        .update(organizationDomains)
        .set({
            verifiedDate: domainVerified ? (domain.verifiedDate ?? now) : domain.verifiedDate,
            lastCheckedDate: now,
            jobRunCount: Math.min((domain.jobRunCount ?? 0) + 1, 3),
            nextRunDate: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
        })
        .where(eq(organizationDomains.id, domain.id));

    const verified = await db.select().from(organizationDomains).where(eq(organizationDomains.id, domain.id)).get();
    if (!verified) throw new NotFoundError('Organization domain not found after verification.');

    if (domainVerified) {
        await ensureSingleOrgPolicyEnabled(db, orgId, now);
        await logEvent(c.env.DB, 2002, {
            organizationId: orgId,
            actingUserId: userId,
            deviceType: getDeviceTypeFromRequest(c),
        });
    }

    return c.json(toOrganizationDomainResponse(verified));
});

/**
 * GET /api/organizations/:id/sso
 */
organizationDomainsRoutes.get('/:id/sso', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    const organization = await getOrganizationOrNotFound(db, orgId);
    const ssoConfig = await db.select().from(ssoConfigs)
        .where(eq(ssoConfigs.organizationId, orgId))
        .get();

    return c.json(toOrganizationSsoResponse(c, organization, ssoConfig));
});

/**
 * POST /api/organizations/:id/sso
 */
organizationDomainsRoutes.post('/:id/sso', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('id');
    const userId = c.get('userId');

    await getManageSsoOrgUser(db, orgId, userId);
    const organization = await getOrganizationOrNotFound(db, orgId);
    if (!organization.useSso) {
        throw new BadRequestError("Your organization's plan does not support SSO.");
    }

    const body = await c.req.json<Record<string, unknown>>();
    const enabled = body.enabled === true || body.Enabled === true;

    const requestedIdentifier = getRequestString(body, 'identifier', 'Identifier');
    const identifier = requestedIdentifier ?? organization.identifier;
    if (identifier && identifier.length > 50) {
        throw new BadRequestError('Identifier must be at most 50 characters.');
    }

    const now = new Date().toISOString();
    const existing = await db.select().from(ssoConfigs)
        .where(eq(ssoConfigs.organizationId, orgId))
        .get();
    const existingData = parseSsoConfigData(existing);
    const urls = buildSsoUrls(c, orgId);
    const oidc = normalizeOrganizationOidcConfig(body, urls.callbackPath, {
        issuer: existing?.issuer,
        clientId: existing?.clientId,
        clientSecretEnv: existing?.clientSecretEnv,
        redirectUri: existing?.redirectUri,
        claimMapping: existing?.claimMapping,
        data: existingData,
    });
    if (enabled) {
        if (!identifier) throw new BadRequestError('Identifier is required when OIDC is enabled.');
        const requestedData = getNestedSsoData(body);
        const configType = requestedData.configType ?? existingData.configType ?? 0;
        if (configType !== 0) {
            throw new BadRequestError('This Workers deployment currently supports OIDC SSO configuration only.');
        }
        const identifierConflict = await db.select({ id: organizations.id }).from(organizations)
            .where(and(
                ne(organizations.id, orgId),
                sql`lower(${organizations.identifier}) = lower(${identifier})`,
            ))
            .get();
        if (identifierConflict) {
            throw new ConflictError('The organization SSO identifier is already in use.');
        }
        await validateOrganizationOidcEnable(
            oidc,
            (bindingName) => Reflect.get(c.env, bindingName),
        );
    }

    const data = normalizeSsoData(body.data ?? body.Data ?? existingData);
    data.authority = oidc.issuer;
    data.clientId = oidc.clientId;
    data.clientSecretEnv = oidc.clientSecretEnv;
    data.redirectUri = oidc.redirectUri;
    data.claimMapping = oidc.claimMapping;

    if (existing) {
        await db.update(ssoConfigs).set({
            enabled,
            issuer: oidc.issuer,
            clientId: oidc.clientId,
            clientSecretEnv: oidc.clientSecretEnv,
            redirectUri: oidc.redirectUri,
            claimMapping: JSON.stringify(oidc.claimMapping),
            data: JSON.stringify(data),
            revisionDate: now,
        }).where(eq(ssoConfigs.id, existing.id));
    } else {
        await db.insert(ssoConfigs).values({
            id: generateUuid(),
            organizationId: orgId,
            enabled,
            issuer: oidc.issuer,
            clientId: oidc.clientId,
            clientSecretEnv: oidc.clientSecretEnv,
            redirectUri: oidc.redirectUri,
            claimMapping: JSON.stringify(oidc.claimMapping),
            data: JSON.stringify(data),
            creationDate: now,
            revisionDate: now,
        });
    }

    await db.update(organizations).set({
        identifier: identifier ?? null,
        revisionDate: now,
    }).where(eq(organizations.id, orgId));

    const updatedOrg = await getOrganizationOrNotFound(db, orgId);
    const updatedConfig = await db.select().from(ssoConfigs)
        .where(eq(ssoConfigs.organizationId, orgId))
        .get();

    return c.json(toOrganizationSsoResponse(c, updatedOrg, updatedConfig));
});

export default organizationDomainsRoutes;
