/**
 * Bitwarden Workers - Reports 路由
 * 对应官方 ReportsController + OrganizationReportsController
 *
 * 路由前缀: /api/reports
 */

import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/d1';
import { eq, and, desc, isNull, inArray, sql } from 'drizzle-orm';
import {
    organizations,
    organizationUsers,
    organizationReports,
    passwordHealthReportApplications,
    users,
    ciphers,
    collections,
    collectionUsers,
    collectionCiphers,
    groups,
    groupUsers,
    collectionGroups,
} from '../db/schema';
import type {
    OrganizationUserRow,
    OrganizationReportRow,
    PasswordHealthReportApplicationRow,
} from '../db/schema';
import { authMiddleware } from '../middleware/auth';
import { NotFoundError, BadRequestError } from '../middleware/error';
import { generateUuid } from '../services/crypto';
import type { Bindings, Variables } from '../types';

const reports = new Hono<{ Bindings: Bindings; Variables: Variables }>();

type D1Db = ReturnType<typeof drizzle>;
const MAX_REPORT_FILE_BYTES = 501 * 1024 * 1024;
const REPORT_FILE_LEEWAY_BYTES = 1024 * 1024;
const REPORT_FILE_UPLOAD_TYPE_DIRECT = 0;

type OrganizationReportMetrics = {
    totalApplicationCount?: number | null;
    totalAtRiskApplicationCount?: number | null;
    totalCriticalApplicationCount?: number | null;
    totalCriticalAtRiskApplicationCount?: number | null;
    totalMemberCount?: number | null;
    totalAtRiskMemberCount?: number | null;
    totalCriticalMemberCount?: number | null;
    totalCriticalAtRiskMemberCount?: number | null;
    totalPasswordCount?: number | null;
    totalAtRiskPasswordCount?: number | null;
    totalCriticalPasswordCount?: number | null;
    totalCriticalAtRiskPasswordCount?: number | null;
};

type OrganizationReportRequestBody = {
    organizationId?: string;
    reportData?: string;
    contentEncryptionKey?: string;
    summaryData?: string;
    applicationData?: string;
    metrics?: OrganizationReportMetrics;
    reportMetrics?: OrganizationReportMetrics;
    fileSize?: number | string | null;
};

type ReportFile = {
    id: string;
    fileName: string;
    size: number;
    validated: boolean;
};

interface OrgUserPermissions {
    accessReports?: boolean;
    [key: string]: boolean | undefined;
}

function parsePermissions(raw: string | null): OrgUserPermissions | null {
    if (!raw) return null;
    try {
        return JSON.parse(raw) as OrgUserPermissions;
    } catch {
        return null;
    }
}

/**
 * AccessReports 权限检查 — 对应官方 CurrentContext.AccessReports
 * Owner / Admin 或 permissions.accessReports
 */
function canAccessReports(orgUser: OrganizationUserRow): boolean {
    if (orgUser.type === 0 || orgUser.type === 1) return true;
    const perms = parsePermissions(orgUser.permissions);
    return !!(perms?.accessReports);
}

async function requireReportsAccess(db: D1Db, orgId: string, userId: string): Promise<OrganizationUserRow> {
    const orgUser = await db.select().from(organizationUsers)
        .where(and(eq(organizationUsers.organizationId, orgId), eq(organizationUsers.userId, userId)))
        .get();

    if (!orgUser || orgUser.status !== 2) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    if (!canAccessReports(orgUser)) {
        throw new NotFoundError('Organization not found or access denied.');
    }
    return orgUser;
}

/**
 * POST /api/reports/organizations/file/validate/azure
 *
 * Workers/R2 版本不依赖 Azure Event Grid；保留兼容响应，避免客户端或部署脚本探测时报 404。
 */
reports.post('/organizations/file/validate/azure', (c) => c.json({ object: 'eventGridValidation' }));

reports.use('/*', authMiddleware);

function toPasswordHealthReportApplicationResponse(row: PasswordHealthReportApplicationRow) {
    return {
        id: row.id,
        organizationId: row.organizationId,
        uri: row.uri,
        url: row.uri,
        creationDate: row.creationDate,
        revisionDate: row.revisionDate,
    };
}

function parseReportFile(raw: string | null): ReportFile | null {
    if (!raw) return null;
    try {
        const parsed = JSON.parse(raw) as Partial<ReportFile> & {
            Id?: string;
            FileName?: string;
            Size?: number | string;
            Validated?: boolean;
        };
        const id = parsed.id ?? parsed.Id;
        if (!id) return null;
        return {
            id,
            fileName: parsed.fileName ?? parsed.FileName ?? 'report-data.json',
            size: Number(parsed.size ?? parsed.Size ?? 0),
            validated: !!(parsed.validated ?? parsed.Validated),
        };
    } catch {
        return null;
    }
}

function serializeReportFile(file: ReportFile): string {
    return JSON.stringify({
        id: file.id,
        fileName: file.fileName,
        size: file.size,
        validated: file.validated,
    });
}

function getMetrics(body: { metrics?: OrganizationReportMetrics; reportMetrics?: OrganizationReportMetrics }) {
    return body.metrics ?? body.reportMetrics ?? {};
}

function applyMetrics(metrics: OrganizationReportMetrics) {
    return {
        applicationCount: metrics.totalApplicationCount ?? null,
        applicationAtRiskCount: metrics.totalAtRiskApplicationCount ?? null,
        criticalApplicationCount: metrics.totalCriticalApplicationCount ?? null,
        criticalApplicationAtRiskCount: metrics.totalCriticalAtRiskApplicationCount ?? null,
        memberCount: metrics.totalMemberCount ?? null,
        memberAtRiskCount: metrics.totalAtRiskMemberCount ?? null,
        criticalMemberCount: metrics.totalCriticalMemberCount ?? null,
        criticalMemberAtRiskCount: metrics.totalCriticalAtRiskMemberCount ?? null,
        passwordCount: metrics.totalPasswordCount ?? null,
        passwordAtRiskCount: metrics.totalAtRiskPasswordCount ?? null,
        criticalPasswordCount: metrics.totalCriticalPasswordCount ?? null,
        criticalPasswordAtRiskCount: metrics.totalCriticalAtRiskPasswordCount ?? null,
    };
}

function getReportFileKey(report: OrganizationReportRow, file: ReportFile): string {
    return `reports/${report.organizationId}/${report.id}/${file.id}/${file.fileName}`;
}

function getReportFileUploadUrl(c: { req: { url: string } }, orgId: string, reportId: string, fileId: string): string {
    const url = new URL(c.req.url);
    url.pathname = `/api/reports/organizations/${orgId}/${reportId}/file`;
    url.search = '';
    url.searchParams.set('reportFileId', fileId);
    return url.toString();
}

function getReportFileDownloadUrl(c: { req: { url: string } }, orgId: string, reportId: string): string {
    const url = new URL(c.req.url);
    url.pathname = `/api/reports/organizations/${orgId}/${reportId}/file/download`;
    url.search = '';
    return url.toString();
}

async function getAuthorizedReport(db: D1Db, orgId: string, reportId: string, userId: string): Promise<OrganizationReportRow> {
    await requireReportsAccess(db, orgId, userId);
    const report = await db.select().from(organizationReports)
        .where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)))
        .get();
    if (!report) throw new NotFoundError('Organization report not found.');
    return report;
}

function toSummaryDataResponse(row: OrganizationReportRow) {
    return {
        encryptedData: row.summaryData ?? '',
        encryptionKey: row.contentEncryptionKey,
        date: row.revisionDate,
    };
}

function toApplicationDataResponse(row: OrganizationReportRow) {
    return {
        applicationData: row.applicationData ?? null,
    };
}

function hasTwoFactorEnabled(raw: string | null): boolean {
    if (!raw) return false;
    try {
        const providers = JSON.parse(raw) as Record<string, unknown> | unknown[];
        if (Array.isArray(providers)) return providers.length > 0;
        return Object.keys(providers).length > 0;
    } catch {
        return false;
    }
}

function bytesOf(value: string): Uint8Array {
    return new TextEncoder().encode(value);
}

function concatBytes(a: Uint8Array<ArrayBufferLike>, b: Uint8Array<ArrayBufferLike>): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0);
    out.set(b, a.length);
    return out;
}

function indexOfBytes(haystack: Uint8Array<ArrayBufferLike>, needle: Uint8Array<ArrayBufferLike>): number {
    if (needle.length === 0) return 0;
    outer:
    for (let i = 0; i <= haystack.length - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (haystack[i + j] !== needle[j]) continue outer;
        }
        return i;
    }
    return -1;
}

function getMultipartBoundary(contentType: string): string | null {
    const match = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(contentType);
    return match?.[1] || match?.[2]?.trim() || null;
}

function createMultipartFileStream(body: ReadableStream<Uint8Array>, boundary: string): ReadableStream<Uint8Array> {
    const headerEnd = bytesOf('\r\n\r\n');
    const delimiter = bytesOf(`\r\n--${boundary}`);
    const keepLength = delimiter.length + 4;
    let buffer: Uint8Array<ArrayBufferLike> = new Uint8Array();
    let inFile = false;
    let done = false;

    return body.pipeThrough(new TransformStream<Uint8Array, Uint8Array>({
        transform(chunk, controller) {
            if (done) return;
            buffer = concatBytes(buffer, chunk);

            if (!inFile) {
                const headerIndex = indexOfBytes(buffer, headerEnd);
                if (headerIndex === -1) {
                    if (buffer.length > 64 * 1024) {
                        throw new BadRequestError('Invalid multipart content.');
                    }
                    return;
                }
                buffer = buffer.slice(headerIndex + headerEnd.length);
                inFile = true;
            }

            const delimiterIndex = indexOfBytes(buffer, delimiter);
            if (delimiterIndex !== -1) {
                if (delimiterIndex > 0) controller.enqueue(buffer.slice(0, delimiterIndex));
                buffer = new Uint8Array();
                done = true;
                return;
            }

            if (buffer.length > keepLength) {
                controller.enqueue(buffer.slice(0, buffer.length - keepLength));
                buffer = buffer.slice(buffer.length - keepLength);
            }
        },
        flush(controller) {
            if (!inFile) throw new BadRequestError('Invalid multipart content.');
            if (!done && buffer.length > 0) controller.enqueue(buffer);
        },
    }));
}

function getUploadBodyStream(request: Request): ReadableStream<Uint8Array> {
    if (!request.body) throw new BadRequestError('Invalid content.');
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.toLowerCase().includes('multipart/')) return request.body;

    const boundary = getMultipartBoundary(contentType);
    if (!boundary) throw new BadRequestError('Invalid multipart content.');
    return createMultipartFileStream(request.body, boundary);
}

function isFileSizeValid(size: number, expected: number): boolean {
    const minimum = Math.max(0, expected - REPORT_FILE_LEEWAY_BYTES);
    const maximum = Math.min(expected + REPORT_FILE_LEEWAY_BYTES, MAX_REPORT_FILE_BYTES);
    return minimum <= size && size <= maximum;
}

// ==================== GET /password-health-report-applications/:orgId ====================
// 对应 ReportsController.GetPasswordHealthReportApplications
reports.get('/password-health-report-applications/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);

    await requireReportsAccess(db, orgId, userId);

    const apps = await db.select().from(passwordHealthReportApplications)
        .where(eq(passwordHealthReportApplications.organizationId, orgId))
        .all();

    return c.json(apps.map(toPasswordHealthReportApplicationResponse));
});

// ==================== POST /password-health-report-application ====================
reports.post('/password-health-report-application', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as { organizationId?: string; url?: string; uri?: string };
    if (!body.organizationId) throw new BadRequestError('OrganizationId is required.');
    if (!body.url && !body.uri) throw new BadRequestError('Url is required.');

    await requireReportsAccess(db, body.organizationId, userId);

    const now = new Date().toISOString();
    const id = generateUuid();
    await db.insert(passwordHealthReportApplications).values({
        id,
        organizationId: body.organizationId,
        uri: body.url ?? body.uri ?? null,
        creationDate: now,
        revisionDate: now,
    });

    const created = await db.select().from(passwordHealthReportApplications)
        .where(eq(passwordHealthReportApplications.id, id))
        .get();
    return c.json(created ? toPasswordHealthReportApplicationResponse(created) : null);
});

// ==================== POST /password-health-report-applications ====================
reports.post('/password-health-report-applications', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => []) as Array<{ organizationId?: string; url?: string; uri?: string }>;
    if (!Array.isArray(body)) throw new BadRequestError('Request body must be an array.');

    const created: PasswordHealthReportApplicationRow[] = [];
    const now = new Date().toISOString();
    for (const item of body) {
        if (!item.organizationId) throw new BadRequestError('OrganizationId is required.');
        if (!item.url && !item.uri) throw new BadRequestError('Url is required.');
        await requireReportsAccess(db, item.organizationId, userId);

        const id = generateUuid();
        await db.insert(passwordHealthReportApplications).values({
            id,
            organizationId: item.organizationId,
            uri: item.url ?? item.uri ?? null,
            creationDate: now,
            revisionDate: now,
        });
        const row = await db.select().from(passwordHealthReportApplications)
            .where(eq(passwordHealthReportApplications.id, id))
            .get();
        if (row) created.push(row);
    }

    return c.json(created.map(toPasswordHealthReportApplicationResponse));
});

// ==================== DELETE /password-health-report-application ====================
reports.delete('/password-health-report-application', async (c) => {
    const db = drizzle(c.env.DB);
    const userId = c.get('userId');
    const body = await c.req.json().catch(() => ({})) as {
        organizationId?: string;
        passwordHealthReportApplicationIds?: string[];
    };
    if (!body.organizationId) throw new BadRequestError('OrganizationId is required.');
    const ids = Array.isArray(body.passwordHealthReportApplicationIds)
        ? body.passwordHealthReportApplicationIds.filter(Boolean)
        : [];
    if (ids.length === 0) throw new BadRequestError('PasswordHealthReportApplicationIds are required.');

    await requireReportsAccess(db, body.organizationId, userId);

    await db.delete(passwordHealthReportApplications)
        .where(and(
            eq(passwordHealthReportApplications.organizationId, body.organizationId),
            inArray(passwordHealthReportApplications.id, ids),
        ));

    return c.body(null, 200);
});

// ==================== GET /organizations/:orgId/latest ====================
// 对应 OrganizationReportsController.GetLatestOrganizationReportAsync
reports.get('/organizations/:orgId/latest', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);

    await requireReportsAccess(db, orgId, userId);

    const latest = await db.select().from(organizationReports)
        .where(eq(organizationReports.organizationId, orgId))
        .orderBy(desc(organizationReports.creationDate))
        .limit(1)
        .get();

    if (!latest) return c.json(null);

    return c.json(toOrganizationReportResponse(latest, c));
});

// ==================== POST /organizations/:orgId ====================
// 对应 OrganizationReportsController.CreateOrganizationReportAsync
reports.post('/organizations/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);

    await requireReportsAccess(db, orgId, userId);

    const body = await c.req.json<OrganizationReportRequestBody>();

    if (body.organizationId && body.organizationId !== orgId) {
        throw new BadRequestError('Organization ID in the request body must match the route parameter');
    }

    const org = await db.select().from(organizations).where(eq(organizations.id, orgId)).get();
    if (!org) throw new BadRequestError('Invalid Organization');

    if (!body.contentEncryptionKey?.trim()) throw new BadRequestError('Content Encryption Key is required');
    if (!body.summaryData?.trim()) throw new BadRequestError('Summary Data is required');
    if (!body.applicationData?.trim()) throw new BadRequestError('Application Data is required');
    const metrics = getMetrics(body);

    const fileSize = body.fileSize === null || body.fileSize === undefined
        ? null
        : Number(body.fileSize);
    if (fileSize !== null) {
        if (!Number.isFinite(fileSize) || fileSize < 0) throw new BadRequestError('File size is required.');
        if (fileSize > MAX_REPORT_FILE_BYTES) throw new BadRequestError('Max file size is 500 MB.');
    } else if (!body.reportData?.trim()) {
        throw new BadRequestError('Report Data is required');
    }

    const now = new Date().toISOString();
    const id = generateUuid();
    const reportFile: ReportFile | null = fileSize === null
        ? null
        : {
            id: generateUuid().replace(/-/g, ''),
            fileName: 'report-data.json',
            size: fileSize,
            validated: false,
        };

    const row: typeof organizationReports.$inferInsert = {
        id,
        organizationId: orgId,
        reportData: body.reportData ?? '',
        contentEncryptionKey: body.contentEncryptionKey ?? '',
        summaryData: body.summaryData ?? null,
        applicationData: body.applicationData ?? null,
        reportFile: reportFile ? serializeReportFile(reportFile) : null,
        ...applyMetrics(metrics),
        creationDate: now,
        revisionDate: now,
    };

    await db.insert(organizationReports).values(row);
    const created = await db.select().from(organizationReports).where(eq(organizationReports.id, id)).get();

    if (!created) return c.json(null);
    const response = toOrganizationReportResponse(created, c);
    if (reportFile) {
        return c.json({
            reportFileUploadUrl: getReportFileUploadUrl(c, orgId, id, reportFile.id),
            reportResponse: response,
            fileUploadType: REPORT_FILE_UPLOAD_TYPE_DIRECT,
        });
    }

    return c.json(response);
});

// ==================== GET /member-cipher-details/:orgId ====================
// 对应 ReportsController.GetMemberCipherDetails
// 复刻官方 RiskInsightsReportQuery + MemberAccessReport_GetMemberAccessCipherDetails SP
reports.get('/member-cipher-details/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);

    await requireReportsAccess(db, orgId, userId);

    const org = await db.select().from(organizations)
        .where(and(eq(organizations.id, orgId), eq(organizations.enabled, true)))
        .get();
    if (!org) throw new NotFoundError('Organization not found.');

    // 1) 直接通过 CollectionUser 关联的 Cipher
    const directRows = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            usesKeyConnector: users.usesKeyConnector,
            cipherId: ciphers.id,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .innerJoin(collectionUsers, eq(collectionUsers.organizationUserId, organizationUsers.id))
        .innerJoin(collections, and(eq(collections.id, collectionUsers.collectionId), eq(collections.organizationId, orgId)))
        .innerJoin(collectionCiphers, eq(collectionCiphers.collectionId, collections.id))
        .innerJoin(ciphers, and(eq(ciphers.id, collectionCiphers.cipherId), eq(ciphers.organizationId, orgId), isNull(ciphers.deletedDate)))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    // 2) 通过 Group -> CollectionGroup 关联的 Cipher
    const groupRows = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            usesKeyConnector: users.usesKeyConnector,
            cipherId: ciphers.id,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .innerJoin(groupUsers, eq(groupUsers.organizationUserId, organizationUsers.id))
        .innerJoin(groups, eq(groups.id, groupUsers.groupId))
        .innerJoin(collectionGroups, eq(collectionGroups.groupId, groups.id))
        .innerJoin(collections, and(eq(collections.id, collectionGroups.collectionId), eq(collections.organizationId, orgId)))
        .innerJoin(collectionCiphers, eq(collectionCiphers.collectionId, collections.id))
        .innerJoin(ciphers, and(eq(ciphers.id, collectionCiphers.cipherId), eq(ciphers.organizationId, orgId), isNull(ciphers.deletedDate)))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    // 3) 没有任何集合关联的成员（通常是受邀但未确认、也未分配集合的用户）
    const allOrgUsers = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            usesKeyConnector: users.usesKeyConnector,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    const usersWithCollections = new Set([
        ...directRows.map(r => r.userGuid),
        ...groupRows.map(r => r.userGuid),
    ]);

    const noCollectionUsers = allOrgUsers.filter(u => !usersWithCollections.has(u.userGuid));

    // 合并并按用户分组（对应 RiskInsightsReportQuery 的 GroupBy 逻辑）
    type RawRow = { userGuid: string; userName: string | null; email: string; usesKeyConnector: boolean | null; cipherId?: string | null };
    const allRows: RawRow[] = [
        ...directRows,
        ...groupRows,
        ...noCollectionUsers.map(u => ({ ...u, cipherId: null as string | null })),
    ];

    const grouped = new Map<string, {
        userGuid: string;
        userName: string | null;
        email: string;
        usesKeyConnector: boolean;
        cipherIds: Set<string>;
    }>();

    for (const row of allRows) {
        let entry = grouped.get(row.userGuid);
        if (!entry) {
            entry = {
                userGuid: row.userGuid,
                userName: row.userName,
                email: row.email,
                usesKeyConnector: row.usesKeyConnector ?? false,
                cipherIds: new Set(),
            };
            grouped.set(row.userGuid, entry);
        }
        if (row.cipherId) {
            entry.cipherIds.add(row.cipherId);
        }
    }

    const result = Array.from(grouped.values()).map(entry => ({
        userGuid: entry.userGuid,
        userName: entry.userName,
        email: entry.email,
        usesKeyConnector: entry.usesKeyConnector,
        cipherIds: Array.from(entry.cipherIds),
    }));

    return c.json(result);
});

// ==================== GET /member-access/:orgId ====================
// 对应 ReportsController.GetMemberAccessReport
reports.get('/member-access/:orgId', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);

    await requireReportsAccess(db, orgId, userId);

    const org = await db.select().from(organizations)
        .where(and(eq(organizations.id, orgId), eq(organizations.enabled, true)))
        .get();
    if (!org) throw new NotFoundError('Organization not found.');
    const useResetPassword = !!org.useResetPassword;

    const directRows = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            twoFactorProviders: users.twoFactorProviders,
            resetPasswordKey: organizationUsers.resetPasswordKey,
            usesKeyConnector: users.usesKeyConnector,
            collectionId: collections.id,
            collectionName: collections.name,
            groupId: sql<string | null>`null`,
            groupName: sql<string | null>`null`,
            readOnly: collectionUsers.readOnly,
            hidePasswords: collectionUsers.hidePasswords,
            manage: collectionUsers.manage,
            cipherId: ciphers.id,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .innerJoin(collectionUsers, eq(collectionUsers.organizationUserId, organizationUsers.id))
        .innerJoin(collections, and(eq(collections.id, collectionUsers.collectionId), eq(collections.organizationId, orgId)))
        .leftJoin(collectionCiphers, eq(collectionCiphers.collectionId, collections.id))
        .leftJoin(ciphers, and(eq(ciphers.id, collectionCiphers.cipherId), eq(ciphers.organizationId, orgId), isNull(ciphers.deletedDate)))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    const groupRows = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            twoFactorProviders: users.twoFactorProviders,
            resetPasswordKey: organizationUsers.resetPasswordKey,
            usesKeyConnector: users.usesKeyConnector,
            collectionId: collections.id,
            collectionName: collections.name,
            groupId: groups.id,
            groupName: groups.name,
            readOnly: collectionGroups.readOnly,
            hidePasswords: collectionGroups.hidePasswords,
            manage: collectionGroups.manage,
            cipherId: ciphers.id,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .innerJoin(groupUsers, eq(groupUsers.organizationUserId, organizationUsers.id))
        .innerJoin(groups, eq(groups.id, groupUsers.groupId))
        .innerJoin(collectionGroups, eq(collectionGroups.groupId, groups.id))
        .innerJoin(collections, and(eq(collections.id, collectionGroups.collectionId), eq(collections.organizationId, orgId)))
        .leftJoin(collectionCiphers, eq(collectionCiphers.collectionId, collections.id))
        .leftJoin(ciphers, and(eq(ciphers.id, collectionCiphers.cipherId), eq(ciphers.organizationId, orgId), isNull(ciphers.deletedDate)))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    const allMembers = await db
        .select({
            userGuid: organizationUsers.id,
            userName: users.name,
            email: sql<string>`coalesce(${users.email}, ${organizationUsers.email})`,
            twoFactorProviders: users.twoFactorProviders,
            resetPasswordKey: organizationUsers.resetPasswordKey,
            usesKeyConnector: users.usesKeyConnector,
        })
        .from(organizationUsers)
        .leftJoin(users, eq(users.id, organizationUsers.userId))
        .where(and(
            eq(organizationUsers.organizationId, orgId),
            inArray(organizationUsers.status, [0, 1, 2]),
        ))
        .all();

    type AccessRow = {
        userGuid: string;
        userName: string | null;
        email: string;
        twoFactorProviders: string | null;
        resetPasswordKey: string | null;
        usesKeyConnector: boolean | null;
        collectionId: string | null;
        collectionName: string | null;
        groupId: string | null;
        groupName: string | null;
        readOnly: boolean | null;
        hidePasswords: boolean | null;
        manage: boolean | null;
        cipherId: string | null;
    };

    const grouped = new Map<string, {
        userGuid: string;
        userName: string | null;
        email: string;
        twoFactorEnabled: boolean;
        accountRecoveryEnabled: boolean;
        usesKeyConnector: boolean;
        groups: Set<string>;
        collections: Set<string>;
        cipherIds: Set<string>;
        details: Map<string, {
            collectionId: string | null;
            groupId: string | null;
            groupName: string | null;
            collectionName: string | null;
            readOnly: boolean | null;
            hidePasswords: boolean | null;
            manage: boolean | null;
            collectionCipherIds: Set<string>;
        }>;
    }>();

    function ensureMember(member: {
        userGuid: string;
        userName: string | null;
        email: string;
        twoFactorProviders: string | null;
        resetPasswordKey: string | null;
        usesKeyConnector: boolean | null;
    }) {
        let entry = grouped.get(member.userGuid);
        if (!entry) {
            entry = {
                userGuid: member.userGuid,
                userName: member.userName,
                email: member.email,
                twoFactorEnabled: hasTwoFactorEnabled(member.twoFactorProviders),
                accountRecoveryEnabled: !!member.resetPasswordKey && useResetPassword,
                usesKeyConnector: member.usesKeyConnector ?? false,
                groups: new Set(),
                collections: new Set(),
                cipherIds: new Set(),
                details: new Map(),
            };
            grouped.set(member.userGuid, entry);
        }
        return entry;
    }

    for (const member of allMembers) {
        ensureMember(member);
    }

    for (const row of [...directRows, ...groupRows] as AccessRow[]) {
        const entry = ensureMember(row);
        if (row.groupId) entry.groups.add(row.groupId);
        if (row.collectionId) entry.collections.add(row.collectionId);
        if (row.cipherId) entry.cipherIds.add(row.cipherId);

        const detailKey = `${row.collectionId || ''}:${row.groupId || ''}:${row.readOnly}:${row.hidePasswords}:${row.manage}`;
        let detail = entry.details.get(detailKey);
        if (!detail) {
            detail = {
                collectionId: row.collectionId,
                groupId: row.groupId,
                groupName: row.groupName,
                collectionName: row.collectionName,
                readOnly: row.readOnly,
                hidePasswords: row.hidePasswords,
                manage: row.manage,
                collectionCipherIds: new Set(),
            };
            entry.details.set(detailKey, detail);
        }
        if (row.cipherId) detail.collectionCipherIds.add(row.cipherId);
    }

    return c.json(Array.from(grouped.values()).map(member => ({
        userName: member.userName,
        email: member.email,
        twoFactorEnabled: member.twoFactorEnabled,
        accountRecoveryEnabled: member.accountRecoveryEnabled,
        groupsCount: member.groups.size,
        collectionsCount: member.collections.size,
        totalItemCount: member.cipherIds.size,
        userGuid: member.userGuid,
        usesKeyConnector: member.usesKeyConnector,
        accessDetails: Array.from(member.details.values()).map(detail => ({
            collectionId: detail.collectionId,
            groupId: detail.groupId,
            groupName: detail.groupName,
            collectionName: detail.collectionName,
            itemCount: detail.collectionCipherIds.size,
            readOnly: detail.readOnly,
            hidePasswords: detail.hidePasswords,
            manage: detail.manage,
            collectionCipherIds: Array.from(detail.collectionCipherIds),
        })),
    })));
});

// ==================== GET /organizations/:orgId/data/summary ====================
reports.get('/organizations/:orgId/data/summary', async (c) => {
    const orgId = c.req.param('orgId');
    const userId = c.get('userId');
    const db = drizzle(c.env.DB);
    await requireReportsAccess(db, orgId, userId);

    const startDate = c.req.query('startDate');
    const endDate = c.req.query('endDate');
    const rows = await db.select().from(organizationReports)
        .where(eq(organizationReports.organizationId, orgId))
        .all();

    const filtered = rows
        .filter((row) => {
            if (!row.summaryData) return false;
            if (startDate && row.revisionDate < startDate) return false;
            if (endDate && row.revisionDate > endDate) return false;
            return true;
        })
        .sort((a, b) => b.revisionDate.localeCompare(a.revisionDate));

    return c.json(filtered.map(toSummaryDataResponse));
});

// ==================== GET /organizations/:orgId/data/summary/:reportId ====================
reports.get('/organizations/:orgId/data/summary/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const report = await getAuthorizedReport(db, c.req.param('orgId'), c.req.param('reportId'), c.get('userId'));
    if (!report.summaryData) throw new NotFoundError('Report not found for the specified organization.');
    return c.json(toSummaryDataResponse(report));
});

// ==================== PATCH /organizations/:orgId/data/summary/:reportId ====================
reports.patch('/organizations/:orgId/data/summary/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const body = await c.req.json().catch(() => ({})) as { summaryData?: string | null; metrics?: OrganizationReportMetrics; reportMetrics?: OrganizationReportMetrics };
    const now = new Date().toISOString();

    await db.update(organizationReports).set({
        summaryData: body.summaryData ?? '',
        ...applyMetrics(getMetrics(body)),
        revisionDate: now,
    }).where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));

    const updated = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    return c.json(toOrganizationReportResponse(updated, c));
});

// ==================== GET /organizations/:orgId/data/application/:reportId ====================
reports.get('/organizations/:orgId/data/application/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const report = await getAuthorizedReport(db, c.req.param('orgId'), c.req.param('reportId'), c.get('userId'));
    if (!report.applicationData) throw new NotFoundError('Organization report application data not found.');
    return c.json(toApplicationDataResponse(report));
});

// ==================== PATCH /organizations/:orgId/data/application/:reportId ====================
reports.patch('/organizations/:orgId/data/application/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const body = await c.req.json().catch(() => ({})) as { applicationData?: string | null };
    const now = new Date().toISOString();

    await db.update(organizationReports).set({
        applicationData: body.applicationData ?? '',
        revisionDate: now,
    }).where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));

    const updated = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    return c.json(toOrganizationReportResponse(updated, c));
});

// ==================== GET /organizations/:orgId/:reportId ====================
reports.get('/organizations/:orgId/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const report = await getAuthorizedReport(db, c.req.param('orgId'), c.req.param('reportId'), c.get('userId'));
    return c.json(toOrganizationReportResponse(report, c));
});

// ==================== PATCH /organizations/:orgId/:reportId ====================
reports.patch('/organizations/:orgId/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const body = await c.req.json<OrganizationReportRequestBody>();
    const now = new Date().toISOString();

    await db.update(organizationReports).set({
        contentEncryptionKey: body.contentEncryptionKey ?? '',
        summaryData: body.summaryData ?? '',
        applicationData: body.applicationData ?? '',
        ...applyMetrics(getMetrics(body)),
        revisionDate: now,
    }).where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));

    const updated = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    return c.json(toOrganizationReportResponse(updated, c));
});

// ==================== DELETE /organizations/:orgId/:reportId ====================
reports.delete('/organizations/:orgId/:reportId', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    const report = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const file = parseReportFile(report.reportFile);

    await db.delete(organizationReports)
        .where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));
    if (file) {
        await c.env.ATTACHMENTS.delete(getReportFileKey(report, file));
    }

    return c.body(null, 200);
});

// ==================== GET /organizations/:orgId/:reportId/file/renew ====================
reports.get('/organizations/:orgId/:reportId/file/renew', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    const reportFileId = c.req.query('reportFileId') || '';
    const report = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const file = parseReportFile(report.reportFile);

    if (!reportFileId) throw new BadRequestError('ReportFileId is required.');
    if (!file || file.id !== reportFileId || file.validated) throw new NotFoundError('Report file not found.');

    return c.json({
        reportFileUploadUrl: getReportFileUploadUrl(c, orgId, reportId, file.id),
        reportResponse: toOrganizationReportResponse(report, c),
        fileUploadType: REPORT_FILE_UPLOAD_TYPE_DIRECT,
    });
});

// ==================== POST /organizations/:orgId/:reportId/file ====================
reports.post('/organizations/:orgId/:reportId/file', async (c) => {
    const db = drizzle(c.env.DB);
    const orgId = c.req.param('orgId');
    const reportId = c.req.param('reportId');
    const reportFileId = c.req.query('reportFileId') || '';
    const report = await getAuthorizedReport(db, orgId, reportId, c.get('userId'));
    const file = parseReportFile(report.reportFile);

    if (!reportFileId) throw new BadRequestError('ReportFileId query parameter is required');
    if (!file || file.id !== reportFileId || file.validated) throw new NotFoundError('Report file not found.');

    const contentLength = Number(c.req.header('content-length') || 0);
    if (Number.isFinite(contentLength) && contentLength > MAX_REPORT_FILE_BYTES + REPORT_FILE_LEEWAY_BYTES) {
        throw new BadRequestError('Max file size is 500 MB.');
    }

    const key = getReportFileKey(report, file);
    const object = await c.env.ATTACHMENTS.put(key, getUploadBodyStream(c.req.raw), {
        httpMetadata: {
            contentType: 'application/octet-stream',
            contentDisposition: `attachment; filename="${file.fileName}"`,
        },
        customMetadata: {
            organizationId: orgId,
            reportId,
            reportFileId: file.id,
        },
    });

    const actualSize = object.size;
    if (!isFileSizeValid(actualSize, file.size)) {
        await c.env.ATTACHMENTS.delete(key);
        await db.delete(organizationReports)
            .where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));
        throw new BadRequestError('File received does not match expected constraints.');
    }

    const updatedFile = { ...file, size: actualSize, validated: true };
    await db.update(organizationReports).set({
        reportFile: serializeReportFile(updatedFile),
        revisionDate: new Date().toISOString(),
    }).where(and(eq(organizationReports.id, reportId), eq(organizationReports.organizationId, orgId)));

    return c.body(null, 200);
});

// ==================== GET /organizations/:orgId/:reportId/file/download ====================
reports.get('/organizations/:orgId/:reportId/file/download', async (c) => {
    const db = drizzle(c.env.DB);
    const report = await getAuthorizedReport(db, c.req.param('orgId'), c.req.param('reportId'), c.get('userId'));
    const file = parseReportFile(report.reportFile);
    if (!file || !file.validated) throw new NotFoundError('Report file not found.');

    const object = await c.env.ATTACHMENTS.get(getReportFileKey(report, file));
    if (!object) throw new NotFoundError('Report file not found.');

    const headers = new Headers();
    headers.set('Content-Type', object.httpMetadata?.contentType || 'application/octet-stream');
    headers.set('Content-Length', object.size.toString());
    headers.set('Content-Disposition', object.httpMetadata?.contentDisposition || `attachment; filename="${file.fileName}"`);
    return new Response(object.body, { headers });
});

// ==================== 响应转换 ====================

function toOrganizationReportResponse(row: OrganizationReportRow, c?: { req: { url: string } }) {
    const reportFile = parseReportFile(row.reportFile);
    return {
        id: row.id,
        organizationId: row.organizationId,
        reportData: row.reportData,
        contentEncryptionKey: row.contentEncryptionKey,
        summaryData: row.summaryData ?? null,
        applicationData: row.applicationData ?? null,
        reportFile,
        reportFileDownloadUrl: reportFile?.validated && c
            ? getReportFileDownloadUrl(c, row.organizationId, row.id)
            : null,
        fileUploadType: reportFile ? REPORT_FILE_UPLOAD_TYPE_DIRECT : null,
        applicationCount: row.applicationCount ?? null,
        applicationAtRiskCount: row.applicationAtRiskCount ?? null,
        criticalApplicationCount: row.criticalApplicationCount ?? null,
        criticalApplicationAtRiskCount: row.criticalApplicationAtRiskCount ?? null,
        passwordCount: row.passwordCount ?? null,
        passwordAtRiskCount: row.passwordAtRiskCount ?? null,
        criticalPasswordCount: row.criticalPasswordCount ?? null,
        criticalPasswordAtRiskCount: row.criticalPasswordAtRiskCount ?? null,
        memberCount: row.memberCount ?? null,
        memberAtRiskCount: row.memberAtRiskCount ?? null,
        criticalMemberCount: row.criticalMemberCount ?? null,
        criticalMemberAtRiskCount: row.criticalMemberAtRiskCount ?? null,
        creationDate: row.creationDate,
        revisionDate: row.revisionDate,
    };
}

export default reports;
