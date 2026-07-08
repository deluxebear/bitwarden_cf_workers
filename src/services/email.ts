import { and, eq, isNull } from 'drizzle-orm';
import { verificationTokens } from '../db/schema';
import { BadRequestError } from '../middleware/error';
import { generateSecureRandomString, generateUuid, sha256 } from './crypto';

type D1Db = ReturnType<typeof import('drizzle-orm/d1').drizzle>;

export type VerificationTokenType =
    | 'registration'
    | 'password_hint'
    | 'email_change'
    | 'new_device'
    | 'two_factor'
    | 'organization_invite';

type EmailEnv = {
    EMAIL?: SendEmail;
    EMAIL_MODE?: string;
    EMAIL_RETURN_TOKENS?: string;
    EMAIL_FROM?: string;
    EMAIL_FROM_NAME?: string;
    EMAIL_REPLY_TO?: string;
    EMAIL_PROVIDER_ENDPOINT?: string;
    EMAIL_PROVIDER_TOKEN?: string;
    VAULT_BASE_URL?: string;
};

type VerificationTokenResult = {
    token: string;
    expiresAt: string;
};

function normalizeEmail(email: string): string {
    return email.toLowerCase().trim();
}

function isTokenEchoEnabled(env: EmailEnv): boolean {
    return String(env.EMAIL_RETURN_TOKENS ?? '').toLowerCase() === 'true';
}

function getEmailMode(env: EmailEnv): 'disabled' | 'log' | 'cloudflare' | 'provider' {
    const mode = String(env.EMAIL_MODE ?? 'disabled').toLowerCase();
    if (mode === 'cloudflare') return 'cloudflare';
    if (mode === 'provider') return 'provider';
    if (mode === 'disabled') return 'disabled';
    return 'log';
}

function escapeHtml(value: unknown): string {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function parseFromAddress(env: EmailEnv): string | EmailAddress {
    const configured = env.EMAIL_FROM?.trim();
    if (!configured) {
        throw new BadRequestError('Cloudflare email sender is not configured. Set EMAIL_FROM.');
    }

    const match = configured.match(/^(.+?)\s*<([^<>@\s]+@[^<>@\s]+)>$/);
    const email = match ? match[2].trim() : configured;
    const name = (env.EMAIL_FROM_NAME || (match ? match[1] : '')).trim().replace(/^"|"$/g, '');
    return name ? { email, name } : email;
}

function getEmailMessage(type: VerificationTokenType, data: Record<string, unknown>) {
    const token = String(data.token ?? '');
    const expiresAt = String(data.expiresAt ?? '');
    const vaultUrl = typeof data.vaultUrl === 'string' && data.vaultUrl ? data.vaultUrl : null;
    const hint = String(data.hint ?? '');
    const organizationName = String(data.organizationName ?? 'your organization');
    const inviteUrl = String(data.inviteUrl ?? '');

    switch (type) {
        case 'registration':
            return {
                subject: 'Verify your Bitwarden account',
                text: `Use this verification token to finish creating your Bitwarden account:\n\n${token}\n\nThis token expires at ${expiresAt}.${vaultUrl ? `\n\nVault: ${vaultUrl}` : ''}`,
                html: `<p>Use this verification token to finish creating your Bitwarden account:</p><p><code>${escapeHtml(token)}</code></p><p>This token expires at ${escapeHtml(expiresAt)}.</p>${vaultUrl ? `<p><a href="${escapeHtml(vaultUrl)}">Open vault</a></p>` : ''}`,
            };
        case 'email_change':
            return {
                subject: 'Verify your new Bitwarden email address',
                text: `Use this verification token to confirm your new email address:\n\n${token}\n\nThis token expires at ${expiresAt}.`,
                html: `<p>Use this verification token to confirm your new email address:</p><p><code>${escapeHtml(token)}</code></p><p>This token expires at ${escapeHtml(expiresAt)}.</p>`,
            };
        case 'new_device':
            return {
                subject: 'Verify your new Bitwarden device',
                text: `Use this verification token to finish signing in from a new device:\n\n${token}\n\nThis token expires at ${expiresAt}.`,
                html: `<p>Use this verification token to finish signing in from a new device:</p><p><code>${escapeHtml(token)}</code></p><p>This token expires at ${escapeHtml(expiresAt)}.</p>`,
            };
        case 'password_hint':
            return {
                subject: 'Your Bitwarden master password hint',
                text: hint ? `Your master password hint is:\n\n${hint}` : 'You do not have a master password hint configured.',
                html: hint ? `<p>Your master password hint is:</p><p>${escapeHtml(hint)}</p>` : '<p>You do not have a master password hint configured.</p>',
            };
        case 'two_factor':
            return {
                subject: 'Your Bitwarden two-step login code',
                text: `Use this code to finish signing in to Bitwarden:\n\n${token}${expiresAt ? `\n\nThis code expires at ${expiresAt}.` : ''}`,
                html: `<p>Use this code to finish signing in to Bitwarden:</p><p><code>${escapeHtml(token)}</code></p>${expiresAt ? `<p>This code expires at ${escapeHtml(expiresAt)}.</p>` : ''}`,
            };
        case 'organization_invite':
            return {
                subject: `You have been invited to join ${organizationName} on Bitwarden`,
                text: `You have been invited to join ${organizationName} on Bitwarden.\n\nAccept the invitation:\n${inviteUrl}`,
                html: `<p>You have been invited to join ${escapeHtml(organizationName)} on Bitwarden.</p><p><a href="${escapeHtml(inviteUrl)}">Accept invitation</a></p>`,
            };
    }
}

async function deliverCloudflareEmail(
    env: EmailEnv,
    type: VerificationTokenType,
    email: string,
    data: Record<string, unknown>,
): Promise<void> {
    if (!env.EMAIL) {
        throw new BadRequestError('Cloudflare email binding is not configured. Add [[send_email]] name = "EMAIL".');
    }

    const message = getEmailMessage(type, data);
    try {
        await env.EMAIL.send({
            to: normalizeEmail(email),
            from: parseFromAddress(env),
            replyTo: env.EMAIL_REPLY_TO?.trim() || undefined,
            subject: message.subject,
            text: message.text,
            html: message.html,
        });
    } catch (error) {
        const details = error instanceof Error ? error.message : 'unknown';
        const errorLike = error as { code?: unknown; name?: unknown };
        const code = typeof errorLike.code === 'string' ? errorLike.code : null;
        const name = typeof errorLike.name === 'string'
            ? errorLike.name
            : error instanceof Error ? error.name : null;
        console.error(JSON.stringify({
            event: 'email.cloudflare.failed',
            type,
            email: normalizeEmail(email),
            code,
            name,
            error: details,
        }));
        throw new BadRequestError(code
            ? `Cloudflare Email Service rejected the message (${code}).`
            : 'Cloudflare Email Service rejected the message.');
    }
}

async function createVerificationToken(
    db: D1Db,
    email: string,
    type: VerificationTokenType,
    userId: string | null,
    ttlSeconds: number,
): Promise<VerificationTokenResult> {
    const token = generateSecureRandomString(64);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000).toISOString();

    await db.insert(verificationTokens).values({
        id: generateUuid(),
        userId,
        email: normalizeEmail(email),
        type,
        tokenHash: await sha256(token),
        expiresAt,
        usedAt: null,
        creationDate: now.toISOString(),
    });

    return { token, expiresAt };
}

async function deliverEmail(
    env: EmailEnv,
    type: VerificationTokenType,
    email: string,
    data: Record<string, unknown>,
): Promise<void> {
    const mode = getEmailMode(env);
    if (mode === 'disabled') {
        if (isTokenEchoEnabled(env)) return;
        throw new BadRequestError('Email delivery is disabled.');
    }

    if (mode === 'log') {
        console.log(JSON.stringify({
            event: 'email.delivery.log',
            type,
            email: normalizeEmail(email),
            data,
        }));
        return;
    }

    if (mode === 'cloudflare') {
        await deliverCloudflareEmail(env, type, email, data);
        return;
    }

    if (!env.EMAIL_PROVIDER_ENDPOINT) {
        throw new BadRequestError('Email provider is not configured.');
    }

    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (env.EMAIL_PROVIDER_TOKEN) {
        headers.Authorization = `Bearer ${env.EMAIL_PROVIDER_TOKEN}`;
    }

    const response = await fetch(env.EMAIL_PROVIDER_ENDPOINT, {
        method: 'POST',
        headers,
        body: JSON.stringify({
            type,
            to: normalizeEmail(email),
            data,
        }),
    });
    if (!response.ok) {
        throw new BadRequestError('Email provider rejected the message.');
    }
}

async function getValidVerificationToken(
    db: D1Db,
    email: string,
    type: VerificationTokenType,
    token: string,
    userId?: string | null,
): Promise<typeof verificationTokens.$inferSelect> {
    const tokenHash = await sha256(token);
    const normalizedEmail = normalizeEmail(email);
    const row = await db.select().from(verificationTokens)
        .where(and(
            eq(verificationTokens.tokenHash, tokenHash),
            eq(verificationTokens.email, normalizedEmail),
            eq(verificationTokens.type, type),
            isNull(verificationTokens.usedAt),
        ))
        .get();

    if (!row) {
        throw new BadRequestError('Verification token is invalid.');
    }
    if (row.expiresAt <= new Date().toISOString()) {
        throw new BadRequestError('Verification token has expired.');
    }
    if (userId && row.userId && row.userId !== userId) {
        throw new BadRequestError('Verification token is invalid.');
    }

    return row;
}

export async function verifyVerificationToken(
    db: D1Db,
    email: string,
    type: VerificationTokenType,
    token: string,
    userId?: string | null,
): Promise<void> {
    await getValidVerificationToken(db, email, type, token, userId);
}

export async function consumeVerificationToken(
    db: D1Db,
    email: string,
    type: VerificationTokenType,
    token: string,
    userId?: string | null,
): Promise<void> {
    const row = await getValidVerificationToken(db, email, type, token, userId);
    await db.update(verificationTokens)
        .set({ usedAt: new Date().toISOString() })
        .where(eq(verificationTokens.id, row.id));
}

export async function sendRegistrationVerification(
    db: D1Db,
    env: EmailEnv,
    email: string,
): Promise<VerificationTokenResult> {
    const result = await createVerificationToken(db, email, 'registration', null, 60 * 60);
    await deliverEmail(env, 'registration', email, {
        token: result.token,
        expiresAt: result.expiresAt,
        vaultUrl: env.VAULT_BASE_URL ?? null,
    });
    return result;
}

export async function sendPasswordHint(env: EmailEnv, email: string, hint: string | null): Promise<void> {
    await deliverEmail(env, 'password_hint', email, { hint: hint ?? '' });
}

export async function sendTwoFactorEmail(env: EmailEnv, email: string, token: string, expiresAt?: string): Promise<void> {
    await deliverEmail(env, 'two_factor', email, { token, expiresAt: expiresAt ?? '' });
}

export async function sendEmailChangeToken(
    db: D1Db,
    env: EmailEnv,
    userId: string,
    email: string,
): Promise<VerificationTokenResult> {
    const result = await createVerificationToken(db, email, 'email_change', userId, 60 * 60);
    await deliverEmail(env, 'email_change', email, {
        token: result.token,
        expiresAt: result.expiresAt,
    });
    return result;
}

export async function sendNewDeviceVerification(
    db: D1Db,
    env: EmailEnv,
    userId: string,
    email: string,
): Promise<VerificationTokenResult> {
    const result = await createVerificationToken(db, email, 'new_device', userId, 15 * 60);
    await deliverEmail(env, 'new_device', email, {
        token: result.token,
        expiresAt: result.expiresAt,
    });
    return result;
}

export async function sendOrganizationInvite(
    env: EmailEnv,
    email: string,
    organizationName: string,
    inviteUrl: string,
): Promise<void> {
    await deliverEmail(env, 'organization_invite', email, {
        organizationName,
        inviteUrl,
    });
}

export function buildDevTokenResponse(env: EmailEnv, result: VerificationTokenResult): Record<string, unknown> {
    if (!isTokenEchoEnabled(env)) {
        return {};
    }
    return { token: result.token, emailVerificationToken: result.token, expiresAt: result.expiresAt };
}
