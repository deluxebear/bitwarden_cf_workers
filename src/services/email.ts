import { and, eq, isNull } from 'drizzle-orm';
import { verificationTokens } from '../db/schema';
import { BadRequestError } from '../middleware/error';
import { generateSecureRandomString, generateUuid, sha256 } from './crypto';

type D1Db = ReturnType<typeof import('drizzle-orm/d1').drizzle>;

export type VerificationTokenType =
    | 'registration'
    | 'password_hint'
    | 'email_change'
    | 'new_device';

type EmailEnv = {
    EMAIL_MODE?: string;
    EMAIL_RETURN_TOKENS?: string;
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

function getEmailMode(env: EmailEnv): 'disabled' | 'log' | 'provider' {
    const mode = String(env.EMAIL_MODE ?? 'disabled').toLowerCase();
    if (mode === 'provider') return 'provider';
    if (mode === 'disabled') return 'disabled';
    return 'log';
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

export function buildDevTokenResponse(env: EmailEnv, result: VerificationTokenResult): Record<string, unknown> {
    if (!isTokenEchoEnabled(env)) {
        return {};
    }
    return { token: result.token, emailVerificationToken: result.token, expiresAt: result.expiresAt };
}
