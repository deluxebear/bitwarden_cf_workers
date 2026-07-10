import { sha256 } from './crypto';
import { generateDuoOpaqueValue, normalizeDuoHost, validateDuoConfig, type DuoConfig } from './duo';

const CONFIG_KEY_VERSION = 1;
const LOGIN_STATE_LIFETIME_MS = 15 * 60 * 1000;
const MAX_ACTIVE_LOGIN_STATES_PER_USER = 20;

export type DuoConfigOwner =
    | { userId: string; organizationId?: never }
    | { userId?: never; organizationId: string };

export type StoredDuoConfig = DuoConfig & DuoConfigOwner & {
    id: string;
    clientSecretPrefix: string;
    keyVersion: number;
    creationDate: string;
    revisionDate: string;
};

export type DuoLoginState = {
    userId: string;
    providerType: 2 | 6;
    organizationId: string | null;
    configId: string;
    configRevision: string;
    nonce: string;
    redirectUri: string;
};

type EncryptedSecret = {
    ciphertext: string;
    iv: string;
    keyVersion: number;
};

type DuoConfigRow = {
    id: string;
    user_id: string | null;
    organization_id: string | null;
    client_id: string;
    host: string;
    client_secret_ciphertext: string;
    client_secret_iv: string;
    client_secret_prefix: string;
    key_version: number;
    creation_date: string;
    revision_date: string;
};

type DuoLoginStateRow = {
    user_id: string;
    provider_type: number;
    organization_id: string | null;
    config_id: string;
    config_revision: string;
    nonce: string;
    redirect_uri: string;
};

function bytesToBase64Url(bytes: Uint8Array): string {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToBytes(value: string): Uint8Array {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized + '='.repeat((4 - normalized.length % 4) % 4);
    let binary: string;
    try {
        binary = atob(padded);
    } catch {
        throw new Error('DUO_CONFIG_ENCRYPTION_KEY is not valid base64.');
    }
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function importConfigKey(
    encodedKey: string,
    usage: Array<'encrypt' | 'decrypt'>,
): Promise<CryptoKey> {
    const keyBytes = base64UrlToBytes(encodedKey.trim());
    if (keyBytes.length !== 32) {
        throw new Error('DUO_CONFIG_ENCRYPTION_KEY must encode exactly 32 bytes.');
    }
    return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, usage);
}

function configId(owner: DuoConfigOwner): string {
    if (owner.userId) return `user:${owner.userId}`;
    if (owner.organizationId) return `organization:${owner.organizationId}`;
    throw new Error('A Duo configuration must have exactly one owner.');
}

function secretAdditionalData(id: string): Uint8Array {
    return new TextEncoder().encode(`bitwarden-workers:duo-config:v1:${id}`);
}

export async function encryptDuoClientSecret(
    secret: string,
    encodedKey: string,
    id: string,
): Promise<EncryptedSecret> {
    if (secret.length !== 40) throw new Error('Duo Client Secret must be exactly 40 characters.');
    const key = await importConfigKey(encodedKey, ['encrypt']);
    const iv = new Uint8Array(12);
    crypto.getRandomValues(iv);
    const ciphertext = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv,
        additionalData: secretAdditionalData(id),
        tagLength: 128,
    }, key, new TextEncoder().encode(secret));
    return {
        ciphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
        iv: bytesToBase64Url(iv),
        keyVersion: CONFIG_KEY_VERSION,
    };
}

export async function decryptDuoClientSecret(
    encrypted: EncryptedSecret,
    encodedKey: string,
    id: string,
): Promise<string> {
    if (encrypted.keyVersion !== CONFIG_KEY_VERSION) throw new Error('Unsupported Duo encryption key version.');
    const key = await importConfigKey(encodedKey, ['decrypt']);
    const iv = base64UrlToBytes(encrypted.iv);
    if (iv.length !== 12) throw new Error('Duo secret IV is invalid.');
    try {
        const plaintext = await crypto.subtle.decrypt({
            name: 'AES-GCM',
            iv,
            additionalData: secretAdditionalData(id),
            tagLength: 128,
        }, key, base64UrlToBytes(encrypted.ciphertext));
        const secret = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(plaintext);
        if (secret.length !== 40) throw new Error('Duo secret plaintext is invalid.');
        return secret;
    } catch {
        throw new Error('Unable to decrypt Duo client secret.');
    }
}

function ownerFromRow(row: DuoConfigRow): DuoConfigOwner {
    if (row.user_id && !row.organization_id) return { userId: row.user_id };
    if (row.organization_id && !row.user_id) return { organizationId: row.organization_id };
    throw new Error('Duo configuration owner is invalid.');
}

async function rowToConfig(row: DuoConfigRow, encodedKey: string): Promise<StoredDuoConfig> {
    const clientSecret = await decryptDuoClientSecret({
        ciphertext: row.client_secret_ciphertext,
        iv: row.client_secret_iv,
        keyVersion: row.key_version,
    }, encodedKey, row.id);
    return {
        id: row.id,
        ...ownerFromRow(row),
        clientId: row.client_id,
        clientSecret,
        clientSecretPrefix: row.client_secret_prefix,
        host: normalizeDuoHost(row.host),
        keyVersion: row.key_version,
        creationDate: row.creation_date,
        revisionDate: row.revision_date,
    };
}

export async function upsertDuoConfig(
    db: D1Database,
    encodedKey: string,
    owner: DuoConfigOwner,
    configValue: DuoConfig,
    expectedRevision?: string | null,
): Promise<StoredDuoConfig> {
    const config = validateDuoConfig(configValue);
    const id = configId(owner);
    const encrypted = await encryptDuoClientSecret(config.clientSecret, encodedKey, id);
    const now = new Date().toISOString();
    const revision = `${now}:${crypto.randomUUID()}`;
    let result: D1Result;
    if (expectedRevision === null) {
        result = await db.prepare(`
            INSERT INTO duo_configs
                (id, user_id, organization_id, client_id, host, client_secret_ciphertext,
                 client_secret_iv, client_secret_prefix, key_version, creation_date, revision_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
        `).bind(
            id, owner.userId ?? null, owner.organizationId ?? null, config.clientId, config.host,
            encrypted.ciphertext, encrypted.iv, config.clientSecret.slice(0, 6),
            encrypted.keyVersion, now, revision,
        ).run();
    } else if (typeof expectedRevision === 'string') {
        result = await db.prepare(`
            UPDATE duo_configs
            SET client_id = ?, host = ?, client_secret_ciphertext = ?, client_secret_iv = ?,
                client_secret_prefix = ?, key_version = ?, revision_date = ?
            WHERE id = ? AND revision_date = ?
        `).bind(
            config.clientId, config.host, encrypted.ciphertext, encrypted.iv,
            config.clientSecret.slice(0, 6), encrypted.keyVersion, revision, id, expectedRevision,
        ).run();
    } else {
        result = await db.prepare(`
            INSERT INTO duo_configs
                (id, user_id, organization_id, client_id, host, client_secret_ciphertext,
                 client_secret_iv, client_secret_prefix, key_version, creation_date, revision_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                client_id = excluded.client_id,
                host = excluded.host,
                client_secret_ciphertext = excluded.client_secret_ciphertext,
                client_secret_iv = excluded.client_secret_iv,
                client_secret_prefix = excluded.client_secret_prefix,
                key_version = excluded.key_version,
                revision_date = excluded.revision_date
        `).bind(
            id, owner.userId ?? null, owner.organizationId ?? null, config.clientId, config.host,
            encrypted.ciphertext, encrypted.iv, config.clientSecret.slice(0, 6),
            encrypted.keyVersion, now, revision,
        ).run();
    }
    if (result.meta.changes !== 1) throw new Error('Unable to persist Duo configuration.');
    const stored = await getDuoConfigById(db, encodedKey, id);
    if (!stored || stored.revisionDate !== revision) throw new Error('Unable to read Duo configuration.');
    return stored;
}

export async function getDuoConfigById(
    db: D1Database,
    encodedKey: string,
    id: string,
): Promise<StoredDuoConfig | null> {
    const row = await db.prepare(`
        SELECT id, user_id, organization_id, client_id, host, client_secret_ciphertext,
               client_secret_iv, client_secret_prefix, key_version, creation_date, revision_date
        FROM duo_configs WHERE id = ?
    `).bind(id).first<DuoConfigRow>();
    return row ? rowToConfig(row, encodedKey) : null;
}

export async function getDuoConfigByOwner(
    db: D1Database,
    encodedKey: string,
    owner: DuoConfigOwner,
): Promise<StoredDuoConfig | null> {
    return getDuoConfigById(db, encodedKey, configId(owner));
}

export async function deleteDuoConfig(
    db: D1Database,
    owner: DuoConfigOwner,
    expectedRevision?: string,
): Promise<boolean> {
    const result = expectedRevision
        ? await db.prepare('DELETE FROM duo_configs WHERE id = ? AND revision_date = ?')
            .bind(configId(owner), expectedRevision).run()
        : await db.prepare('DELETE FROM duo_configs WHERE id = ?').bind(configId(owner)).run();
    // D1 includes cascaded login-state deletions in meta.changes.
    return result.meta.changes >= 1;
}

export async function createDuoLoginState(
    db: D1Database,
    value: Omit<DuoLoginState, 'nonce'> & { nonce?: string },
): Promise<{ state: string; nonce: string }> {
    if (value.providerType === 2 && value.organizationId !== null) throw new Error('Personal Duo state cannot bind an organization.');
    if (value.providerType === 6 && !value.organizationId) throw new Error('Organization Duo state requires an organization.');
    const state = generateDuoOpaqueValue();
    const nonce = value.nonce ?? generateDuoOpaqueValue();
    const now = new Date();
    const nowIso = now.toISOString();
    const [, inserted] = await db.batch([
        db.prepare('DELETE FROM duo_login_states WHERE expiration_date <= ?').bind(nowIso),
        db.prepare(`
            INSERT INTO duo_login_states
                (state_hash, user_id, provider_type, organization_id, config_id, config_revision,
                 nonce, redirect_uri, creation_date, expiration_date)
            SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            FROM duo_configs
            WHERE id = ? AND revision_date = ?
              AND ((? = 2 AND user_id = ? AND organization_id IS NULL) OR
                   (? = 6 AND organization_id = ? AND user_id IS NULL))
              AND (SELECT COUNT(*) FROM duo_login_states
                   WHERE user_id = ? AND consumed_date IS NULL AND expiration_date > ?) < ?
        `).bind(
            await sha256(state),
            value.userId,
            value.providerType,
            value.organizationId,
            value.configId,
            value.configRevision,
            nonce,
            value.redirectUri,
            nowIso,
            new Date(now.getTime() + LOGIN_STATE_LIFETIME_MS).toISOString(),
            value.configId,
            value.configRevision,
            value.providerType,
            value.userId,
            value.providerType,
            value.organizationId,
            value.userId,
            nowIso,
            MAX_ACTIVE_LOGIN_STATES_PER_USER,
        ),
    ]);
    if (inserted.meta.changes !== 1) throw new Error('Unable to persist Duo login request.');
    return { state, nonce };
}

export async function consumeDuoLoginState(
    db: D1Database,
    input: { state: string; userId: string; providerType: 2 | 6 },
): Promise<DuoLoginState | null> {
    if (!/^[A-Za-z0-9_-]{22,1024}$/.test(input.state)) return null;
    const now = new Date().toISOString();
    const row = await db.prepare(`
        UPDATE duo_login_states
        SET consumed_date = ?
        WHERE state_hash = ? AND user_id = ? AND provider_type = ?
          AND consumed_date IS NULL AND expiration_date > ?
        RETURNING user_id, provider_type, organization_id, config_id, config_revision,
                  nonce, redirect_uri
    `).bind(
        now,
        await sha256(input.state),
        input.userId,
        input.providerType,
        now,
    ).first<DuoLoginStateRow>();
    if (!row || (row.provider_type !== 2 && row.provider_type !== 6)) return null;
    return {
        userId: row.user_id,
        providerType: row.provider_type,
        organizationId: row.organization_id,
        configId: row.config_id,
        configRevision: row.config_revision,
        nonce: row.nonce,
        redirectUri: row.redirect_uri,
    };
}

export async function purgeExpiredDuoLoginStates(db: D1Database, now: Date = new Date()): Promise<number> {
    const result = await db.prepare('DELETE FROM duo_login_states WHERE expiration_date <= ?')
        .bind(now.toISOString()).run();
    return result.meta.changes;
}
