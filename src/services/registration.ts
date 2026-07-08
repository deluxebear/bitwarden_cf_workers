type KdfRequest = {
    kdfType?: number;
    iterations?: number;
    memory?: number | null;
    parallelism?: number | null;
};

type MasterPasswordAuthenticationRequest = {
    masterPasswordAuthenticationHash?: string;
    masterKeyAuthenticationHash?: string;
    salt?: string;
    kdf?: KdfRequest;
};

type MasterPasswordUnlockRequest = {
    masterKeyWrappedUserKey?: string;
    masterKeyEncryptedUserKey?: string;
    salt?: string;
    kdf?: KdfRequest;
};

type AsymmetricKeysRequest = {
    publicKey?: string;
    encryptedPrivateKey?: string;
};

export type NormalizedRegistrationRequest = {
    email?: string;
    name?: string | null;
    masterPasswordHash?: string;
    masterPasswordHint?: string | null;
    key?: string | null;
    publicKey?: string | null;
    privateKey?: string | null;
    kdf: number;
    kdfIterations: number;
    kdfMemory: number | null;
    kdfParallelism: number | null;
};

export function normalizeRegistrationRequest(body: any): NormalizedRegistrationRequest {
    const authenticationData = (body?.masterPasswordAuthentication ?? body?.authenticationData) as MasterPasswordAuthenticationRequest | undefined;
    const unlockData = (body?.masterPasswordUnlock ?? body?.unlockData) as MasterPasswordUnlockRequest | undefined;
    const kdf = authenticationData?.kdf ?? unlockData?.kdf;
    const kdfType = typeof body?.kdfType === 'number'
        ? body.kdfType
        : typeof body?.kdf === 'number'
            ? body.kdf
            : kdf?.kdfType ?? 0;
    const asymmetricKeys = (body?.userAsymmetricKeys ?? body?.keys) as AsymmetricKeysRequest | undefined;

    return {
        email: body?.email,
        name: body?.name ?? null,
        masterPasswordHash: body?.masterPasswordHash
            ?? body?.newMasterPasswordHash
            ?? authenticationData?.masterPasswordAuthenticationHash
            ?? authenticationData?.masterKeyAuthenticationHash,
        masterPasswordHint: body?.masterPasswordHint ?? body?.master_password_hint ?? null,
        key: body?.userSymmetricKey
            ?? body?.key
            ?? unlockData?.masterKeyWrappedUserKey
            ?? unlockData?.masterKeyEncryptedUserKey
            ?? null,
        publicKey: asymmetricKeys?.publicKey ?? null,
        privateKey: asymmetricKeys?.encryptedPrivateKey ?? null,
        kdf: kdfType,
        kdfIterations: body?.kdfIterations ?? kdf?.iterations ?? 600000,
        kdfMemory: body?.kdfMemory ?? kdf?.memory ?? null,
        kdfParallelism: body?.kdfParallelism ?? kdf?.parallelism ?? null,
    };
}
