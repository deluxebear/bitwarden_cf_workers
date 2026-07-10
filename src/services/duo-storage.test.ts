import { describe, expect, it } from 'vitest';

import { decryptDuoClientSecret, encryptDuoClientSecret } from './duo-storage';

function randomKey(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return btoa(String.fromCharCode(...bytes));
}

describe('Duo configuration encryption', () => {
    it('encrypts secrets with AES-GCM and binds ciphertext to its configuration id', async () => {
        const key = randomKey();
        const secret = '0123456789012345678901234567890123456789';
        const encrypted = await encryptDuoClientSecret(secret, key, 'user:user-1');

        expect(encrypted.ciphertext).not.toContain(secret);
        expect(encrypted.iv).toMatch(/^[A-Za-z0-9_-]+$/);
        await expect(decryptDuoClientSecret(encrypted, key, 'user:user-1')).resolves.toBe(secret);
        await expect(decryptDuoClientSecret(encrypted, key, 'user:user-2')).rejects.toThrow('decrypt');
    });

    it('rejects invalid key lengths and tampered ciphertext', async () => {
        const secret = '0123456789012345678901234567890123456789';
        await expect(encryptDuoClientSecret(secret, btoa('short'), 'user:user-1')).rejects.toThrow('32 bytes');

        const key = randomKey();
        const encrypted = await encryptDuoClientSecret(secret, key, 'user:user-1');
        const first = encrypted.ciphertext[0] === 'A' ? 'B' : 'A';
        await expect(decryptDuoClientSecret({
            ...encrypted,
            ciphertext: `${first}${encrypted.ciphertext.slice(1)}`,
        }, key, 'user:user-1')).rejects.toThrow('decrypt');
    });
});
