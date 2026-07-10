import { describe, expect, it, vi } from 'vitest';
import { putObjectThenPersist, removeMetadataThenDeleteObject } from '../src/services/storage-compensation';

describe('storage compensation', () => {
    it('removes an uploaded object when metadata persistence fails', async () => {
        const error = new Error('D1 update failed');
        const bucket = { put: vi.fn().mockResolvedValue(undefined), delete: vi.fn().mockResolvedValue(undefined) };
        await expect(putObjectThenPersist(bucket, 'cipher/file', 'encrypted', undefined,
            vi.fn().mockRejectedValue(error))).rejects.toBe(error);
        expect(bucket.delete).toHaveBeenCalledWith('cipher/file');
    });

    it('does not persist metadata when object upload fails', async () => {
        const error = new Error('R2 put failed');
        const persist = vi.fn();
        const bucket = { put: vi.fn().mockRejectedValue(error), delete: vi.fn() };
        await expect(putObjectThenPersist(bucket, 'send/file', 'encrypted', undefined, persist)).rejects.toBe(error);
        expect(persist).not.toHaveBeenCalled();
        expect(bucket.delete).not.toHaveBeenCalled();
    });

    it('restores metadata when object deletion fails', async () => {
        const error = new Error('R2 delete failed');
        const remove = vi.fn().mockResolvedValue(undefined);
        const restore = vi.fn().mockResolvedValue(undefined);
        const bucket = { delete: vi.fn().mockRejectedValue(error) };
        await expect(removeMetadataThenDeleteObject(bucket, 'send/file', remove, restore)).rejects.toBe(error);
        expect(remove).toHaveBeenCalledOnce();
        expect(restore).toHaveBeenCalledOnce();
    });

    it('does not touch R2 when metadata removal fails', async () => {
        const error = new Error('D1 delete failed');
        const bucket = { delete: vi.fn() };
        await expect(removeMetadataThenDeleteObject(bucket, 'send/file',
            vi.fn().mockRejectedValue(error), vi.fn())).rejects.toBe(error);
        expect(bucket.delete).not.toHaveBeenCalled();
    });
});
