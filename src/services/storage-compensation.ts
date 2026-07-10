type ObjectBody = ReadableStream | ArrayBuffer | ArrayBufferView | string | Blob;

interface ObjectBucket {
    put(key: string, value: ObjectBody, options?: R2PutOptions): Promise<unknown>;
    delete(key: string): Promise<void>;
}

/** R2 与 D1 无法组成事务；元数据落库失败时尽力回删新对象。 */
export async function putObjectThenPersist(
    bucket: ObjectBucket,
    key: string,
    value: ObjectBody,
    options: R2PutOptions | undefined,
    persist: () => Promise<void>,
): Promise<void> {
    await bucket.put(key, value, options);
    try {
        await persist();
    } catch (error) {
        try {
            await bucket.delete(key);
        } catch {
            // 保留原始 D1 错误；补偿失败的孤儿对象交由后续清理任务处理。
        }
        throw error;
    }
}

/** 先移除元数据；R2 删除失败时恢复元数据，避免客户端看到半删除状态。 */
export async function removeMetadataThenDeleteObject(
    bucket: Pick<ObjectBucket, 'delete'>,
    key: string,
    removeMetadata: () => Promise<void>,
    restoreMetadata: () => Promise<void>,
): Promise<void> {
    await removeMetadata();
    try {
        await bucket.delete(key);
    } catch (error) {
        try {
            await restoreMetadata();
        } catch {
            // 保留触发补偿的 R2 错误，避免掩盖请求失败的首要原因。
        }
        throw error;
    }
}
