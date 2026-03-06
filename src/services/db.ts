/**
 * D1 数据库工具函数
 * D1 (SQLite) 绑定变量上限约 100，批量 inArray 查询需分批执行
 */

import { inArray } from 'drizzle-orm';
import type { SQLiteSelect } from 'drizzle-orm/sqlite-core';
import type { SQLiteColumn } from 'drizzle-orm/sqlite-core';

/** D1 单条 SQL 最大绑定变量数，保守取 50 */
export const D1_BATCH_SIZE = 50;

/**
 * 分批执行 inArray 查询，避免超出 D1 绑定变量上限
 * @param db drizzle 实例
 * @param table 表对象
 * @param column inArray 的列
 * @param values 值数组
 * @param batchSize 每批大小，默认 50
 * @returns 所有批次结果合并后的数组
 */
export async function batchedInArrayQuery<T>(
    db: any,
    table: any,
    column: any,
    values: string[],
    batchSize = D1_BATCH_SIZE,
): Promise<T[]> {
    if (values.length === 0) return [];
    const results: T[] = [];
    for (let i = 0; i < values.length; i += batchSize) {
        const batch = values.slice(i, i + batchSize);
        const rows = await db.select().from(table).where(inArray(column, batch)).all();
        results.push(...rows);
    }
    return results;
}
