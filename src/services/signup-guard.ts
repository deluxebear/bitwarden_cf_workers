/**
 * 注册控制守卫
 * 根据 SIGNUPS_ALLOWED 环境变量和系统状态判断是否允许新用户注册。
 *
 * SIGNUPS_ALLOWED 取值：
 *   "true"  - 始终允许
 *   "false" - 始终禁止（仅邀请注册有效）
 *   "auto"  - 系统无用户时允许首个注册，之后自动关闭（默认）
 *
 * 邀请注册（organization_users 中存在该邮箱的待接受邀请）不受此限制。
 */

import { sql } from 'drizzle-orm';
import { users } from '../db/schema';
import type { Bindings } from '../types';

export async function isSignupAllowed(
    env: Bindings,
    db: ReturnType<typeof import('drizzle-orm/d1').drizzle>,
    email: string,
): Promise<boolean> {
    const mode = (env.SIGNUPS_ALLOWED ?? 'auto').toLowerCase().trim();

    if (mode === 'true') return true;

    // "false" 模式下仍需检查是否有组织邀请
    if (mode === 'false') {
        return await hasOrgInvite(db, email);
    }

    // "auto" 模式：系统中无用户时允许，有用户后仅邀请可注册
    const result = await db
        .select({ count: sql<number>`count(*)` })
        .from(users)
        .get();
    const userCount = result?.count ?? 0;

    if (userCount === 0) return true;

    return await hasOrgInvite(db, email);
}

async function hasOrgInvite(
    db: ReturnType<typeof import('drizzle-orm/d1').drizzle>,
    email: string,
): Promise<boolean> {
    try {
        const row = await db.all(
            sql`SELECT 1 FROM organization_users WHERE email = ${email.toLowerCase().trim()} AND status = 0 LIMIT 1`,
        );
        return row.length > 0;
    } catch {
        return false;
    }
}
