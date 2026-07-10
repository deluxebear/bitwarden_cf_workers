/** 统一 Premium 权限判断，避免配置与登录链路对组织授权产生分歧。 */
export async function canAccessPremium(
    db: D1Database,
    user: { id: string; premium: boolean },
    globalPremium: unknown,
): Promise<boolean> {
    if (user.premium || String(globalPremium ?? '').toLowerCase() === 'true') return true;
    const entitlement = await db.prepare(`
        SELECT 1 AS entitled
        FROM organization_users ou
        INNER JOIN organizations o ON o.id = ou.organization_id
        WHERE ou.user_id = ? AND o.enabled = 1
          AND COALESCE(o.users_get_premium, 1) = 1
        LIMIT 1
    `).bind(user.id).first<{ entitled: number }>();
    return entitlement?.entitled === 1;
}
