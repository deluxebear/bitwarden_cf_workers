const FAILURE_COUNT_BEFORE_BACKOFF = 3;
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 5 * 60 * 1_000;

/**
 * 登录失败后的短期指数退避。前三次失败不延迟，之后从 1 秒开始翻倍，最多 5 分钟。
 * 仅使用 users 表的现有字段，避免为兼容性加固引入数据库迁移。
 */
export function getLoginBackoffMs(failedLoginCount: number): number {
    if (!Number.isFinite(failedLoginCount) || failedLoginCount < FAILURE_COUNT_BEFORE_BACKOFF) {
        return 0;
    }

    const exponent = Math.min(
        Math.max(Math.trunc(failedLoginCount) - FAILURE_COUNT_BEFORE_BACKOFF, 0),
        20,
    );
    return Math.min(INITIAL_BACKOFF_MS * 2 ** exponent, MAX_BACKOFF_MS);
}

export function isLoginBackoffActive(
    failedLoginCount: number,
    lastFailedLoginDate: string | null | undefined,
    nowMs: number = Date.now(),
): boolean {
    const backoffMs = getLoginBackoffMs(failedLoginCount);
    if (backoffMs === 0 || !lastFailedLoginDate) return false;

    const lastFailureMs = Date.parse(lastFailedLoginDate);
    if (!Number.isFinite(lastFailureMs)) return false;

    return nowMs < lastFailureMs + backoffMs;
}
