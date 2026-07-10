import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('identity token replay protections', () => {
    const source = readFileSync('src/routes/identity.ts', 'utf8');

    it('atomically consumes an Auth Request before issuing tokens', () => {
        const consume = source.indexOf('Auth Request 必须在签发任何 token 前原子消费');
        const sign = source.indexOf('// 签发 access token');
        expect(consume).toBeGreaterThan(0);
        expect(consume).toBeLessThan(sign);
        expect(source).toContain('isNull(authRequests.authenticationDate)');
        expect(source).toContain('consumed.meta.changes !== 1');
    });

    it('atomically consumes the old refresh token during rotation', () => {
        expect(source).toContain('并发 rotation 只能有一个请求成功');
        expect(source).toContain('eq(refreshTokens.tokenHash, tokenHash)');
    });

    it('increments failures atomically and clears them only after all authentication checks', () => {
        expect(source).toContain('failedLoginCount: sql`${users.failedLoginCount} + 1`');
        const clear = source.indexOf('只有密码、二步验证和新设备验证全部成功后才清零');
        const twoFactor = source.indexOf('// ================= 检查二步验证');
        expect(clear).toBeGreaterThan(twoFactor);
    });

    it('checks account backoff before branching into AuthRequest or password authentication', () => {
        const backoff = source.indexOf('// 所有密码登录路径（包括 approved AuthRequest）共享账户退避');
        const authRequest = source.indexOf('// Auth Request (设备登录) 流程');
        expect(backoff).toBeGreaterThan(0);
        expect(backoff).toBeLessThan(authRequest);
    });

    it('uses the shared organization-aware premium entitlement before filtering Duo', () => {
        expect(source).toContain('await canAccessPremium(c.env.DB, user, c.env.GLOBAL_PREMIUM)');
        expect(source).not.toContain("const premium = user.premium || String(c.env.GLOBAL_PREMIUM");
    });
});
