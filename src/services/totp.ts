/**
 * Bitwarden Workers - TOTP (Time-based One-time Password) 服务
 * 用于两步验证 (Authenticator) 的密钥生成与验证
 */

import * as OTPAuth from 'otpauth';

/**
 * 生成 20 字节随机密钥，并返回 Base32 编码字符串
 */
export function generateAuthenticatorKey(): string {
    const secret = new OTPAuth.Secret({ size: 20 });
    return secret.base32;
}

/**
 * 验证 6 位 TOTP code
 * 默认宽容度 (window): 1 (前后各 30 秒，总共 90 秒的有效窗口)
 */
export function verifyAuthenticatorCode(key: string, code: string): boolean {
    try {
        const totp = new OTPAuth.TOTP({
            issuer: 'Bitwarden',
            label: 'Bitwarden',
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: OTPAuth.Secret.fromBase32(key),
        });

        const delta = totp.validate({ token: code, window: 1 });
        return delta !== null;
    } catch (e) {
        return false;
    }
}
