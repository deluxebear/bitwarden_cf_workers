import { describe, expect, it } from 'vitest';
import {
    EmergencyAccessDomainError,
    EmergencyAccessStatus,
    EmergencyAccessType,
    acceptEmergencyAccess,
    approveEmergencyAccess,
    approveExpiredEmergencyAccess,
    assertEmergencyAccessCanBeUsed,
    assertEmergencyAccessParticipant,
    confirmEmergencyAccess,
    createEmergencyAccessInvite,
    initiateEmergencyAccess,
    rejectEmergencyAccess,
    revokeEmergencyAccess,
} from './emergency-access';

const start = new Date('2026-01-01T00:00:00.000Z');

function invite(waitTimeDays = 2) {
    return createEmergencyAccessInvite({
        id: 'ea-1', grantorId: 'grantor', grantorEmail: 'grantor@example.com',
        granteeEmail: 'GRANTEE@example.com', type: EmergencyAccessType.View,
        waitTimeDays, now: start,
    });
}

function confirmed(waitTimeDays = 2) {
    const accepted = acceptEmergencyAccess(invite(waitTimeDays),
        { userId: 'grantee', email: 'grantee@example.com' }, new Date('2026-01-01T01:00:00Z'));
    return confirmEmergencyAccess(accepted, 'grantor', 'client-encrypted-key', new Date('2026-01-01T02:00:00Z'));
}

describe('emergency access domain', () => {
    it('creates a normalized invitation without plaintext key material', () => {
        const record = invite();
        expect(record).toMatchObject({ email: 'grantee@example.com', granteeId: null,
            keyEncrypted: null, status: EmergencyAccessStatus.Invited });
        expect(() => createEmergencyAccessInvite({
            id: 'ea-2', grantorId: 'grantor', grantorEmail: 'same@example.com',
            granteeEmail: 'SAME@example.com', type: EmergencyAccessType.View, waitTimeDays: 1, now: start,
        })).toThrow(EmergencyAccessDomainError);
    });

    it('follows invited -> accepted -> confirmed and keeps repeated calls idempotent', () => {
        const invited = invite();
        const accepted = acceptEmergencyAccess(invited,
            { userId: 'grantee', email: 'grantee@example.com' }, new Date('2026-01-01T01:00:00Z'));
        expect(accepted).toMatchObject({ status: EmergencyAccessStatus.Accepted, granteeId: 'grantee', email: null });
        expect(acceptEmergencyAccess(accepted,
            { userId: 'grantee', email: 'grantee@example.com' }, new Date('2026-01-01T01:01:00Z'))).toBe(accepted);

        const result = confirmEmergencyAccess(accepted, 'grantor', 'ciphertext', new Date('2026-01-01T02:00:00Z'));
        expect(result).toMatchObject({ status: EmergencyAccessStatus.Confirmed, keyEncrypted: 'ciphertext' });
        expect(confirmEmergencyAccess(result, 'grantor', 'ciphertext', new Date('2026-01-01T03:00:00Z'))).toBe(result);
    });

    it('rejects an invitation accepted by another email or the grantor', () => {
        expect(() => acceptEmergencyAccess(invite(),
            { userId: 'attacker', email: 'attacker@example.com' }, start)).toThrowError(/email/i);
        expect(() => acceptEmergencyAccess(invite(),
            { userId: 'grantor', email: 'grantee@example.com' }, start)).toThrow(EmergencyAccessDomainError);
    });

    it('enforces actor roles and legal transition order', () => {
        expect(() => confirmEmergencyAccess(invite(), 'grantor', 'ciphertext', start)).toThrowError(/transition/i);
        expect(() => confirmEmergencyAccess(
            acceptEmergencyAccess(invite(), { userId: 'grantee', email: 'grantee@example.com' }, start),
            'grantee', 'ciphertext', start)).toThrow(EmergencyAccessDomainError);
        expect(() => initiateEmergencyAccess(confirmed(), 'grantor', start)).toThrow(EmergencyAccessDomainError);
    });

    it('starts recovery idempotently and advances revision', () => {
        const before = confirmed();
        const initiated = initiateEmergencyAccess(before, 'grantee', new Date('2026-01-02T00:00:00Z'));
        expect(initiated).toMatchObject({ status: EmergencyAccessStatus.RecoveryInitiated,
            recoveryInitiatedDate: '2026-01-02T00:00:00.000Z' });
        expect(Date.parse(initiated.revisionDate)).toBeGreaterThan(Date.parse(before.revisionDate));
        expect(initiateEmergencyAccess(initiated, 'grantee', new Date('2026-01-03T00:00:00Z'))).toBe(initiated);
    });

    it('allows the grantor to approve immediately while still enforcing the requested access type', () => {
        const initiated = initiateEmergencyAccess(confirmed(2), 'grantee', new Date('2026-01-02T00:00:00Z'));
        const approved = approveEmergencyAccess(initiated, 'grantor', new Date('2026-01-02T01:00:00Z'));
        expect(approved.status).toBe(EmergencyAccessStatus.RecoveryApproved);
        expect(() => assertEmergencyAccessCanBeUsed(approved, 'grantee', EmergencyAccessType.Takeover,
            new Date('2026-01-02T01:00:00Z'))).toThrow(EmergencyAccessDomainError);
        expect(() => assertEmergencyAccessCanBeUsed(approved, 'grantee', EmergencyAccessType.View,
            new Date('2026-01-02T01:00:00Z'))).not.toThrow();
        expect(rejectEmergencyAccess(approved, 'grantor', new Date('2026-01-02T02:00:00Z')))
            .toMatchObject({ status: EmergencyAccessStatus.Confirmed });
    });

    it('supports internal timeout approval only after expiry', () => {
        const initiated = initiateEmergencyAccess(confirmed(1), 'grantee', new Date('2026-01-02T00:00:00Z'));
        expect(() => approveExpiredEmergencyAccess(initiated, new Date('2026-01-02T12:00:00Z')))
            .toThrowError(/waiting period/i);
        expect(approveExpiredEmergencyAccess(initiated, new Date('2026-01-03T00:00:00Z')).status)
            .toBe(EmergencyAccessStatus.RecoveryApproved);
    });

    it('rejects a recovery back to confirmed and makes retry idempotent', () => {
        const initiated = initiateEmergencyAccess(confirmed(0), 'grantee', new Date('2026-01-02T00:00:00Z'));
        const rejected = rejectEmergencyAccess(initiated, 'grantor', new Date('2026-01-02T01:00:00Z'));
        expect(rejected).toMatchObject({ status: EmergencyAccessStatus.Confirmed,
            recoveryRejectedDate: '2026-01-02T01:00:00.000Z' });
        expect(rejectEmergencyAccess(rejected, 'grantor', new Date('2026-01-02T02:00:00Z'))).toBe(rejected);
    });

    it('allows either participant to revoke and denies all subsequent access', () => {
        const record = confirmed();
        const revoked = revokeEmergencyAccess(record, 'grantee', new Date('2026-01-02T00:00:00Z'));
        expect(revoked).toMatchObject({ revokedByUserId: 'grantee', revokedDate: '2026-01-02T00:00:00.000Z' });
        expect(revokeEmergencyAccess(revoked, 'grantee', new Date('2026-01-03T00:00:00Z'))).toBe(revoked);
        expect(() => assertEmergencyAccessParticipant(revoked, 'grantor')).toThrowError(/revoked/i);
    });

    it('denies non-participants without revealing record state', () => {
        expect(() => assertEmergencyAccessParticipant(confirmed(), 'attacker')).toThrow(EmergencyAccessDomainError);
        expect(() => revokeEmergencyAccess(confirmed(), 'attacker', start)).toThrow(EmergencyAccessDomainError);
    });
});
