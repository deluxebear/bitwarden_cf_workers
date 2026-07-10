export enum EmergencyAccessStatus {
    Invited = 0,
    Accepted = 1,
    Confirmed = 2,
    RecoveryInitiated = 3,
    RecoveryApproved = 4,
}

export enum EmergencyAccessType {
    View = 0,
    Takeover = 1,
}

export interface EmergencyAccessRecord {
    id: string;
    grantorId: string;
    granteeId: string | null;
    email: string | null;
    keyEncrypted: string | null;
    type: EmergencyAccessType;
    status: EmergencyAccessStatus;
    waitTimeDays: number;
    recoveryInitiatedDate: string | null;
    recoveryRejectedDate: string | null;
    lastNotificationDate: string | null;
    revokedDate: string | null;
    revokedByUserId: string | null;
    creationDate: string;
    revisionDate: string;
}

export class EmergencyAccessDomainError extends Error {
    constructor(
        message: string,
        readonly code: 'invalid' | 'forbidden' | 'invalid_transition' | 'waiting_period',
    ) {
        super(message);
        this.name = 'EmergencyAccessDomainError';
    }
}

const DAY_MS = 24 * 60 * 60 * 1000;

function iso(date: Date): string {
    if (!Number.isFinite(date.getTime())) throw new EmergencyAccessDomainError('Invalid server time.', 'invalid');
    return date.toISOString();
}

function revised(record: EmergencyAccessRecord, now: Date): string {
    const candidate = now.getTime();
    const previous = Date.parse(record.revisionDate);
    return new Date(Number.isFinite(previous) && candidate <= previous ? previous + 1 : candidate).toISOString();
}

function assertActive(record: EmergencyAccessRecord): void {
    if (record.revokedDate) throw new EmergencyAccessDomainError('Emergency Access has been revoked.', 'invalid');
}

function assertGrantor(record: EmergencyAccessRecord, actorUserId: string): void {
    assertActive(record);
    if (record.grantorId !== actorUserId) throw new EmergencyAccessDomainError('Emergency Access not valid.', 'forbidden');
}

function assertGrantee(record: EmergencyAccessRecord, actorUserId: string): void {
    assertActive(record);
    if (record.granteeId !== actorUserId) throw new EmergencyAccessDomainError('Emergency Access not valid.', 'forbidden');
}

function assertStatus(record: EmergencyAccessRecord, expected: EmergencyAccessStatus): void {
    if (record.status !== expected) throw new EmergencyAccessDomainError('Emergency Access state transition is not valid.', 'invalid_transition');
}

export function createEmergencyAccessInvite(input: {
    id: string;
    grantorId: string;
    grantorEmail: string;
    granteeEmail: string;
    type: EmergencyAccessType;
    waitTimeDays: number;
    now: Date;
}): EmergencyAccessRecord {
    const email = input.granteeEmail.trim().toLowerCase();
    if (!email || email === input.grantorEmail.trim().toLowerCase()) {
        throw new EmergencyAccessDomainError('You cannot invite yourself as an emergency access contact.', 'invalid');
    }
    if (!Number.isInteger(input.waitTimeDays) || input.waitTimeDays < 0 || input.waitTimeDays > 365) {
        throw new EmergencyAccessDomainError('Wait time must be between 0 and 365 days.', 'invalid');
    }
    if (input.type !== EmergencyAccessType.View && input.type !== EmergencyAccessType.Takeover) {
        throw new EmergencyAccessDomainError('Emergency Access type is not valid.', 'invalid');
    }
    const now = iso(input.now);
    return {
        id: input.id,
        grantorId: input.grantorId,
        granteeId: null,
        email,
        keyEncrypted: null,
        type: input.type,
        status: EmergencyAccessStatus.Invited,
        waitTimeDays: input.waitTimeDays,
        recoveryInitiatedDate: null,
        recoveryRejectedDate: null,
        lastNotificationDate: null,
        revokedDate: null,
        revokedByUserId: null,
        creationDate: now,
        revisionDate: now,
    };
}

export function assertEmergencyAccessParticipant(record: EmergencyAccessRecord, actorUserId: string): void {
    assertActive(record);
    if (record.grantorId !== actorUserId && record.granteeId !== actorUserId) {
        throw new EmergencyAccessDomainError('Emergency Access not valid.', 'forbidden');
    }
}

export function acceptEmergencyAccess(
    record: EmergencyAccessRecord,
    actor: { userId: string; email: string },
    now: Date,
): EmergencyAccessRecord {
    assertActive(record);
    if (record.status === EmergencyAccessStatus.Accepted && record.granteeId === actor.userId) return record;
    assertStatus(record, EmergencyAccessStatus.Invited);
    if (record.grantorId === actor.userId || record.email?.toLowerCase() !== actor.email.trim().toLowerCase()) {
        throw new EmergencyAccessDomainError('User email does not match invite.', 'forbidden');
    }
    return { ...record, granteeId: actor.userId, email: null, status: EmergencyAccessStatus.Accepted,
        revisionDate: revised(record, now) };
}

export function confirmEmergencyAccess(
    record: EmergencyAccessRecord,
    actorUserId: string,
    keyEncrypted: string,
    now: Date,
): EmergencyAccessRecord {
    assertGrantor(record, actorUserId);
    if (record.status === EmergencyAccessStatus.Confirmed && record.keyEncrypted === keyEncrypted) return record;
    assertStatus(record, EmergencyAccessStatus.Accepted);
    if (!keyEncrypted.trim()) throw new EmergencyAccessDomainError('Encrypted key is required.', 'invalid');
    return { ...record, keyEncrypted, status: EmergencyAccessStatus.Confirmed, revisionDate: revised(record, now) };
}

export function initiateEmergencyAccess(
    record: EmergencyAccessRecord,
    actorUserId: string,
    now: Date,
): EmergencyAccessRecord {
    assertGrantee(record, actorUserId);
    if (record.status === EmergencyAccessStatus.RecoveryInitiated) return record;
    assertStatus(record, EmergencyAccessStatus.Confirmed);
    const timestamp = iso(now);
    return { ...record, status: EmergencyAccessStatus.RecoveryInitiated, recoveryInitiatedDate: timestamp,
        recoveryRejectedDate: null, lastNotificationDate: timestamp, revisionDate: revised(record, now) };
}

export function recoveryAvailableAt(record: EmergencyAccessRecord): Date {
    if (!record.recoveryInitiatedDate) {
        throw new EmergencyAccessDomainError('Recovery has not been initiated.', 'invalid_transition');
    }
    const initiated = Date.parse(record.recoveryInitiatedDate);
    if (!Number.isFinite(initiated)) throw new EmergencyAccessDomainError('Recovery initiation date is invalid.', 'invalid');
    return new Date(initiated + record.waitTimeDays * DAY_MS);
}

function assertWaitElapsed(record: EmergencyAccessRecord, now: Date): void {
    if (now.getTime() < recoveryAvailableAt(record).getTime()) {
        throw new EmergencyAccessDomainError('Emergency Access waiting period has not elapsed.', 'waiting_period');
    }
}

export function approveEmergencyAccess(
    record: EmergencyAccessRecord,
    actorUserId: string,
    now: Date,
): EmergencyAccessRecord {
    assertGrantor(record, actorUserId);
    if (record.status === EmergencyAccessStatus.RecoveryApproved) return record;
    assertStatus(record, EmergencyAccessStatus.RecoveryInitiated);
    return { ...record, status: EmergencyAccessStatus.RecoveryApproved, revisionDate: revised(record, now) };
}

export function approveExpiredEmergencyAccess(record: EmergencyAccessRecord, now: Date): EmergencyAccessRecord {
    assertActive(record);
    if (record.status === EmergencyAccessStatus.RecoveryApproved) return record;
    assertStatus(record, EmergencyAccessStatus.RecoveryInitiated);
    assertWaitElapsed(record, now);
    return { ...record, status: EmergencyAccessStatus.RecoveryApproved, revisionDate: revised(record, now) };
}

export function rejectEmergencyAccess(
    record: EmergencyAccessRecord,
    actorUserId: string,
    now: Date,
): EmergencyAccessRecord {
    assertGrantor(record, actorUserId);
    if (record.status === EmergencyAccessStatus.Confirmed && record.recoveryRejectedDate) return record;
    if (record.status !== EmergencyAccessStatus.RecoveryInitiated
        && record.status !== EmergencyAccessStatus.RecoveryApproved) {
        throw new EmergencyAccessDomainError('Emergency Access state transition is not valid.', 'invalid_transition');
    }
    return { ...record, status: EmergencyAccessStatus.Confirmed, recoveryRejectedDate: iso(now),
        revisionDate: revised(record, now) };
}

export function revokeEmergencyAccess(
    record: EmergencyAccessRecord,
    actorUserId: string,
    now: Date,
): EmergencyAccessRecord {
    if (record.revokedDate) {
        if (record.grantorId !== actorUserId && record.granteeId !== actorUserId) {
            throw new EmergencyAccessDomainError('Emergency Access not valid.', 'forbidden');
        }
        return record;
    }
    assertEmergencyAccessParticipant(record, actorUserId);
    return { ...record, revokedDate: iso(now), revokedByUserId: actorUserId, revisionDate: revised(record, now) };
}

export function assertEmergencyAccessCanBeUsed(
    record: EmergencyAccessRecord,
    actorUserId: string,
    requestedType: EmergencyAccessType,
    _now: Date,
): void {
    assertGrantee(record, actorUserId);
    if (record.status !== EmergencyAccessStatus.RecoveryApproved || record.type !== requestedType) {
        throw new EmergencyAccessDomainError('Emergency Access not valid.', 'forbidden');
    }
}
