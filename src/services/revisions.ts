import { eq } from 'drizzle-orm';
import { ciphers, organizations, users } from '../db/schema';

type D1Db = ReturnType<typeof import('drizzle-orm/d1').drizzle>;

export async function touchUser(db: D1Db, userId: string, date = new Date().toISOString()): Promise<string> {
    await db.update(users).set({
        revisionDate: date,
        accountRevisionDate: date,
    }).where(eq(users.id, userId));
    return date;
}

export async function touchCipher(db: D1Db, cipherId: string, date = new Date().toISOString()): Promise<string> {
    await db.update(ciphers).set({ revisionDate: date }).where(eq(ciphers.id, cipherId));
    return date;
}

export async function touchOrganization(db: D1Db, organizationId: string, date = new Date().toISOString()): Promise<string> {
    await db.update(organizations).set({ revisionDate: date }).where(eq(organizations.id, organizationId));
    return date;
}
