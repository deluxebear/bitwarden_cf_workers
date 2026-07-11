import { describe, expect, it } from 'vitest';
import { toApiDate } from './sync';

describe('sync response dates', () => {
    it('normalizes legacy SQLite policy timestamps for strict iOS decoding', () => {
        expect(toApiDate('2026-07-09 03:38:19Z')).toBe('2026-07-09T03:38:19.000Z');
    });

    it('preserves existing ISO-8601 timestamps and null values', () => {
        expect(toApiDate('2026-07-09T03:38:19.000Z')).toBe('2026-07-09T03:38:19.000Z');
        expect(toApiDate(null)).toBeNull();
    });
});
