import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { debugMiddleware } from './debug';
import { errorHandler, globalErrorHandler } from './error';
import type { Bindings, Variables } from '../types';

function createApp() {
    const app = new Hono<{ Bindings: Bindings; Variables: Variables }>();
    app.onError(globalErrorHandler);
    app.use('*', debugMiddleware);
    app.use('*', errorHandler);
    app.get('/users/:id', (c) => c.json({ ok: true }));
    app.get('/failure', () => { throw new Error('secret token@example.com'); });
    return app;
}

afterEach(() => vi.restoreAllMocks());

describe('observability middleware', () => {
    it('emits one sanitized completion log and returns the request id', async () => {
        const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
        const response = await createApp().request('/users/private-user-id?token=private-token', {
            headers: { Authorization: 'Bearer private-token', 'X-Request-Id': 'caller_request_123' },
        });

        expect(response.headers.get('X-Request-Id')).toBe('caller_request_123');
        expect(log).toHaveBeenCalledTimes(1);
        const entry = JSON.parse(String(log.mock.calls[0][0]));
        expect(entry).toMatchObject({
            requestId: 'caller_request_123', method: 'GET', route: '/users/:id', status: 200, errorCode: null,
        });
        expect(String(log.mock.calls[0][0])).not.toContain('private');
    });

    it('correlates a sanitized 500 error with its completion log', async () => {
        const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);
        const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
        const response = await createApp().request('/failure', {
            headers: { 'X-Request-Id': 'failure_request_123' },
        });

        expect(response.status).toBe(500);
        expect(response.headers.get('X-Worker-Error-Code')).toBeNull();
        expect(error).toHaveBeenCalledTimes(1);
        expect(log).toHaveBeenCalledTimes(1);
        expect(String(error.mock.calls[0][0])).toContain('failure_request_123');
        expect(String(error.mock.calls[0][0])).not.toContain('token@example.com');
        expect(JSON.parse(String(log.mock.calls[0][0]))).toMatchObject({
            requestId: 'failure_request_123', status: 500, errorCode: 'INTERNAL_ERROR',
        });
    });
});
