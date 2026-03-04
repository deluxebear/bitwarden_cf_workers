/**
 * Bitwarden Workers - 错误处理中间件
 * 对应原始项目的异常处理和 HTTP 错误响应
 */

import { Context, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';

/**
 * 自定义业务异常
 */
export class BadRequestError extends Error {
    constructor(message: string = 'Bad request') {
        super(message);
        this.name = 'BadRequestError';
    }
}

export class NotFoundError extends Error {
    constructor(message: string = 'Not found') {
        super(message);
        this.name = 'NotFoundError';
    }
}

export class UnauthorizedError extends Error {
    constructor(message: string = 'Unauthorized') {
        super(message);
        this.name = 'UnauthorizedError';
    }
}

/**
 * 全局错误处理中间件
 */
export const errorHandler: MiddlewareHandler = async (c, next) => {
    try {
        await next();
    } catch (err) {
        if (err instanceof HTTPException) {
            return c.json(
                { message: err.message, validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' },
                err.status
            );
        }

        if (err instanceof BadRequestError) {
            return c.json(
                { message: err.message, validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' },
                400
            );
        }

        if (err instanceof NotFoundError) {
            return c.json(
                { message: err.message, validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' },
                404
            );
        }

        if (err instanceof UnauthorizedError) {
            return c.json(
                { message: err.message, validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' },
                401
            );
        }

        console.error('Unhandled error:', err);
        return c.json(
            { message: 'An error has occurred.', validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' },
            500
        );
    }
};
