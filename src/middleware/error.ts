/**
 * Bitwarden Workers - 错误处理中间件
 * 对应原始项目的异常处理和 HTTP 错误响应
 */

import { Context, ErrorHandler as HonoErrorHandler, MiddlewareHandler } from 'hono';
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

export class ConflictError extends Error {
    constructor(message: string = 'Conflict') {
        super(message);
        this.name = 'ConflictError';
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

function buildErrorResponse(c: Context, err: Error) {
    const body = { message: '', validationErrors: null, exceptionMessage: null, exceptionStackTrace: null, innerExceptionMessage: null, object: 'error' };

    if (err instanceof HTTPException) {
        body.message = err.message;
        return c.json(body, err.status);
    }
    if (err instanceof BadRequestError) {
        body.message = err.message;
        return c.json(body, 400);
    }
    if (err instanceof ConflictError) {
        body.message = err.message;
        return c.json(body, 409);
    }
    if (err instanceof NotFoundError) {
        body.message = err.message;
        return c.json(body, 404);
    }
    if (err instanceof UnauthorizedError) {
        body.message = err.message;
        return c.json(body, 401);
    }

    console.error('Unhandled error:', err);
    body.message = 'An error has occurred.';
    return c.json(body, 500);
}

/**
 * 全局错误处理中间件（try-catch 模式，兜底用）
 */
export const errorHandler: MiddlewareHandler = async (c, next) => {
    try {
        await next();
    } catch (err) {
        return buildErrorResponse(c, err as Error);
    }
};

/**
 * Hono app.onError 全局错误处理钩子。
 * 子路由 (app.route) 抛出的异常可能绕过中间件的 try-catch，
 * 必须通过 onError 捕获，否则 Hono 会返回默认的 "Internal Server Error" 纯文本 500。
 */
export const globalErrorHandler: HonoErrorHandler = (err, c) => {
    return buildErrorResponse(c, err);
};
