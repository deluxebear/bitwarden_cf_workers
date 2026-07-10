/**
 * Bitwarden Workers - 错误处理中间件
 * 对应原始项目的异常处理和 HTTP 错误响应
 */

import { Context, ErrorHandler as HonoErrorHandler, MiddlewareHandler } from 'hono';
import { HTTPException } from 'hono/http-exception';

/** 仅供中间件之间传递错误分类；debugMiddleware 会在响应发出前删除。 */
export const INTERNAL_ERROR_CODE_HEADER = 'X-Worker-Error-Code';

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
        c.header(INTERNAL_ERROR_CODE_HEADER, `HTTP_${err.status}`);
        body.message = err.message;
        return c.json(body, err.status);
    }
    if (err instanceof BadRequestError) {
        c.header(INTERNAL_ERROR_CODE_HEADER, 'BAD_REQUEST');
        body.message = err.message;
        return c.json(body, 400);
    }
    if (err instanceof ConflictError) {
        c.header(INTERNAL_ERROR_CODE_HEADER, 'CONFLICT');
        body.message = err.message;
        return c.json(body, 409);
    }
    if (err instanceof NotFoundError) {
        c.header(INTERNAL_ERROR_CODE_HEADER, 'NOT_FOUND');
        body.message = err.message;
        return c.json(body, 404);
    }
    if (err instanceof UnauthorizedError) {
        c.header(INTERNAL_ERROR_CODE_HEADER, 'UNAUTHORIZED');
        body.message = err.message;
        return c.json(body, 401);
    }

    c.header(INTERNAL_ERROR_CODE_HEADER, 'INTERNAL_ERROR');
    console.error(JSON.stringify({
        requestId: c.get('requestId') || 'unknown',
        level: 'error',
        errorCode: 'INTERNAL_ERROR',
        errorType: 'UnhandledError',
    }));
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
