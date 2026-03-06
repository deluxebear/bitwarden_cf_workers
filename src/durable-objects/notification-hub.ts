/**
 * NotificationHub Durable Object
 *
 * 管理所有 WebSocket 连接，实现 SignalR 协议兼容层。
 * 对应官方 NotificationsHub.cs + AnonymousNotificationsHub.cs + HubHelpers.cs
 *
 * 功能：
 * - WebSocket 连接管理（连接/断开/心跳）
 * - SignalR Handshake + MessagePack 协议
 * - 按 User/Organization/Token 分组
 * - 消息路由与广播
 */

import {
    createHandshakeResponse,
    createInvocationMessage,
    createPingMessage,
    isHandshakeRequest,
    parseSignalRFrames,
    isPingMessage,
} from '../services/signalr-protocol';

// 连接元数据
interface ConnectionMeta {
    userId: string | null;    // 认证用户 ID
    token: string | null;     // 匿名 Hub 的 Token
    orgIds: string[];         // 用户所属组织 ID
    deviceId: string | null;  // 设备标识（用于 contextId 排除）
    isAnonymous: boolean;     // 是否匿名连接
    handshakeCompleted: boolean;
}

// 发送给 DO 的通知请求
export interface NotificationRequest {
    type: 'push';
    target: 'user' | 'organization' | 'anonymous-token';
    targetId: string;
    method: string;           // SignalR 方法名 (ReceiveMessage / AuthRequestResponseRecieved)
    data: unknown;            // 消息 payload
    contextId: string | null; // 排除的设备 ID
}

// 心跳间隔 (120秒，对齐官方 HeartbeatHostedService)
const HEARTBEAT_INTERVAL_MS = 120_000;

export class NotificationHub {
    private state: DurableObjectState;
    private connections: Map<WebSocket, ConnectionMeta> = new Map();
    private heartbeatInterval: ReturnType<typeof setInterval> | null = null;

    constructor(state: DurableObjectState) {
        this.state = state;

        // Hibernation API: 恢复之前的 WebSocket 连接
        for (const ws of state.getWebSockets()) {
            const meta = ws.deserializeAttachment() as ConnectionMeta | null;
            if (meta) {
                this.connections.set(ws, meta);
            }
        }
    }

    async fetch(request: Request): Promise<Response> {
        const url = new URL(request.url);

        // 处理推送通知请求 (从 Worker 发来的内部 API)
        if (url.pathname === '/notify' && request.method === 'POST') {
            return this.handleNotifyRequest(request);
        }

        // 处理 WebSocket 升级请求
        if (request.headers.get('Upgrade') === 'websocket') {
            return this.handleWebSocket(request, url);
        }

        return new Response('Not Found', { status: 404 });
    }

    /**
     * 处理 WebSocket 连接升级
     */
    private handleWebSocket(request: Request, url: URL): Response {
        const isAnonymous = url.pathname === '/anonymous-hub';

        // 从 URL 参数获取连接信息（Worker 端已验证 JWT 并解析）
        const userId = url.searchParams.get('userId');
        const orgIds = url.searchParams.get('orgIds');
        const deviceId = url.searchParams.get('deviceId');
        const token = url.searchParams.get('Token') || url.searchParams.get('token');

        // 认证连接必须有 userId，匿名连接可以没有
        if (!isAnonymous && !userId) {
            return new Response('Unauthorized', { status: 401 });
        }

        const meta: ConnectionMeta = {
            userId: userId,
            token: isAnonymous ? token : null,
            orgIds: orgIds ? orgIds.split(',') : [],
            deviceId: deviceId,
            isAnonymous,
            handshakeCompleted: false,
        };

        // 使用 Hibernation API 创建 WebSocket
        const pair = new WebSocketPair();
        const [client, server] = [pair[0], pair[1]];

        this.state.acceptWebSocket(server);
        server.serializeAttachment(meta);
        this.connections.set(server, meta);

        this.ensureHeartbeat();

        return new Response(null, { status: 101, webSocket: client });
    }

    /**
     * Hibernation API: WebSocket 消息回调
     */
    async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
        const meta = this.connections.get(ws);
        if (!meta) return;

        // 处理二进制消息
        if (message instanceof ArrayBuffer) {
            const data = new Uint8Array(message);

            // 检查是否是 Handshake 请求
            if (!meta.handshakeCompleted && isHandshakeRequest(data)) {
                meta.handshakeCompleted = true;
                ws.serializeAttachment(meta);
                ws.send(createHandshakeResponse());
                return;
            }

            // 解析 SignalR 帧
            try {
                const messages = parseSignalRFrames(data);
                for (const msg of messages) {
                    if (isPingMessage(msg)) {
                        // 回复 Ping
                        ws.send(createPingMessage());
                    }
                    // 客户端一般不发其他消息给服务端（Hub 不暴露可调用方法）
                }
            } catch {
                // 忽略解析错误
            }
            return;
        }

        // 处理文本消息 (可能是 JSON Handshake)
        if (typeof message === 'string') {
            if (!meta.handshakeCompleted) {
                // 尝试按文本 handshake 处理
                const bytes = new TextEncoder().encode(message);
                if (isHandshakeRequest(bytes)) {
                    meta.handshakeCompleted = true;
                    ws.serializeAttachment(meta);
                    ws.send(createHandshakeResponse());
                }
            }
        }
    }

    /**
     * Hibernation API: WebSocket 关闭回调
     */
    async webSocketClose(ws: WebSocket, code: number, reason: string, wasClean: boolean): Promise<void> {
        this.connections.delete(ws);
        this.cleanupHeartbeatIfEmpty();
    }

    /**
     * Hibernation API: WebSocket 错误回调
     */
    async webSocketError(ws: WebSocket, error: unknown): Promise<void> {
        this.connections.delete(ws);
        ws.close(1011, 'Internal Error');
        this.cleanupHeartbeatIfEmpty();
    }

    /**
     * 处理从 Worker 发来的推送通知请求
     */
    private async handleNotifyRequest(request: Request): Promise<Response> {
        const body = await request.json() as NotificationRequest;
        const { target, targetId, method, data, contextId } = body;

        let count = 0;

        for (const [ws, meta] of this.connections) {
            if (!meta.handshakeCompleted) continue;

            // 排除当前设备
            if (contextId && meta.deviceId === contextId) continue;

            let shouldSend = false;

            switch (target) {
                case 'user':
                    shouldSend = meta.userId === targetId;
                    break;
                case 'organization':
                    shouldSend = !meta.isAnonymous && meta.orgIds.includes(targetId);
                    break;
                case 'anonymous-token':
                    shouldSend = meta.isAnonymous && meta.token === targetId;
                    break;
            }

            if (shouldSend) {
                try {
                    const frame = createInvocationMessage(method, [data]);
                    ws.send(frame);
                    count++;
                } catch {
                    // 连接可能已关闭
                    this.connections.delete(ws);
                }
            }
        }

        return Response.json({ sent: count });
    }

    /**
     * 确保心跳定时器运行
     */
    private ensureHeartbeat(): void {
        if (this.heartbeatInterval) return;

        this.heartbeatInterval = setInterval(() => {
            if (this.connections.size === 0) {
                this.cleanupHeartbeatIfEmpty();
                return;
            }

            const ping = createPingMessage();
            for (const [ws, meta] of this.connections) {
                if (!meta.handshakeCompleted) continue;
                try {
                    ws.send(ping);
                } catch {
                    this.connections.delete(ws);
                }
            }
        }, HEARTBEAT_INTERVAL_MS);
    }

    /**
     * 无连接时清理心跳
     */
    private cleanupHeartbeatIfEmpty(): void {
        if (this.connections.size === 0 && this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }
}
