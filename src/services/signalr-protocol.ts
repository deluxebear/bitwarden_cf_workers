/**
 * SignalR Hub Protocol 实现 (MessagePack)
 *
 * 实现 SignalR 服务端协议，兼容 @microsoft/signalr 客户端。
 * 客户端使用 skipNegotiation: true + WebSocket + MessagePackHubProtocol。
 *
 * 协议流程：
 * 1. WebSocket 连接建立
 * 2. 客户端发送 Handshake 请求 (JSON + 0x1E 分隔符)
 * 3. 服务端回复 Handshake 响应 (JSON + 0x1E 分隔符)
 * 4. 后续消息使用 MessagePack 二进制编码
 *
 * MessagePack 帧格式：
 * - 每个帧 = VarInt(payload长度) + MessagePack(payload)
 * - Invocation: [1, headers, invocationId, target, args]
 * - Ping: [6]
 * - Close: [7]
 *
 * 参考：
 * - https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md
 * - https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/TransportProtocols.md
 */

const RECORD_SEPARATOR = 0x1E;

// SignalR 消息类型
const enum MessageType {
    Invocation = 1,
    StreamItem = 2,
    Completion = 3,
    StreamInvocation = 4,
    CancelInvocation = 5,
    Ping = 6,
    Close = 7,
}

// ============================================================
// MessagePack 编码器 (最小实现，仅覆盖 SignalR 需要的类型)
// ============================================================

/**
 * 将 JavaScript 值编码为 MessagePack 二进制。
 * 支持：null, boolean, number (int/float), string, array, object (map), Uint8Array (bin)
 */
export function msgpackEncode(value: unknown): Uint8Array {
    const parts: Uint8Array[] = [];
    encodeValue(value, parts);
    return concat(parts);
}

function encodeValue(value: unknown, parts: Uint8Array[]): void {
    if (value === null || value === undefined) {
        parts.push(new Uint8Array([0xc0])); // nil
        return;
    }

    if (typeof value === 'boolean') {
        parts.push(new Uint8Array([value ? 0xc3 : 0xc2]));
        return;
    }

    if (typeof value === 'number') {
        if (Number.isInteger(value)) {
            encodeInteger(value, parts);
        } else {
            // float64
            const buf = new ArrayBuffer(9);
            const view = new DataView(buf);
            view.setUint8(0, 0xcb);
            view.setFloat64(1, value, false);
            parts.push(new Uint8Array(buf));
        }
        return;
    }

    if (typeof value === 'string') {
        encodeString(value, parts);
        return;
    }

    if (value instanceof Uint8Array) {
        encodeBin(value, parts);
        return;
    }

    if (Array.isArray(value)) {
        encodeArray(value, parts);
        return;
    }

    if (typeof value === 'object') {
        encodeMap(value as Record<string, unknown>, parts);
        return;
    }
}

function encodeInteger(value: number, parts: Uint8Array[]): void {
    if (value >= 0) {
        if (value <= 0x7f) {
            parts.push(new Uint8Array([value])); // positive fixint
        } else if (value <= 0xff) {
            parts.push(new Uint8Array([0xcc, value])); // uint 8
        } else if (value <= 0xffff) {
            const buf = new Uint8Array(3);
            buf[0] = 0xcd;
            new DataView(buf.buffer).setUint16(1, value, false);
            parts.push(buf);
        } else if (value <= 0xffffffff) {
            const buf = new Uint8Array(5);
            buf[0] = 0xce;
            new DataView(buf.buffer).setUint32(1, value, false);
            parts.push(buf);
        } else {
            // Use float64 for large integers
            const buf = new ArrayBuffer(9);
            const view = new DataView(buf);
            view.setUint8(0, 0xcb);
            view.setFloat64(1, value, false);
            parts.push(new Uint8Array(buf));
        }
    } else {
        if (value >= -32) {
            parts.push(new Uint8Array([value & 0xff])); // negative fixint
        } else if (value >= -128) {
            parts.push(new Uint8Array([0xd0, value & 0xff])); // int 8
        } else if (value >= -32768) {
            const buf = new Uint8Array(3);
            buf[0] = 0xd1;
            new DataView(buf.buffer).setInt16(1, value, false);
            parts.push(buf);
        } else if (value >= -2147483648) {
            const buf = new Uint8Array(5);
            buf[0] = 0xd2;
            new DataView(buf.buffer).setInt32(1, value, false);
            parts.push(buf);
        } else {
            const buf = new ArrayBuffer(9);
            const view = new DataView(buf);
            view.setUint8(0, 0xcb);
            view.setFloat64(1, value, false);
            parts.push(new Uint8Array(buf));
        }
    }
}

function encodeString(value: string, parts: Uint8Array[]): void {
    const encoded = new TextEncoder().encode(value);
    const len = encoded.length;
    if (len <= 31) {
        parts.push(new Uint8Array([0xa0 | len])); // fixstr
    } else if (len <= 0xff) {
        parts.push(new Uint8Array([0xd9, len])); // str 8
    } else if (len <= 0xffff) {
        const buf = new Uint8Array(3);
        buf[0] = 0xda;
        new DataView(buf.buffer).setUint16(1, len, false);
        parts.push(buf);
    } else {
        const buf = new Uint8Array(5);
        buf[0] = 0xdb;
        new DataView(buf.buffer).setUint32(1, len, false);
        parts.push(buf);
    }
    parts.push(encoded);
}

function encodeBin(value: Uint8Array, parts: Uint8Array[]): void {
    const len = value.length;
    if (len <= 0xff) {
        parts.push(new Uint8Array([0xc4, len]));
    } else if (len <= 0xffff) {
        const buf = new Uint8Array(3);
        buf[0] = 0xc5;
        new DataView(buf.buffer).setUint16(1, len, false);
        parts.push(buf);
    } else {
        const buf = new Uint8Array(5);
        buf[0] = 0xc6;
        new DataView(buf.buffer).setUint32(1, len, false);
        parts.push(buf);
    }
    parts.push(value);
}

function encodeArray(value: unknown[], parts: Uint8Array[]): void {
    const len = value.length;
    if (len <= 15) {
        parts.push(new Uint8Array([0x90 | len])); // fixarray
    } else if (len <= 0xffff) {
        const buf = new Uint8Array(3);
        buf[0] = 0xdc;
        new DataView(buf.buffer).setUint16(1, len, false);
        parts.push(buf);
    } else {
        const buf = new Uint8Array(5);
        buf[0] = 0xdd;
        new DataView(buf.buffer).setUint32(1, len, false);
        parts.push(buf);
    }
    for (const item of value) {
        encodeValue(item, parts);
    }
}

function encodeMap(value: Record<string, unknown>, parts: Uint8Array[]): void {
    const keys = Object.keys(value);
    const len = keys.length;
    if (len <= 15) {
        parts.push(new Uint8Array([0x80 | len])); // fixmap
    } else if (len <= 0xffff) {
        const buf = new Uint8Array(3);
        buf[0] = 0xde;
        new DataView(buf.buffer).setUint16(1, len, false);
        parts.push(buf);
    } else {
        const buf = new Uint8Array(5);
        buf[0] = 0xdf;
        new DataView(buf.buffer).setUint32(1, len, false);
        parts.push(buf);
    }
    for (const key of keys) {
        encodeString(key, parts);
        encodeValue(value[key], parts);
    }
}

// ============================================================
// MessagePack 解码器 (最小实现)
// ============================================================

export function msgpackDecode(data: Uint8Array): unknown {
    const result = decodeValue(data, 0);
    return result.value;
}

interface DecodeResult {
    value: unknown;
    offset: number;
}

function decodeValue(data: Uint8Array, offset: number): DecodeResult {
    if (offset >= data.length) {
        throw new Error('Unexpected end of msgpack data');
    }
    const byte = data[offset];

    // positive fixint (0x00 - 0x7f)
    if (byte <= 0x7f) {
        return { value: byte, offset: offset + 1 };
    }

    // fixmap (0x80 - 0x8f)
    if (byte >= 0x80 && byte <= 0x8f) {
        return decodeMapN(data, offset + 1, byte & 0x0f);
    }

    // fixarray (0x90 - 0x9f)
    if (byte >= 0x90 && byte <= 0x9f) {
        return decodeArrayN(data, offset + 1, byte & 0x0f);
    }

    // fixstr (0xa0 - 0xbf)
    if (byte >= 0xa0 && byte <= 0xbf) {
        const len = byte & 0x1f;
        const str = new TextDecoder().decode(data.subarray(offset + 1, offset + 1 + len));
        return { value: str, offset: offset + 1 + len };
    }

    // nil
    if (byte === 0xc0) return { value: null, offset: offset + 1 };
    // false
    if (byte === 0xc2) return { value: false, offset: offset + 1 };
    // true
    if (byte === 0xc3) return { value: true, offset: offset + 1 };

    // bin 8
    if (byte === 0xc4) {
        const len = data[offset + 1];
        return { value: data.slice(offset + 2, offset + 2 + len), offset: offset + 2 + len };
    }
    // bin 16
    if (byte === 0xc5) {
        const len = new DataView(data.buffer, data.byteOffset).getUint16(offset + 1, false);
        return { value: data.slice(offset + 3, offset + 3 + len), offset: offset + 3 + len };
    }

    // float32
    if (byte === 0xca) {
        const val = new DataView(data.buffer, data.byteOffset).getFloat32(offset + 1, false);
        return { value: val, offset: offset + 5 };
    }
    // float64
    if (byte === 0xcb) {
        const val = new DataView(data.buffer, data.byteOffset).getFloat64(offset + 1, false);
        return { value: val, offset: offset + 9 };
    }

    // uint8
    if (byte === 0xcc) return { value: data[offset + 1], offset: offset + 2 };
    // uint16
    if (byte === 0xcd) {
        const val = new DataView(data.buffer, data.byteOffset).getUint16(offset + 1, false);
        return { value: val, offset: offset + 3 };
    }
    // uint32
    if (byte === 0xce) {
        const val = new DataView(data.buffer, data.byteOffset).getUint32(offset + 1, false);
        return { value: val, offset: offset + 5 };
    }

    // int8
    if (byte === 0xd0) {
        const val = new DataView(data.buffer, data.byteOffset).getInt8(offset + 1);
        return { value: val, offset: offset + 2 };
    }
    // int16
    if (byte === 0xd1) {
        const val = new DataView(data.buffer, data.byteOffset).getInt16(offset + 1, false);
        return { value: val, offset: offset + 3 };
    }
    // int32
    if (byte === 0xd2) {
        const val = new DataView(data.buffer, data.byteOffset).getInt32(offset + 1, false);
        return { value: val, offset: offset + 5 };
    }

    // str 8
    if (byte === 0xd9) {
        const len = data[offset + 1];
        const str = new TextDecoder().decode(data.subarray(offset + 2, offset + 2 + len));
        return { value: str, offset: offset + 2 + len };
    }
    // str 16
    if (byte === 0xda) {
        const len = new DataView(data.buffer, data.byteOffset).getUint16(offset + 1, false);
        const str = new TextDecoder().decode(data.subarray(offset + 3, offset + 3 + len));
        return { value: str, offset: offset + 3 + len };
    }
    // str 32
    if (byte === 0xdb) {
        const len = new DataView(data.buffer, data.byteOffset).getUint32(offset + 1, false);
        const str = new TextDecoder().decode(data.subarray(offset + 5, offset + 5 + len));
        return { value: str, offset: offset + 5 + len };
    }

    // array 16
    if (byte === 0xdc) {
        const len = new DataView(data.buffer, data.byteOffset).getUint16(offset + 1, false);
        return decodeArrayN(data, offset + 3, len);
    }
    // array 32
    if (byte === 0xdd) {
        const len = new DataView(data.buffer, data.byteOffset).getUint32(offset + 1, false);
        return decodeArrayN(data, offset + 5, len);
    }

    // map 16
    if (byte === 0xde) {
        const len = new DataView(data.buffer, data.byteOffset).getUint16(offset + 1, false);
        return decodeMapN(data, offset + 3, len);
    }
    // map 32
    if (byte === 0xdf) {
        const len = new DataView(data.buffer, data.byteOffset).getUint32(offset + 1, false);
        return decodeMapN(data, offset + 5, len);
    }

    // negative fixint (0xe0 - 0xff)
    if (byte >= 0xe0) {
        return { value: byte - 256, offset: offset + 1 };
    }

    throw new Error(`Unknown msgpack type: 0x${byte.toString(16)} at offset ${offset}`);
}

function decodeArrayN(data: Uint8Array, offset: number, count: number): DecodeResult {
    const arr: unknown[] = [];
    let currentOffset = offset;
    for (let i = 0; i < count; i++) {
        const result = decodeValue(data, currentOffset);
        arr.push(result.value);
        currentOffset = result.offset;
    }
    return { value: arr, offset: currentOffset };
}

function decodeMapN(data: Uint8Array, offset: number, count: number): DecodeResult {
    const map: Record<string, unknown> = {};
    let currentOffset = offset;
    for (let i = 0; i < count; i++) {
        const keyResult = decodeValue(data, currentOffset);
        const valueResult = decodeValue(data, keyResult.offset);
        map[String(keyResult.value)] = valueResult.value;
        currentOffset = valueResult.offset;
    }
    return { value: map, offset: currentOffset };
}

// ============================================================
// SignalR 帧编码/解码
// ============================================================

/**
 * 编码 VarInt 长度前缀（SignalR MessagePack Binary 传输格式）
 * 参考：https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/common/Shared/BinaryMessageParser.cs
 */
function encodeVarInt(value: number): Uint8Array {
    const bytes: number[] = [];
    do {
        let b = value & 0x7f;
        value >>= 7;
        if (value > 0) b |= 0x80;
        bytes.push(b);
    } while (value > 0);
    return new Uint8Array(bytes);
}

/**
 * 解码 VarInt 长度前缀
 */
function decodeVarInt(data: Uint8Array, offset: number): { value: number; bytesRead: number } {
    let value = 0;
    let shift = 0;
    let bytesRead = 0;
    do {
        if (offset + bytesRead >= data.length) {
            throw new Error('Incomplete varint');
        }
        const b = data[offset + bytesRead];
        value |= (b & 0x7f) << shift;
        shift += 7;
        bytesRead++;
        if (!(b & 0x80)) break;
    } while (true);
    return { value, bytesRead };
}

/**
 * 创建 SignalR Handshake 响应
 * 客户端发送: {"protocol":"messagepack","version":1}\x1E
 * 服务端回复: {}\x1E
 */
export function createHandshakeResponse(): Uint8Array {
    const json = '{}';
    const encoder = new TextEncoder();
    const jsonBytes = encoder.encode(json);
    const result = new Uint8Array(jsonBytes.length + 1);
    result.set(jsonBytes);
    result[jsonBytes.length] = RECORD_SEPARATOR;
    return result;
}

/**
 * 检查是否是 Handshake 请求
 */
export function isHandshakeRequest(data: ArrayBuffer | Uint8Array): boolean {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    // Handshake 以 0x1E 结尾，且内容是 JSON 文本
    if (bytes.length === 0) return false;
    if (bytes[bytes.length - 1] !== RECORD_SEPARATOR) return false;
    try {
        const text = new TextDecoder().decode(bytes.subarray(0, bytes.length - 1));
        const parsed = JSON.parse(text);
        return parsed.protocol === 'messagepack' || parsed.protocol === 'json';
    } catch {
        return false;
    }
}

/**
 * 解析 SignalR 帧中的 MessagePack 消息
 * 返回解码后的消息数组
 */
export function parseSignalRFrames(data: ArrayBuffer | Uint8Array): unknown[] {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    const messages: unknown[] = [];
    let offset = 0;

    while (offset < bytes.length) {
        const { value: payloadLength, bytesRead } = decodeVarInt(bytes, offset);
        offset += bytesRead;

        if (offset + payloadLength > bytes.length) break;

        const payload = bytes.subarray(offset, offset + payloadLength);
        const decoded = msgpackDecode(payload);
        messages.push(decoded);
        offset += payloadLength;
    }

    return messages;
}

/**
 * 创建 SignalR Invocation 消息帧
 * 格式: VarInt(len) + MessagePack([1, headers, invocationId, target, [args]])
 *
 * 对应官方 SignalR 的 SendAsync(method, data)
 */
export function createInvocationMessage(target: string, args: unknown[]): Uint8Array {
    // [type=1, headers={}, invocationId=null, target, args]
    const msgpack = msgpackEncode([
        MessageType.Invocation, // type
        {},                     // headers
        null,                   // invocationId (null = 非请求消息)
        target,                 // method name
        args,                   // arguments array
    ]);

    const lengthPrefix = encodeVarInt(msgpack.length);
    return concat([lengthPrefix, msgpack]);
}

/**
 * 创建 SignalR Ping 消息帧
 */
export function createPingMessage(): Uint8Array {
    const msgpack = msgpackEncode([MessageType.Ping]);
    const lengthPrefix = encodeVarInt(msgpack.length);
    return concat([lengthPrefix, msgpack]);
}

/**
 * 创建 SignalR Close 消息帧
 */
export function createCloseMessage(error?: string): Uint8Array {
    const msg = error
        ? [MessageType.Close, error]
        : [MessageType.Close];
    const msgpack = msgpackEncode(msg);
    const lengthPrefix = encodeVarInt(msgpack.length);
    return concat([lengthPrefix, msgpack]);
}

/**
 * 判断解码后的消息类型
 */
export function getMessageType(decoded: unknown): MessageType | null {
    if (!Array.isArray(decoded) || decoded.length === 0) return null;
    const type = decoded[0];
    if (typeof type === 'number' && type >= 1 && type <= 7) {
        return type as MessageType;
    }
    return null;
}

/**
 * 判断是否是 Ping 消息
 */
export function isPingMessage(decoded: unknown): boolean {
    return getMessageType(decoded) === MessageType.Ping;
}

// ============================================================
// 工具函数
// ============================================================

function concat(arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
}
