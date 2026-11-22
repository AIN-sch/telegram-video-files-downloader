# MTProto 2.0 传输层：TCP/intermediate、SOCKS5、加密报文收发、RPC 分发
import asyncio
import os
import socket
import struct
import time

import crypto

INTERMEDIATE_TAG = b'\xee\xee\xee\xee'
ABRIDGED_TAG = b'\xef'
ERROR_TAG = b'\x00\x00\x00\x00'

# 系统消息构造 id
MSG_CONTAINER = 0x73F1F8DC
GZIP_PACKED = 0x3072CFA1
RPC_RESULT = 0xF35C6D01
RPC_ERROR = 0x2144CA19
BAD_SERVER_SALT = 0xEDAB447B
BAD_MSG_NOTIFICATION = 0xA7EFF811
NEW_SESSION_CREATED = 0x9EC20908
MSGS_ACK = 0x62D6B459
PONG = 0x347773C5

# invokeWithLayer / initConnection
INVOKE_WITH_LAYER = 0xDA9B0D0D
INIT_CONNECTION = 0xC1CD5EA9

# Telegram Desktop 官方 api_id
TDESKTOP_API_ID = 2040
TDESKTOP_API_HASH = 'b18441a1ff607e10a989891a5462e627'

DEFAULT_LAYER = 181


class MtprotoError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, 'RPC %d: %s' % (code, message))
        self.code = code
        self.message = message


class Socks5Connector(object):
    # 通过 SOCKS5 建立 TCP 连接
    def __init__(self, host, port, user=None, password=None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    async def connect(self, dst_host, dst_port):
        reader, writer = await asyncio.open_connection(self.host, self.port)
        if self.user:
            writer.write(b'\x05\x01\x02')
            await writer.drain()
            r = await reader.readexactly(2)
            if r[1] != 0x02:
                raise IOError('SOCKS5 代理未提供用户密码认证')
            u = self.user.encode()
            p = self.password.encode()
            writer.write(b'\x01' + bytes([len(u)]) + u + bytes([len(p)]) + p)
            await writer.drain()
            r = await reader.readexactly(2)
            if r[1] != 0:
                raise IOError('SOCKS5 认证失败 code=%d' % r[1])
        else:
            writer.write(b'\x05\x01\x00')
            await writer.drain()
            await reader.readexactly(2)
        h = dst_host.encode()
        writer.write(b'\x05\x01\x00\x03' + bytes([len(h)]) + h + struct.pack('>H', dst_port))
        await writer.drain()
        r = await reader.readexactly(4)
        if r[1] != 0:
            raise IOError('SOCKS5 CONNECT 失败 reply=%d' % r[1])
        if r[3] == 1:
            await reader.readexactly(4)
        elif r[3] == 3:
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n)
        else:
            await reader.readexactly(16)
        await reader.readexactly(2)
        return reader, writer


class MtprotoConnection(object):
    # 单条 MTProto 加密连接：负责 intermediate 帧、salt/seqno/msg_id 维护与 RPC 应答
    def __init__(self, auth_key, dc_id, host, port, proxy=None, use_abridged=False, log=None):
        self.auth_key = auth_key
        self.key_id = crypto.auth_key_id(auth_key)
        self.dc_id = dc_id
        self.host = host
        self.port = port
        self.proxy = proxy
        self.use_abridged = use_abridged
        self.reader = None
        self.writer = None
        self.session_id = struct.unpack('<Q', os.urandom(8))[0]
        self.salt = 0
        self.seq_no = 0
        self.last_msg_id = 0
        self.pending = {}
        self.log = log or (lambda *a, **k: None)
        self.raw_log = []
        self.closed = False
        self.lock = asyncio.Lock()

    async def connect(self):
        if self.proxy:
            conn = Socks5Connector(self.proxy[0], self.proxy[1],
                                   self.proxy[2] if len(self.proxy) > 2 else None,
                                   self.proxy[3] if len(self.proxy) > 3 else None)
            self.reader, self.writer = await conn.connect(self.host, self.port)
        else:
            self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        if self.use_abridged:
            self.writer.write(ABRIDGED_TAG)
        else:
            self.writer.write(INTERMEDIATE_TAG)
        await self.writer.drain()

    def next_msg_id(self):
        # 单调递增且四字节对齐，全局与连接内同时兜底
        mid = crypto.new_msg_id()
        if mid <= self.last_msg_id:
            mid = self.last_msg_id + 4
            crypto.bump_msg_id(mid)
        self.last_msg_id = mid
        return mid

    async def _send_frame(self, payload):
        if self.use_abridged:
            ints = len(payload) // 4
            if ints < 0x7F:
                head = bytes([ints])
            else:
                head = b'\x7f' + bytes([ints & 0xFF, (ints >> 8) & 0xFF, (ints >> 16) & 0xFF])
            self.writer.write(head + payload)
        else:
            self.writer.write(struct.pack('<i', len(payload)) + payload)
        await self.writer.drain()

    async def _read_frame(self):
        if self.use_abridged:
            first = (await self.reader.readexactly(1))[0]
            if first == 0x7F:
                extra = await self.reader.readexactly(3)
                ints = extra[0] | (extra[1] << 8) | (extra[2] << 16)
            else:
                ints = first
            return await self.reader.readexactly(ints * 4)
        head = await self.reader.readexactly(4)
        n = struct.unpack('<i', head)[0]
        if n < 0 or n > 0x1000000:
            raise IOError('收到的帧长度异常: %d' % n)
        return await self.reader.readexactly(n)

    async def send_raw(self, body, content_related=True):
        # 发一条加密消息，返回 msg_id
        async with self.lock:
            msg_id = self.next_msg_id()
            seq = self.seq_no * 2 + (1 if content_related else 0)
            if content_related:
                self.seq_no += 1
            pkt = crypto.pack_message(self.auth_key, self.key_id, self.salt,
                                      self.session_id, msg_id, seq, body)
            self.raw_log.append(('send', msg_id, body[:512].hex()))
            await self._send_frame(pkt)
            return msg_id

    def _decrypt_packet(self, packet):
        return crypto.unpack_message(self.auth_key, packet)

    async def recv_once(self, timeout=20.0):
        # 收一帧并按需返回解出的响应
        packet = await asyncio.wait_for(self._read_frame(), timeout)
        if packet[:4] == ERROR_TAG:
            code = struct.unpack('<i', packet[4:8])[0]
            raise IOError('服务端返回传输错误码 %d' % code)
        msg = self._decrypt_packet(packet)
        self.raw_log.append(('recv', msg['msg_id'], msg['body'][:512].hex()))
        return msg

    def _unwrap_gzip(self, payload):
        # rpc_result 内层可能是 gzip_packed 或 rpc_error，统一在这里处理
        if len(payload) >= 4:
            cid = struct.unpack('<I', payload[:4])[0]
            if cid == GZIP_PACKED:
                kind, ref, inner = self._parse_body(payload)
                if kind == 'gzip':
                    payload = inner
            elif cid == RPC_ERROR:
                kind, ref, inner = self._parse_body(payload)
                if kind == 'error':
                    raise MtprotoError(inner[0], inner[1])
        return payload

    def _parse_body(self, body):
        # 解析系统消息，返回 ('rpc', req_msg_id, payload_bytes) 或 ('other', ctor, body)
        if len(body) < 4:
            return ('other', None, body)
        ctor = struct.unpack('<I', body[:4])[0]
        if ctor == MSG_CONTAINER:
            out = []
            n = struct.unpack('<I', body[4:8])[0]
            pos = 8
            for _ in range(n):
                _mid, _seq, ln = struct.unpack('<QII', body[pos:pos + 16])
                pos += 16
                out.append(body[pos:pos + ln])
                pos += ln
            return ('container', None, out)
        if ctor == GZIP_PACKED:
            import zlib
            n = body[4]
            if n < 254:
                pos, ln = 5, n
                pad = (4 - (ln + 1) % 4) % 4
            else:
                pos, ln = 8, struct.unpack('<I', body[5:8] + b'\x00')[0]
                pad = (4 - ln % 4) % 4
            data = body[pos:pos + ln]
            return ('gzip', None, zlib.decompress(data, 16 + zlib.MAX_WBITS))
        if ctor == RPC_RESULT:
            req_id = struct.unpack('<Q', body[4:12])[0]
            return ('rpc', req_id, body[12:])
        if ctor == RPC_ERROR:
            code = struct.unpack('<i', body[4:8])[0]
            n = body[8]
            msg = body[9:9 + n].decode('utf-8', 'replace')
            return ('error', None, (code, msg))
        if ctor == BAD_SERVER_SALT:
            req_id = struct.unpack('<Q', body[4:12])[0]
            new_salt = struct.unpack('<Q', body[20:28])[0]
            return ('salt', req_id, new_salt)
        if ctor == NEW_SESSION_CREATED:
            first_id, uid, salt = struct.unpack('<QQQ', body[4:28])
            return ('newsession', None, (first_id, uid, salt))
        if ctor == BAD_MSG_NOTIFICATION:
            bad_id = struct.unpack('<Q', body[4:12])[0]
            err = struct.unpack('<i', body[16:20])[0]
            return ('badmsg', bad_id, err)
        if ctor == MSGS_ACK:
            return ('ack', None, body)
        if ctor == PONG:
            return ('pong', None, body)
        return ('other', None, body)

    async def call(self, body, timeout=25.0, max_retry=3):
        # 发送请求并等待对应 rpc_result，自动处理 bad_server_salt 与容器解包
        attempt = 0
        while True:
            attempt += 1
            msg_id = await self.send_raw(body)
            deadline = time.time() + timeout
            while time.time() < deadline:
                msg = await self.recv_once(timeout=max(1.0, deadline - time.time()))
                kind, ref, payload = self._parse_body(msg['body'])
                if kind == 'salt':
                    self.salt = payload
                    self.log('[mtp] 收到 bad_server_salt，切换 salt=%016x 重发' % self.salt)
                    break
                if kind == 'newsession':
                    self.salt = payload[2]
                    self.log('[mtp] new_session_created salt=%016x' % self.salt)
                    continue
                if kind == 'error':
                    if payload[1] == 'MSGID_DECREASE_RETRY' and attempt <= max_retry:
                        # 服务端要求 msg_id 大于上次，跳一段后重发
                        crypto.bump_msg_id(crypto.cur_msg_id() + 4 * (1 << 16))
                        self.last_msg_id = 0
                        self.log('[mtp] MSGID_DECREASE_RETRY，推进 msg_id 后重发 attempt=%d' % attempt)
                        break
                    raise MtprotoError(payload[0], payload[1])
                if kind == 'container':
                    handled = await self._handle_container(payload, msg)
                    if handled is not None:
                        return handled
                    continue
                if kind == 'gzip':
                    kind, ref, payload = self._parse_body(payload)
                if kind == 'rpc' and ref == msg_id:
                    return self._unwrap_gzip(payload)
                if kind == 'badmsg':
                    if attempt >= max_retry:
                        raise IOError('bad_msg_notification 重试耗尽 err=%d' % payload)
                    self.log('[mtp] bad_msg_notification err=%d 重试' % payload)
                    break
                # 其他消息忽略，继续等
            if attempt > max_retry:
                raise IOError('RPC 超时或重试耗尽')

    async def _handle_container(self, items, msg):
        # 容器内逐条解析，返回 None 表示外层继续等
        for item in items:
            kind, ref, payload = self._parse_body(item)
            if kind == 'gzip':
                kind, ref, payload = self._parse_body(payload)
            if kind == 'salt':
                self.salt = payload
                self.log('[mtp] 容器内 bad_server_salt salt=%016x' % self.salt)
                continue
            if kind == 'ack':
                continue
            if kind == 'newsession':
                self.salt = payload[2]
                continue
            if kind == 'error':
                raise MtprotoError(payload[0], payload[1])
            if kind == 'rpc':
                return payload
        return None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            if self.writer:
                self.writer.close()
                await self.writer.wait_closed()
        except Exception:
            pass
