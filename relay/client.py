#!/usr/bin/env python
# tgdl 加密回传客户端：TLS1.3 + 证书固定 + PSK 认证 + AES-256-GCM 分帧 + 断点续传

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import ssl
import struct
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 部署参数一律走环境变量，仓库内不放真实值
PSK = os.environ.get("TGDL_PSK", "CHANGE_ME_32_BYTES_OR_LONGER").encode()
SERVER_HOST = os.environ.get("TGDL_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("TGDL_PORT", "8443"))
SNI = os.environ.get("TGDL_SNI", "www.microsoft.com")
CERT_PIN = os.environ.get("TGDL_PIN", "")
TUNNEL_MODULE = os.environ.get("TGDL_TUNNEL_MODULE", "tgdl_tunnel")
# 服务端入站端口未放行时，经本机已有 SOCKS5 出网
SOCKS_PORT = int(os.environ.get("TGDL_SOCKS_PORT", "1080"))
AUTOPROXY_SCRIPT = os.environ.get("TGDL_PROXY_SCRIPT", "")

MAGIC = b"TGD1"
HEAD_LEN = 17
TAG_LEN = 16
OFF_LEN = 8
MAX_DATA = 262144
MAX_PAYLOAD = MAX_DATA + OFF_LEN
MAX_BODY = MAX_PAYLOAD + TAG_LEN

FRAME_AUTH = 1
FRAME_PING = 2
FRAME_GET = 3
FRAME_DATA = 4
FRAME_META = 5
FRAME_DONE = 6
FRAME_ERR = 7

HS_LEN = 56
HS_TIMEOUT = 15.0
IO_TIMEOUT = 120.0
DRAIN_TIMEOUT = 30.0
IDLE_TIMEOUT = 60.0
RETRY_MAX = 5
GRID = 4 << 20
CHUNK = 1 << 20


# 口令认证

def _tag(ts, nonce, extra=b""):
    # PSK 对 时间戳+随机数 做 HMAC-SHA256
    return hmac.new(PSK, b"relay-v1|" + struct.pack("!Q", ts) + b"|" + nonce + extra,
                    hashlib.sha256).digest()


def derive_keys(cnonce, snonce):
    # 与服务端 HKDF-SHA256 一致：salt=双端随机数，info=tgdl-v1，输出 76 字节
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    okm = HKDF(algorithm=hashes.SHA256(), length=76, salt=cnonce + snonce,
               info=b"tgdl-v1").derive(PSK)
    return okm[:32], okm[32:64], okm[64:76]


def make_aead(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key)


# 分帧

class ProtocolError(Exception):
    def __init__(self, msg, code=""):
        Exception.__init__(self, msg)
        self.code = code


class Channel:
    def __init__(self, reader, writer, k_tx, k_rx, iv):
        self.reader = reader
        self.writer = writer
        self.aead_tx = make_aead(k_tx)
        self.aead_rx = make_aead(k_rx)
        self.iv = iv
        self.seq_tx = 0
        self.seq_rx = 0

    def _nonce(self, seq):
        # GCM 随机数 = IV 前 4 字节 + 序号
        return self.iv[:4] + struct.pack("!Q", seq)

    async def send(self, ftype, payload=b""):
        seq = self.seq_tx
        self.seq_tx += 1
        head = MAGIC + struct.pack("!QBI", seq, ftype, len(payload))
        self.writer.write(head + self.aead_tx.encrypt(self._nonce(seq), payload, head))
        # 隧道半死时 drain 会永久阻塞，必须设超时
        await asyncio.wait_for(self.writer.drain(), DRAIN_TIMEOUT)

    async def recv(self, timeout=IO_TIMEOUT):
        head = await asyncio.wait_for(self.reader.readexactly(HEAD_LEN), timeout)
        if head[:4] != MAGIC:
            raise ProtocolError("魔数不匹配")
        seq, ftype, ln = struct.unpack("!QBI", head[4:HEAD_LEN])
        if seq != self.seq_rx:
            raise ProtocolError("序号异常 期望 %d 收到 %d" % (self.seq_rx, seq))
        if ln > MAX_BODY:
            raise ProtocolError("帧长度超限 %d" % ln)
        body = await asyncio.wait_for(self.reader.readexactly(ln + TAG_LEN), timeout)
        try:
            payload = self.aead_rx.decrypt(self._nonce(seq), body, head)
        except Exception:
            raise ProtocolError("帧解密失败")
        self.seq_rx += 1
        return ftype, payload


# 连接

def make_ssl_ctx(via_tunnel=False):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["tgdl/1"])
    return ctx


async def client_handshake(reader, writer, pin):
    # 校验证书指纹后做 PSK 双向认证
    der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
    fp = hashlib.sha256(der).hexdigest()
    if pin and fp != pin:
        raise ProtocolError("证书指纹不匹配 %s" % fp, "pin")
    cnonce = os.urandom(16)
    ts = int(time.time())
    writer.write(cnonce + struct.pack("!Q", ts) + _tag(ts, cnonce))
    await writer.drain()
    resp = await asyncio.wait_for(reader.readexactly(HS_LEN), HS_TIMEOUT)
    snonce = resp[:16]
    sts, = struct.unpack("!Q", resp[16:24])
    if not hmac.compare_digest(resp[24:56], _tag(sts, snonce, cnonce)):
        raise ProtocolError("服务端认证失败", "auth")
    return derive_keys(cnonce, snonce)


async def _open(host, port, via_socks, timeout, via_tunnel=False):
    # 按三条链路建立 TCP：直连 / 本机 SOCKS5 / 外部隧道模块，再套 TLS1.3
    ctx = make_ssl_ctx()
    if via_tunnel:
        module = __import__(TUNNEL_MODULE)
        loop = asyncio.get_running_loop()
        raw = await asyncio.wait_for(
            loop.run_in_executor(None, module.open_tunnel, host, port, timeout), timeout + 5)
        raw.setblocking(False)
        return await asyncio.wait_for(
            asyncio.open_connection(sock=raw, ssl=ctx, server_hostname=SNI,
                                    limit=1 << 20), timeout)
    if not via_socks:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=SNI, limit=1 << 20), timeout)
    import socks
    loop = asyncio.get_running_loop()
    raw = await asyncio.wait_for(
        loop.run_in_executor(None, socks.socks_connect, host, port, timeout), timeout)
    raw.setblocking(False)
    return await asyncio.wait_for(
        asyncio.open_connection(sock=raw, ssl=ctx, server_hostname=SNI,
                                limit=1 << 20), timeout)


async def dial(host, port, pin, via_socks=False, timeout=25.0, via_tunnel=False):
    r, w = await _open(host, port, via_socks, timeout, via_tunnel)
    try:
        k_c2s, k_s2c, iv = await client_handshake(r, w, pin)
    except Exception:
        w.close()
        raise
    return Channel(r, w, k_c2s, k_s2c, iv), w


async def do_auth(ch):
    await ch.send(FRAME_AUTH, b"{}")
    ftype, payload = await ch.recv()
    if ftype != FRAME_AUTH:
        raise ProtocolError("AUTH 应答异常")
    info = json.loads(payload.decode("utf-8"))
    if not info.get("ok"):
        raise ProtocolError("AUTH 被拒绝")
    return info


# 状态文件

class State:
    # .state.json 记录分片进度，每块落盘后 fsync
    def __init__(self, path):
        self.path = path
        self.data = {"size": None, "sha256": None, "chunks": {}, "created": time.time()}

    def load(self):
        if not os.path.exists(self.path):
            return False
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            self.data.setdefault("chunks", {})
            return True
        except Exception:
            return False

    def save(self, force=True):
        # 原子写状态文件；force=False 时按 0.3s 限频，避免每块都落盘
        now = time.time()
        if not force and now - getattr(self, "_last", 0.0) < 0.3:
            self._dirty = True
            return
        self._last = now
        self._dirty = False
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


# 下载主体

class Job:
    def __init__(self, args):
        self.args = args
        self.out = os.path.abspath(args.out)
        self.part = self.out + ".part"
        self.state_path = self.out + ".state.json"
        self.state = State(self.state_path)
        self.size = None
        self.meta = {}
        self.done_bytes = 0
        self.t0 = time.time()
        self.mark_t = time.time()
        self.mark_b = 0
        self.rate = 0.0
        self.conns = 0
        self.lock = asyncio.Lock()
        self.file_lock = asyncio.Lock()
        self.fh = None
        self.finished = [False]
        self.error = None

    def prepare(self):
        # 建立输出目录与 .part 文件
        d = os.path.dirname(self.out)
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        if os.path.isdir(self.out):
            raise SystemExit("输出路径是目录：%s" % self.out)
        resumed = False
        if self.args.resume and os.path.exists(self.part):
            resumed = self.state.load()
        if not resumed:
            self.state = State(self.state_path)
            if os.path.exists(self.part):
                os.remove(self.part)
            if os.path.exists(self.state_path):
                os.remove(self.state_path)
        self.fh = open(self.part, "r+b" if os.path.exists(self.part) else "w+b")
        if resumed:
            chunks = self.state.data.get("chunks") or {}
            self.done_bytes = sum(int(v) for v in chunks.values())
            self.size = self.state.data.get("size") or None
        return resumed

    def spec(self):
        if self.args.uri:
            # tgdl:// 由服务端解析，客户端只透传
            return {"kind": "mtproto", "uri": self.args.uri}
        if self.args.spec_file:
            with open(self.args.spec_file, "r", encoding="utf-8") as f:
                return json.load(f)
        if self.args.url:
            if self.args.url.startswith("tgdl://"):
                return {"kind": "mtproto", "uri": self.args.url}
            return {"kind": "http", "url": self.args.url}
        raise SystemExit("需要 --url / --uri / --spec-file")

    def render(self):
        # 每 500ms 输出一行进度
        now = time.time()
        dt = now - self.mark_t
        if dt >= 0.5:
            db = self.done_bytes - self.mark_b
            self.rate = db / dt if dt > 0 else 0.0
            self.mark_t = now
            self.mark_b = self.done_bytes
        pct = (self.done_bytes / self.size * 100) if self.size else 0.0
        total = "%d" % self.size if self.size else "?"
        eta = "?"
        if self.size and self.rate > 1:
            eta = "%ds" % int((self.size - self.done_bytes) / self.rate)
        sys.stdout.write("\r已下 %s / %s  %.1f%%  %s/s  ETA %s  连接 %d   " % (
            _h(self.done_bytes), _h(self.size) if self.size else "?", pct,
            _h(self.rate), eta, self.conns))
        sys.stdout.flush()

    async def write_at(self, off, data):
        # 按偏移写入，数据落盘后记入状态；同偏移重复写入不重复计数
        async with self.file_lock:
            self.fh.seek(off)
            self.fh.write(data)
            self.fh.flush()
            os.fsync(self.fh.fileno())
            key = str(off)
            old = int(self.state.data["chunks"].get(key) or 0)
            self.state.data["chunks"][key] = len(data)
            self.done_bytes += len(data) - old
            self.state.save(force=False)

    async def seg(self, idx, start, end):
        # 单个分片：GET 指定 offset/length，收到 DATA 按序落盘
        spec = dict(self.spec())
        pos = start
        attempt = 0
        while pos < end:
            try:
                ch, w = await dial(self.args.host, self.args.port, self.args.pin, self.args.via_socks, via_tunnel=self.args.via_tunnel)
                async with self.lock:
                    self.conns += 1
                try:
                    await do_auth(ch)
                    req = {"spec": spec, "offset": pos, "length": end - pos}
                    await ch.send(FRAME_GET, json.dumps(req, ensure_ascii=False).encode())
                    idle = 0
                    while True:
                        ftype, payload = await asyncio.wait_for(ch.recv(), IDLE_TIMEOUT)
                        idle = 0
                        if ftype == FRAME_META:
                            m = json.loads(payload.decode("utf-8"))
                            if self.size is None and m.get("size"):
                                self.size = int(m["size"])
                                self.state.data["size"] = self.size
                                self.state.data["sha256"] = m.get("sha256")
                                self.meta = m
                                self.fh.truncate(self.size)
                            if self.args.verbose:
                                sys.stderr.write("\n[META] %s\n" % json.dumps(m, ensure_ascii=False))
                        elif ftype == FRAME_DATA:
                            off, = struct.unpack("!Q", payload[:OFF_LEN])
                            buf = payload[OFF_LEN:]
                            if off != pos:
                                raise ProtocolError("偏移错乱 期望 %d 收到 %d" % (pos, off), "seq")
                            if pos + len(buf) > end:
                                buf = buf[:end - pos]
                            if buf:
                                await self.write_at(pos, buf)
                                pos += len(buf)
                        elif ftype == FRAME_DONE:
                            d = json.loads(payload.decode("utf-8"))
                            if d.get("sha256"):
                                self.state.data["sha256"] = d["sha256"]
                                self.meta["sha256"] = d["sha256"]
                            return
                        elif ftype == FRAME_ERR:
                            e = json.loads(payload.decode("utf-8"))
                            raise ProtocolError("服务端错误 %s %s" % (
                                e.get("code"), e.get("msg")), e.get("code"))
                        else:
                            raise ProtocolError("意外帧 %d" % ftype)
                finally:
                    async with self.lock:
                        self.conns -= 1
                    try:
                        w.close()
                    except Exception:
                        pass
            except SystemExit:
                raise
            except asyncio.TimeoutError as e:
                attempt += 1
                if attempt > RETRY_MAX:
                    raise ProtocolError("空闲超时且重试耗尽 pos=%d" % pos, "idle")
                if self.args.verbose:
                    sys.stderr.write("\n[分片%d] 空闲超时，第%d次重连 pos=%d\n" % (idx, attempt, pos))
                await asyncio.sleep(min(1.5 * attempt, 6.0))
            except Exception as e:
                attempt += 1
                if isinstance(e, ProtocolError) and e.code in ("no_fetcher", "bad_spec"):
                    raise
                if attempt > RETRY_MAX:
                    raise
                if self.args.verbose:
                    sys.stderr.write("\n[分片%d] 第%d次重试 pos=%d %r\n" % (idx, attempt, pos, e))
                await asyncio.sleep(min(1.5 * attempt, 6.0))

    def plan(self):
        # 按 4MB 固定网格切块，跨线程数可复用同一套断点记录
        size = self.size
        grid = max(GRID, size // max(1, int(self.args.threads) * 8))
        grid = min(max(grid, GRID), 16 * 1024 * 1024)
        segs = []
        i = 0
        s = 0
        while s < size:
            e = min(size, s + grid)
            segs.append((i, s, e))
            s = e
            i += 1
        return segs

    async def run(self):
        resumed = self.prepare()
        if resumed:
            sys.stdout.write("发现 .part 与状态文件，已下载 %s，继续续传\n" % _h(self.done_bytes))
        # 拿元信息：先探一次 META
        await self.probe()
        if self.size is None:
            raise SystemExit("未拿到文件大小，无法规划分片")
        if self.state.data.get("size") != self.size:
            self.state.data["size"] = self.size
            self.state.save()
        segs = self.plan()
        pending = [seg for seg in segs if not self.block_done(seg[1], seg[2])]
        if not pending:
            sys.stdout.write("所有分片已落盘，直接校验\n")
        q = asyncio.Queue()
        for seg in pending:
            q.put_nowait(seg)
        workers = max(1, min(int(self.args.threads), max(1, len(pending))))
        ticker = asyncio.ensure_future(self.ticker())
        tasks = [asyncio.ensure_future(self.worker(q)) for _ in range(workers)]
        try:
            await asyncio.gather(*tasks)
        finally:
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
            self.state.save()
            try:
                self.fh.truncate(self.size)
            except Exception:
                pass
            self.fh.close()
        sys.stdout.write("\n")
        await self.finish()

    async def worker(self, q):
        # 工作协程从队列取分片直到取空
        while True:
            try:
                idx, s, e = q.get_nowait()
            except asyncio.QueueEmpty:
                return
            await self.seg(idx, s, e)

    def block_done(self, s, e):
        # 判断区间是否已完整落盘
        chunks = self.state.data.get("chunks") or {}
        pos = s
        while pos < e:
            n = chunks.get(str(pos))
            if not n:
                return False
            pos += int(n)
        return pos >= e

    async def probe(self):
        # 只发 length=1 的 GET 探测元信息
        ch, w = await dial(self.args.host, self.args.port, self.args.pin, self.args.via_socks, via_tunnel=self.args.via_tunnel)
        try:
            info = await do_auth(ch)
            self.meta.update({"auth": info})
            req = {"spec": dict(self.spec()), "offset": 0, "length": 1}
            await ch.send(FRAME_GET, json.dumps(req, ensure_ascii=False).encode())
            while True:
                ftype, payload = await ch.recv()
                if ftype == FRAME_META:
                    m = json.loads(payload.decode("utf-8"))
                    self.meta.update(m)
                    if m.get("size"):
                        self.size = int(m["size"])
                    if m.get("sha256"):
                        self.state.data["sha256"] = m["sha256"]
                    if not self.size:
                        self.fh.seek(0, 2)
                        self.size = self.fh.tell()
                    return
                if ftype == FRAME_ERR:
                    e = json.loads(payload.decode("utf-8"))
                    raise SystemExit("探测失败 %s %s" % (e.get("code"), e.get("msg")))
                if ftype == FRAME_DATA:
                    continue
        finally:
            try:
                w.close()
            except Exception:
                pass

    async def ticker(self):
        while True:
            self.render()
            await asyncio.sleep(0.5)

    async def finish(self):
        # 校验 sha256 与大小，成功后改名
        size = os.path.getsize(self.part)
        h = hashlib.sha256()
        rd = 0
        with open(self.part, "rb") as f:
            while True:
                buf = f.read(CHUNK)
                if not buf:
                    break
                h.update(buf)
                rd += len(buf)
        local = h.hexdigest()
        want = self.args.sha256 or self.state.data.get("sha256") or self.meta.get("sha256")
        elapsed = max(1e-6, time.time() - self.t0)
        sys.stdout.write("文件: %s\n" % self.out)
        sys.stdout.write("大小: %d 字节\n" % size)
        sys.stdout.write("本地 sha256: %s\n" % local)
        if want:
            sys.stdout.write("期望 sha256: %s\n" % want)
        sys.stdout.write("耗时: %.2fs  平均 %.1f KB/s\n" % (elapsed, rd / elapsed / 1024))
        ok = True
        if want and want != local:
            ok = False
            sys.stdout.write("校验: sha256 不一致\n")
        elif want:
            sys.stdout.write("校验: sha256 一致\n")
        else:
            sys.stdout.write("校验: 无期望值，仅记录\n")
        if ok:
            if os.path.exists(self.out):
                os.remove(self.out)
            os.replace(self.part, self.out)
            if os.path.exists(self.state_path):
                os.remove(self.state_path)
            sys.stdout.write("已完成 -> %s\n" % self.out)
        else:
            sys.stdout.write("未通过校验，保留 %s 供排查\n" % self.part)


def _h(n):
    # 人类可读字节数
    if n is None:
        return "?"
    v = float(n)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if v < 1024 or u == "TB":
            return "%.1f%s" % (v, u) if u != "B" else "%dB" % int(v)
        v /= 1024
    return "%.1fTB" % v


def parse_args():
    ap = argparse.ArgumentParser(description="tgdl 加密回传客户端")
    ap.add_argument("--url", help="HTTP 直链或 tgdl:// 直链")
    ap.add_argument("--uri", help="tgdl:// 直链，由服务端解析")
    ap.add_argument("--spec-file", help="源规格 JSON 文件")
    ap.add_argument("--out", required=True, help="输出文件绝对路径或目录")
    ap.add_argument("--threads", type=int, default=1, help="并行连接数")
    ap.add_argument("--resume", action="store_true", help="从 .part 续传")
    ap.add_argument("--via-tunnel", action="store_true", help="经外部隧道模块出网")
    ap.add_argument("--via-socks", action="store_true",
                    help="经本机 SOCKS5 出口")
    ap.add_argument("--direct", action="store_true",
                    help="强制直连服务端，不经本机代理")
    ap.add_argument("--host", default=SERVER_HOST)
    ap.add_argument("--port", type=int, default=SERVER_PORT)
    ap.add_argument("--pin", default=CERT_PIN, help="服务端证书 SHA256")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--sha256", default="", help="期望的 sha256，用于下载后校验")
    ap.add_argument("--no-autoproxy", action="store_true",
                    help="关闭自动探测/拉起本机 SOCKS5")
    ap.add_argument("--proxy-script", default=AUTOPROXY_SCRIPT,
                    help="本机代理脚本路径，用于自动拉起")
    return ap.parse_args()


def _port_open(host, port, timeout=0.6):
    # 探测本机端口是否在监听
    import socket as _s
    try:
        with _s.create_connection((host, port), timeout):
            return True
    except OSError:
        return False


def ensure_proxy(args):
    """确保本机 SOCKS5 可用；未监听时按需拉起代理脚本，句柄保留不杀。"""
    if not args.via_socks or args.no_autoproxy:
        return None
    if _port_open("127.0.0.1", SOCKS_PORT):
        if args.verbose:
            sys.stderr.write("[代理] 127.0.0.1:%d 已在监听\n" % SOCKS_PORT)
        return None
    script = args.proxy_script
    if not os.path.exists(script):
        sys.stderr.write("[代理] 未监听且脚本不存在：%s\n" % script)
        return None
    import subprocess
    # 独立进程组，脚本退出时不连带结束用户的代理
    kwargs = {"cwd": os.path.dirname(script) or ".", "close_fds": True}
    if os.name == "nt":
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([sys.executable, script], **kwargs)
    sys.stderr.write("[代理] 已拉起 %s pid=%d，等待就绪\n" % (os.path.basename(script), proc.pid))
    for _ in range(30):
        time.sleep(0.2)
        if _port_open("127.0.0.1", SOCKS_PORT):
            sys.stderr.write("[代理] 127.0.0.1:%d 就绪\n" % SOCKS_PORT)
            return proc
    sys.stderr.write("[代理] 等待超时，改走直连\n")
    args.via_socks = False
    return proc


def resolve_out(args):
    # --out 为目录时拼上源文件名
    p = os.path.abspath(args.out)
    if p.endswith(("\\", "/")) or os.path.isdir(p):
        name = "download.bin"
        if args.spec_file:
            try:
                with open(args.spec_file, "r", encoding="utf-8") as f:
                    sp = json.load(f)
                name = sp.get("name") or os.path.basename(sp.get("path") or "") or name
            except Exception:
                pass
        elif args.uri or (args.url and args.url.startswith("tgdl://")):
            # 从 URI 的第 7 段（name_b64）取原始文件名
            u = args.uri or args.url
            try:
                import base64
                fields = u.split("://", 1)[1].split("/")
                if len(fields) == 8 and fields[6]:
                    pad = fields[6] + "=" * (-len(fields[6]) % 4)
                    name = base64.urlsafe_b64decode(pad).decode("utf-8") or name
            except Exception:
                pass
        elif args.url:
            name = args.url.split("?", 1)[0].rstrip("/").rsplit("/", 1)[-1] or name
        p = os.path.join(p, name)
    return p


def main():
    args = parse_args()
    if not args.pin:
        if os.environ.get("TGDL_PIN"):
            args.pin = os.environ["TGDL_PIN"]
        else:
            raise SystemExit("缺少 --pin（服务端启动时打印的证书 SHA256）")
    if args.direct:
        args.via_socks = False
    proxy_proc = ensure_proxy(args)
    args.out = resolve_out(args)
    job = Job(args)
    try:
        asyncio.run(job.run())
    except KeyboardInterrupt:
        sys.stdout.write("\n已中断，可用 --resume 继续\n")
        return 130
    except SystemExit:
        raise
    except Exception as e:
        sys.stdout.write("\n失败: %r\n" % (e,))
        if job.state.path and os.path.exists(job.state.path):
            sys.stdout.write("可用 --resume 继续\n")
        return 1
    finally:
        # 自动拉起的代理保留运行，仅在开启 verbose 时提示句柄
        if proxy_proc is not None and args.verbose:
            sys.stderr.write("\n[代理] 保留运行 pid=%d\n" % proxy_proc.pid)
    return 0


if __name__ == "__main__":
    sys.exit(main())
