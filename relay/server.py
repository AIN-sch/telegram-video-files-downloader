#!/usr/bin/env python3
# tgdl 加密回传服务端：TLS1.3 + PSK 双向认证 + HKDF 会话密钥 + AES-256-GCM 分帧

import argparse
import asyncio
import hashlib
import hmac
import json
import logging
import os
import socket
import ssl
import struct
import sys
import time

import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# 部署参数一律走环境变量，仓库内不放真实值
PSK = os.environ.get("TGDL_PSK", "CHANGE_ME_32_BYTES_OR_LONGER").encode()

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

CLOCK_SKEW = 300
HS_LEN = 56
HS_TIMEOUT = 12.0
IDLE_TIMEOUT = 180.0
TLS_SNI = os.environ.get("TGDL_SNI", "www.microsoft.com")

LOG = logging.getLogger("tgdl")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 让 fetcher 与其依赖（mtproto/、spec/）可被普通 import 找到
for _p in (os.path.join(BASE_DIR, "mtproto"), os.path.join(BASE_DIR, "spec"), BASE_DIR):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)
FETCHER = None


# 口令认证

def _tag(ts, nonce, extra=b""):
    # PSK 对 时间戳+随机数 做 HMAC-SHA256
    return hmac.new(PSK, b"relay-v1|" + struct.pack("!Q", ts) + b"|" + nonce + extra,
                    hashlib.sha256).digest()


def derive_keys(cnonce, snonce):
    # 由 PSK 与双端随机数派生 双向密钥 与 IV 基值
    okm = HKDF(algorithm=hashes.SHA256(), length=76,
               salt=cnonce + snonce, info=b"tgdl-v1").derive(PSK)
    return okm[:32], okm[32:64], okm[64:76]


async def server_handshake(reader, writer):
    # 客户端报 随机数|时间戳|HMAC，服务端回 随机数|时间戳|HMAC（含客户端随机数）
    raw = await asyncio.wait_for(reader.readexactly(HS_LEN), HS_TIMEOUT)
    cnonce = raw[:16]
    ts, = struct.unpack("!Q", raw[16:24])
    if not hmac.compare_digest(raw[24:56], _tag(ts, cnonce)):
        raise ConnectionError("客户端认证失败")
    if abs(time.time() - ts) > CLOCK_SKEW:
        raise ConnectionError("客户端时间戳偏移过大")
    snonce = os.urandom(16)
    sts = int(time.time())
    writer.write(snonce + struct.pack("!Q", sts) + _tag(sts, snonce, cnonce))
    await writer.drain()
    return derive_keys(cnonce, snonce)


# 加密分帧

class ProtocolError(Exception):
    pass


class Channel:
    # 单条连接上的加密帧收发，双向密钥与序号各自独立
    def __init__(self, reader, writer, k_tx, k_rx, iv):
        self.reader = reader
        self.writer = writer
        self.aead_tx = AESGCM(k_tx)
        self.aead_rx = AESGCM(k_rx)
        self.iv = iv
        self.seq_tx = 0
        self.seq_rx = 0
        self.wlock = asyncio.Lock()

    def _nonce(self, seq):
        # GCM 随机数 = IV 前 4 字节 + 序号，同密钥下唯一
        return self.iv[:4] + struct.pack("!Q", seq)

    async def send(self, ftype, payload=b""):
        if len(payload) > MAX_BODY:
            raise ProtocolError("发送载荷超限")
        async with self.wlock:
            seq = self.seq_tx
            self.seq_tx += 1
            head = MAGIC + struct.pack("!QBI", seq, ftype, len(payload))
            self.writer.write(head + self.aead_tx.encrypt(self._nonce(seq), payload, head))
            await self.writer.drain()

    async def recv(self, timeout=None):
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


# 限速

class RateLimiter:
    def __init__(self, kbps):
        # kbps 按 KB/s 解释，换算为字节/秒
        self.bps = max(0, int(kbps)) * 1024
        self.t0 = time.monotonic()
        self.sent = 0

    async def take(self, n):
        if not self.bps:
            return
        self.sent += n
        delay = self.t0 + self.sent / self.bps - time.monotonic()
        if delay > 0:
            await asyncio.sleep(delay)


# 源适配层

def probe_fetcher():
    # 探测 mtproto 下载器是否就位
    global FETCHER
    for name in ("fetcher", "mtproto.fetcher"):
        try:
            mod = __import__(name, fromlist=["open_source"])
            if hasattr(mod, "open_source"):
                FETCHER = mod
                return True
        except Exception as e:
            LOG.info("fetcher(%s) 导入失败 %s", name, e)
    return False


def keys_summary():
    # 读取 keys.json 的 DC 数量，不触碰任何密钥内容
    p = os.path.join(BASE_DIR, "keys.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            d = json.load(f)
        dcs = d.get("dcs") or []
        return len(dcs)
    except Exception as e:
        LOG.info("keys.json 解析失败 %s", e)
        return 0


def uri_to_spec(uri):
    # tgdl:// 转 spec，优先复用 fetcher 自带的解析实现
    if FETCHER is not None and hasattr(FETCHER, "uri_to_spec"):
        return FETCHER.uri_to_spec(uri)
    for name in ("tgdl_uri", "spec.tgdl_uri"):
        try:
            mod = __import__(name, fromlist=["to_source_spec"])
            return mod.to_source_spec(uri)
        except Exception:
            continue
    raise ValueError("缺少 tgdl:// 解析器")


async def open_source(spec, start_offset=0, length=None):
    """按规格打开数据源，返回 (meta, 异步字节迭代器)。"""
    kind = (spec.get("kind") or "http").lower()
    if kind == "mtproto":
        if FETCHER is None:
            raise LookupError("no_fetcher")
        return await FETCHER.open_source(spec, start_offset, length)
    if kind == "http" and (spec.get("url") or "").startswith("tgdl://"):
        # 直接传 tgdl:// 时按 MTProto 处理
        if FETCHER is None:
            raise LookupError("no_fetcher")
        return await FETCHER.open_source(uri_to_spec(spec["url"]), start_offset, length)
    if kind == "file":
        return _open_file(spec, start_offset, length)
    if kind == "http":
        return await _open_http(spec, start_offset, length)
    raise ValueError("不支持的源类型 %s" % kind)


def _url_name(url):
    path = url.split("?", 1)[0].rstrip("/")
    return path.rsplit("/", 1)[-1] or "download.bin"


def _bound(spec, start, length, total):
    # 计算实际结束位置
    if length is not None:
        return min(total, start + int(length)) if total is not None else start + int(length)
    end = spec.get("end")
    if end is not None:
        return min(int(end), total) if total is not None else int(end)
    return total


async def _open_http(spec, start_offset, length):
    # HTTP 源：流式读取，支持 Range 续传与重定向跟随
    url = spec["url"]
    offset = int(start_offset or 0)
    chunk = min(int(spec.get("chunk") or MAX_DATA), MAX_DATA)
    hdrs = {"User-Agent": spec.get("ua") or "tgdl/1.0", "Accept": "*/*",
            "Accept-Encoding": "identity"}
    if offset or length:
        # 按 RFC 7233 组装 Range 头：起点-终点，缺终点表示到文件尾
        if length:
            hdrs["Range"] = "bytes=%d-%d" % (offset, offset + int(length) - 1)
        elif offset:
            hdrs["Range"] = "bytes=%d-" % offset
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=25, sock_read=180)
    sess = aiohttp.ClientSession(timeout=timeout)
    try:
        resp = await sess.get(url, headers=hdrs, allow_redirects=True, max_redirects=10)
    except Exception as e:
        await sess.close()
        raise ConnectionError("源连接失败 %s" % e)

    if resp.status == 416:
        resp.release()
        await sess.close()
        raise ValueError("区间不可满足 offset=%d" % offset)
    if resp.status not in (200, 206):
        code = resp.status
        resp.release()
        await sess.close()
        raise ValueError("源返回 HTTP %d" % code)

    total = None
    cr = resp.headers.get("Content-Range")
    clen = resp.headers.get("Content-Length")
    if cr and "/" in cr:
        seg = cr.rsplit("/", 1)[1].strip()
        if seg.isdigit():
            total = int(seg)
    if total is None and clen and clen.isdigit():
        total = offset + int(clen) if resp.status == 206 else int(clen)
    # 源忽略 Range 返回整体时，流内跳过已下载字节而不掉线
    skip = offset if (offset and resp.status == 200) else 0
    if skip and total is not None and skip >= total:
        resp.release()
        await sess.close()
        raise ValueError("区间超出源长度 offset=%d" % offset)

    stop = _bound(spec, offset, length, total)
    need = None if stop is None else max(0, stop - offset)

    async def _iter():
        left = skip
        while left > 0:
            buf = await resp.content.read(min(chunk, left))
            if not buf:
                break
            left -= len(buf)
        left = need
        try:
            while True:
                want = chunk if left is None else min(chunk, left)
                if want <= 0:
                    break
                buf = await resp.content.read(want)
                if not buf:
                    break
                if left is not None:
                    left -= len(buf)
                yield buf
        finally:
            resp.release()
            await sess.close()

    meta = {"kind": "http", "name": spec.get("name") or _url_name(url),
            "size": total, "sha256": spec.get("sha256"), "status": resp.status,
            "skip": skip, "final_url": str(resp.url)}
    return meta, _iter()


def _open_file(spec, start_offset, length):
    # 本地文件源：按 offset 直接定位读取
    path = spec["path"]
    offset = int(start_offset or 0)
    total = os.path.getsize(path)
    chunk = min(int(spec.get("chunk") or MAX_DATA), MAX_DATA)
    stop = _bound(spec, offset, length, total)

    async def _iter():
        left = max(0, stop - offset)
        f = open(path, "rb")
        try:
            f.seek(offset)
            while left > 0:
                buf = f.read(min(chunk, left))
                if not buf:
                    break
                left -= len(buf)
                yield buf
        finally:
            f.close()

    meta = {"kind": "file", "name": os.path.basename(path), "size": total,
            "sha256": spec.get("sha256"), "status": 200, "final_url": path}
    return meta, _iter()


# GET 处理

async def send_err(ch, code, msg):
    await ch.send(FRAME_ERR, json.dumps({"code": code, "msg": msg},
                                        ensure_ascii=False).encode())


def parse_get(payload):
    # 支持 {"spec":{...},"offset":N,"length":M}、扁平写法、以及 {"uri":"tgdl://..."}
    obj = json.loads(payload.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("规格不是对象")
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        spec = dict(obj)
        spec.pop("offset", None)
        spec.pop("length", None)
    uri = obj.get("uri") or spec.pop("uri", None)
    if uri:
        # tgdl:// 直接交给解析器，避免逐字段手工搬运
        spec = uri_to_spec(uri)
    offset = int(obj.get("offset") or (obj.get("spec") or {}).get("offset") or 0)
    length = obj.get("length")
    if length is None:
        length = (obj.get("spec") or {}).get("length")
    length = int(length) if length is not None else None
    return spec, offset, length


async def handle_get(ch, payload, default_rate):
    # 单个 GET：回 META → 按 offset 顺序推 DATA → DONE；断线返回 False
    try:
        spec, offset, length = parse_get(payload)
    except LookupError:
        await send_err(ch, "no_fetcher", "mtproto 下载器未部署")
        return True
    except Exception as e:
        await send_err(ch, "bad_spec", "规格解析失败 %s" % e)
        return True

    rate = RateLimiter(int(spec.get("rate_kbps") or default_rate or 0))
    try:
        meta, gen = await open_source(spec, offset, length)
    except LookupError:
        await send_err(ch, "no_fetcher", "mtproto 下载器未部署")
        return True
    except Exception as e:
        await send_err(ch, "open_fail", "%s: %s" % (type(e).__name__, e))
        return True

    # spec.size 为 0 时用 meta 回填，先发 META 再流式推 DATA
    total = meta.get("size")
    if not spec.get("size") and total:
        spec["size"] = total
    stop = _bound(spec, offset, length, total)
    meta_out = dict(meta)
    meta_out.update({"offset": offset, "stop": stop})
    await ch.send(FRAME_META, json.dumps(meta_out, ensure_ascii=False).encode())

    pos = offset
    sent = 0
    started = time.monotonic()
    try:
        async for buf in gen:
            if stop is not None and pos + len(buf) > stop:
                buf = buf[:max(0, stop - pos)]
            if not buf:
                break
            # 单块超过帧上限时按 256KB 切分，保持 offset 严格递增
            for i in range(0, len(buf), MAX_DATA):
                part = buf[i:i + MAX_DATA]
                if stop is not None and pos + len(part) > stop:
                    part = part[:max(0, stop - pos)]
                if not part:
                    break
                await ch.send(FRAME_DATA, struct.pack("!Q", pos) + part)
                pos += len(part)
                sent += len(part)
                await rate.take(len(part))
    except (asyncio.IncompleteReadError, ConnectionError, ProtocolError,
            ConnectionResetError, BrokenPipeError, OSError):
        LOG.warning("会话中断 pos=%d", pos)
        return False

    elapsed = max(1e-6, time.monotonic() - started)
    await ch.send(FRAME_DONE, json.dumps({
        "size": pos, "bytes": sent, "sha256": meta.get("sha256"),
        "seconds": round(elapsed, 3), "kbps": round(sent / elapsed / 1024, 1),
    }, ensure_ascii=False).encode())
    LOG.info("完成 %s pos=%d %.1fKB/s", meta_out.get("name"), pos, sent / elapsed / 1024)
    return True


# 连接处理

def tune_socket(sock):
    # 加大收发缓冲并启用保活
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8388608)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8388608)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except OSError:
        pass


class Server:
    def __init__(self, cfg, pin=""):
        self.cfg = cfg
        self.pin = pin

    async def handle(self, reader, writer):
        peer = writer.get_extra_info("peername")
        try:
            tune_socket(writer.get_extra_info("socket"))
            k_c2s, k_s2c, iv = await server_handshake(reader, writer)
        except Exception as e:
            LOG.info("握手失败 %s %s", peer, e)
            writer.close()
            return
        ch = Channel(reader, writer, k_s2c, k_c2s, iv)
        LOG.info("已认证 %s", peer)
        try:
            while True:
                try:
                    ftype, payload = await ch.recv(timeout=IDLE_TIMEOUT)
                except asyncio.TimeoutError:
                    # 对端长时间无请求，回收连接避免协程堆积
                    LOG.info("空闲超时，关闭 %s", peer)
                    break
                if ftype == FRAME_AUTH:
                    await ch.send(FRAME_AUTH, json.dumps(
                        {"ok": True, "v": 1, "pin": self.pin,
                         "tls": writer.get_extra_info("ssl_object").version(),
                         "mtproto": FETCHER is not None}).encode())
                elif ftype == FRAME_PING:
                    await ch.send(FRAME_PING, payload)
                elif ftype == FRAME_GET:
                    if not await handle_get(ch, payload, self.cfg.rate_kbps):
                        break
                else:
                    await send_err(ch, "bad_type", "未知帧类型 %d" % ftype)
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except ProtocolError as e:
            LOG.warning("协议错误 %s %s", peer, e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            LOG.warning("会话异常 %s %r", peer, e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def serve(self):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.cfg.cert, self.cfg.key)
        ctx.set_alpn_protocols(["tgdl/1"])
        srv = await asyncio.start_server(self.handle, self.cfg.listen_host,
                                         self.cfg.listen_port, backlog=128,
                                         limit=1 << 20, ssl=ctx)
        for s in srv.sockets:
            LOG.warning("监听 %s:%d (TLS1.3 only)", s.getsockname()[0], s.getsockname()[1])
        return srv


def cert_pin(path):
    # 取证书 DER 的 SHA256，供客户端固定
    with open(path) as f:
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="0.0.0.0:8443")
    ap.add_argument("--cert", default=os.path.join(BASE_DIR, "cert.pem"))
    ap.add_argument("--key", default=os.path.join(BASE_DIR, "key.pem"))
    ap.add_argument("--rate-kbps", type=int, default=0)
    ap.add_argument("--print-pin", action="store_true")
    cfg = ap.parse_args()
    host, _, port = cfg.listen.rpartition(":")
    cfg.listen_host = host or "0.0.0.0"
    cfg.listen_port = int(port)

    if cfg.print_pin:
        print(cert_pin(cfg.cert))
        return

    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    pin = cert_pin(cfg.cert)
    LOG.warning("证书 SHA256 = %s", pin)
    if probe_fetcher():
        LOG.warning("mtproto available=True（fetcher 已加载）")
    else:
        LOG.warning("mtproto available=False（仅 http/file 模式）")
    ndc = keys_summary()
    if ndc is None:
        LOG.warning("keys.json 缺失")
    else:
        LOG.warning("mtproto keys: %d dcs", ndc)

    async def run():
        srv = await Server(cfg, pin).serve()
        async with srv:
            await srv.serve_forever()

    try:
        asyncio.run(run())
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("已停止")


if __name__ == "__main__":
    main()
