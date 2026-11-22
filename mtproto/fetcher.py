# 下载执行层：按 spec 分块拉取落盘，支持区间起始、断点续传、分片
import asyncio
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mtp_client as C

CHUNK = 512 * 1024
ALIGN = 4096


def load_tgdl():
    # 延迟加载 tgdl_uri，保持单一权威实现
    spec_dir = os.path.abspath(os.path.join(HERE, '..', 'spec'))
    if spec_dir not in sys.path:
        sys.path.insert(0, spec_dir)
    import tgdl_uri
    return tgdl_uri


async def resolve_uri(uri):
    # tgdl:// -> fetcher 规格
    return uri_to_spec(uri)


def spec_to_uri(kind, dc, location, file_reference, size, name, mime, thumb_size=None):
    # 规格 -> tgdl:// 字符串，kind 语义值映射为 tgdl 单字符
    kind_map = {'document': 'd', 'video': 'd', 'audio': 'd',
                'photo': 'p', 'webFile': 'w', 'photoStripped': 'm'}
    code = kind_map.get(kind, kind)
    loc = dict(location)
    if code == 'p':
        # p 分支布局：id + access_hash + thumb_size
        loc = {
            'id': loc['id'],
            'access_hash': loc['access_hash'],
            'thumb_size': thumb_size or loc.get('thumb_size') or 'y',
        }
    payload = {
        'kind': code, 'dc': dc, 'location': loc,
        'file_reference': file_reference, 'size': size, 'name': name, 'mime': mime,
    }
    return load_tgdl().encode(payload)


def uri_to_spec(uri):
    # tgdl:// -> open_source 的 spec，补齐 loc_type 供 InputFileLocation 选择
    raw = load_tgdl().decode(uri)
    src = load_tgdl().to_source_spec(uri)
    loc = dict(src['location'])
    if raw['kind'] == 'p':
        src['loc_type'] = 'p'
        src['thumb_size'] = loc.get('thumb_size') or 'y'
    elif raw['kind'] == 'w':
        src['loc_type'] = 'w'
    else:
        src['loc_type'] = 'd'
    src['location'] = loc
    return src


class _FileSource(object):
    # 异步分块迭代器：按 offset 顺序产 bytes，可实现 __aiter__
    def __init__(self, client, spec, start_offset, length, size, progress=None):
        self.client = client
        self.spec = spec
        self.offset = start_offset
        self.remaining = length if length is not None else max(0, size - start_offset)
        self.progress = progress or (lambda *a: None)

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.remaining <= 0:
            raise StopAsyncIteration
        want = min(CHUNK, self.remaining)
        # upload.getFile 要求 offset 4KB 对齐且 limit 4KB 倍数
        aligned = (self.offset % ALIGN) == 0
        if not aligned:
            base = self.offset - (self.offset % ALIGN)
            data = await C.get_file_chunk(self.client, self.spec, base, CHUNK)
            skip = self.offset - base
            data = data[skip:skip + want]
        else:
            data = await C.get_file_chunk(self.client, self.spec, self.offset, want)
        if not data:
            raise StopAsyncIteration
        self.offset += len(data)
        self.remaining -= len(data)
        self.progress(len(data))
        return data


async def open_source(spec, start_offset=0, length=None, proxy=None, log=None):
    # 打开一个数据源，返回 (meta, 异步迭代器)
    kind = spec.get('kind', 'mtproto')
    if kind != 'mtproto':
        raise ValueError('不支持的 source kind: %r' % kind)
    dc = spec['dc']
    size = spec.get('size') or 0
    if length is None and size:
        length = max(0, size - start_offset)
    client = await C.open_client(dc_id=dc, proxy=proxy, log=log)
    meta = {
        'size': size,
        'mime': spec.get('mime') or '',
        'name': spec.get('name') or '',
        'dc': dc,
        'kind': kind,
    }
    return meta, _FileSource(client, spec, start_offset, length, size)


async def download_spec(spec, out_path, proxy=None, threads=1, log=print, resume=True):
    # 按 spec 下载到 out_path，写 .part 与 .state.json，支持断点续传与多连接分片
    size = int(spec.get('size') or 0)
    state_path = out_path + '.state.json'
    part_path = out_path + '.part'
    os.makedirs(os.path.dirname(os.path.abspath(out_path)) or '.', exist_ok=True)

    state = {'size': size, 'chunk': CHUNK, 'done': [], 'spec_hash': _spec_hash(spec)}
    if resume and os.path.exists(state_path) and os.path.exists(part_path):
        try:
            old = json.load(open(state_path, 'r', encoding='utf-8'))
            if old.get('spec_hash') == state['spec_hash'] and old.get('size') == size:
                state = old
                log('[dl] 续传：已完成 %d 块' % len(state['done']))
        except Exception:
            pass

    total_chunks = (size + CHUNK - 1) // CHUNK if size else 0
    done = set(int(x) for x in state['done'])
    todo = [i for i in range(total_chunks) if i not in done]
    log('[dl] 总块数 %d，待下载 %d，线程 %d' % (total_chunks, len(todo), threads))

    mode = 'r+b' if os.path.exists(part_path) else 'wb'
    with open(part_path, mode) as f:
        f.truncate(size)
        if size == 0:
            f.truncate(0)

    lock = asyncio.Lock()
    written = [0]

    async def worker(queue):
        while True:
            try:
                idx = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            offset = idx * CHUNK
            want = min(CHUNK, size - offset)
            client = await C.open_client(dc_id=spec['dc'], proxy=proxy, log=None)
            try:
                data = bytearray()
                got = 0
                while got < want:
                    limit = min(CHUNK, want - got)
                    piece = await C.get_file_chunk(client, spec, offset + got, limit)
                    if not piece:
                        break
                    data += piece
                    got += len(piece)
                if len(data) != want:
                    log('[dl] 块 %d 长度不足 %d/%d，重试一次' % (idx, len(data), want))
                    data = bytearray()
                    got = 0
                    while got < want:
                        limit = min(CHUNK, want - got)
                        piece = await C.get_file_chunk(client, spec, offset + got, limit)
                        if not piece:
                            break
                        data += piece
                        got += len(piece)
            finally:
                await client.close()
            async with lock:
                with open(part_path, 'r+b') as f:
                    f.seek(offset)
                    f.write(data)
                done.add(idx)
                written[0] += len(data)
                state['done'] = sorted(done)
                with open(state_path, 'w', encoding='utf-8') as sf:
                    json.dump(state, sf)
                log('[dl] 块 %d/%d 完成 %d 字节  累计 %d/%d (%.1f%%)' % (
                    idx + 1, total_chunks, len(data), written[0], size,
                    100.0 * (len(done) / total_chunks) if total_chunks else 100.0))

    queue = asyncio.Queue()
    for i in todo:
        queue.put_nowait(i)
    await asyncio.gather(*[worker(queue) for _ in range(max(1, threads))])

    os.replace(part_path, out_path)
    if os.path.exists(state_path):
        os.remove(state_path)
    sha = hashlib.sha256()
    with open(out_path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            sha.update(block)
    return {'path': out_path, 'size': os.path.getsize(out_path), 'sha256': sha.hexdigest()}


def _spec_hash(spec):
    h = hashlib.sha256()
    h.update(str(spec.get('dc')).encode())
    h.update(json.dumps(spec.get('location'), sort_keys=True).encode())
    h.update(str(spec.get('file_reference')).encode())
    h.update(str(spec.get('size')).encode())
    return h.hexdigest()[:16]
