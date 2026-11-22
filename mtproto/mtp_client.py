# MTProto 客户端：layer 协商、TL 调用、t.me 解析、upload.getFile 取块
import asyncio
import hashlib
import json
import os
import struct
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import crypto
import mtp_transport as T
import tl_schema

BUILD_DIR = os.path.abspath(os.path.join(HERE, '..'))


def _find_keys():
    # 依次尝试部署布局：mtproto/../keys.json、mtproto/../tdata/keys.json
    for p in (os.path.join(BUILD_DIR, 'keys.json'),
              os.path.join(BUILD_DIR, 'tdata', 'keys.json'),
              os.path.join(HERE, 'keys.json')):
        if os.path.exists(p):
            return p
    return os.path.join(BUILD_DIR, 'tdata', 'keys.json')


KEYS_PATH = _find_keys()
LAYER_CACHE = os.path.join(HERE, 'layer.json')
DCOPT_CACHE = os.path.join(HERE, 'dc_options.json')
DEBUG_DIR = os.path.join(HERE, 'debug')

CHUNK_SIZE = 512 * 1024
MIN_CHUNK = 4096
# 实测 upload.getFile 的 limit 上限，1048576 可用而 2097152 被拒
MAX_LIMIT = 1048576

# api.tl 内注释标注的 layer，需与 schema 严格一致
SCHEMA_LAYER = 233

_classes = None
_by_name = None


def schema():
    global _classes, _by_name
    if _classes is None:
        _classes, _by_name = tl_schema.load_schema(os.path.join(HERE, 'ref', 'api.tl'))
    return _classes, _by_name


def load_keys(path=None):
    with open(path or KEYS_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def key_for_dc(dc_id):
    # 取指定 DC 的 auth_key，缺失返回 None
    data = load_keys()
    for d in data['dcs']:
        if d['dc'] == dc_id:
            return bytes.fromhex(d['key'])
    return None


def dc_candidates(dc_id):
    # 返回该 DC 的候选 [(ip, port)]，IPv4 优先，跳过 IPv6
    out = []
    if os.path.exists(DCOPT_CACHE):
        try:
            opt = json.load(open(DCOPT_CACHE, 'r', encoding='utf-8'))
            for d in opt.get('options', []):
                if d['id'] != dc_id or d.get('cdn'):
                    continue
                ip = d.get('ip') or ''
                if ':' in ip:
                    continue
                item = (ip, d.get('port') or 443)
                if item not in out:
                    out.append(item)
        except Exception:
            pass
    data = load_keys()
    for d in data['dcs']:
        if d['dc'] == dc_id:
            item = (d['ip'], d['port'])
            if item not in out:
                out.append(item)
    if not out:
        raise KeyError('无 dc%d 地址' % dc_id)
    return out


def dc_address(dc_id):
    # 取该 DC 首选 IPv4 地址
    return dc_candidates(dc_id)[0]


def ctor_id(name):
    _c, by = schema()
    ids = by.get(name)
    if not ids:
        raise KeyError('schema 无构造 %s' % name)
    return ids[0]


def _migrate_dc(message):
    # 从 USER_MIGRATE_5 / PHONE_MIGRATE_5 / NETWORK_MIGRATE_5 提取目标 DC
    import re
    if not message:
        return None
    m = re.match(r'^[A-Z_]*MIGRATE_(-?\d+)$', message.strip())
    if not m:
        return None
    return abs(int(m.group(1)))


class TelegramClient(object):
    # 单 DC 的 MTProto 会话封装
    def __init__(self, auth_key, dc_id, host, port, proxy=None, log=None, layer=None):
        self.auth_key = auth_key
        self.dc_id = dc_id
        self.proxy = proxy
        self.conn = T.MtprotoConnection(auth_key, dc_id, host, port, proxy=proxy, log=log)
        self.classes, self.by_name = schema()
        self.layer = layer or 181
        self.inited = False
        self.log = log or (lambda *a, **k: None)

    async def close(self):
        await self.conn.close()

    def _writer(self):
        return tl_schema.TLWriter(self.classes, self.by_name)

    async def raw_call(self, method, args):
        w = self._writer()
        w.write_obj((method, args))
        try:
            return await self.conn.call(bytes(w.buf), timeout=40)
        except T.MtprotoError as e:
            # X_MIGRATE_N：该调用需在目标 DC 执行，切 DC 后重试一次
            # FILE_MIGRATE 由 get_file_chunk 统一处理，避免在此处重复切换
            dc = _migrate_dc(e.message)
            if not dc or dc == self.dc_id or '_MIGRATE_' in e.message and e.message.startswith('FILE'):
                raise
            await self.migrate_to(dc)
            w = self._writer()
            w.write_obj((method, args))
            return await self.conn.call(bytes(w.buf), timeout=40)

    async def migrate_to(self, dc_id):
        # 切换到目标 DC，保留 layer
        auth_key = key_for_dc(dc_id)
        if not auth_key:
            raise KeyError('迁移目标 dc%d 无 auth_key' % dc_id)
        old = self.conn
        last = None
        for ip, port in dc_candidates(dc_id):
            try:
                conn = T.MtprotoConnection(auth_key, dc_id, ip, port,
                                           proxy=self.proxy, log=self.log)
                await conn.connect()
                self.conn = conn
                self.dc_id = dc_id
                self.auth_key = auth_key
                await self.init(self.layer)
                await old.close()
                self.log('[mtp] 已迁移到 dc%d %s:%d' % (dc_id, ip, port))
                return
            except Exception as e:
                last = e
                try:
                    await conn.close()
                except Exception:
                    pass
        raise IOError('迁移到 dc%d 失败: %s' % (dc_id, last))

    async def init(self, layer=None):
        # invokeWithLayer + initConnection 包裹 help.getConfig，完成 layer 协商
        if layer:
            self.layer = layer
        w = self._writer()
        w.uint(T.INVOKE_WITH_LAYER)
        w.int_(self.layer)
        w.uint(T.INIT_CONNECTION)
        w.uint(0)
        w.int_(T.TDESKTOP_API_ID)
        w.string_('tgdl')
        w.string_('Linux')
        w.string_('1.0')
        w.string_('zh-cn')
        w.string_('')
        w.string_('zh')
        w.write_obj(('help.getConfig', {}))
        resp = await self.conn.call(bytes(w.buf), timeout=40)
        self.inited = True
        return resp

    def parse(self, data):
        r = tl_schema.TLReader(data, self.classes, self.by_name)
        obj = r.read_obj()
        return obj, r.pos

    def config_ok(self, data):
        # 判定 config 是否能用当前 schema 干净解析
        try:
            obj, pos = self.parse(data)
        except Exception:
            return None
        if obj.get('_') != 'config' or pos != len(data):
            return None
        opts = obj.get('dc_options') or []
        date = obj.get('date') or 0
        if not (0 < len(opts) <= 300):
            return None
        if abs(time.time() - date) > 86400 * 400:
            return None
        return obj


async def negotiate(proxy=None, log=print, dc_id=None, force_layer=None):
    # 逐个候选 layer 试探，找能干净解析 config 的层
    keys = load_keys()
    dc_id = dc_id or keys['mainDc']
    ip, port = dc_address(dc_id)
    auth_key = key_for_dc(dc_id)
    if not auth_key:
        raise SystemExit('keys.json 缺少 dc%d 密钥' % dc_id)
    candidates = [force_layer] if force_layer else [SCHEMA_LAYER]
    last_err = None
    for layer in candidates:
        client = TelegramClient(auth_key, dc_id, ip, port, proxy=proxy, log=log, layer=layer)
        try:
            await client.conn.connect()
            resp = await client.init(layer)
            obj = client.config_ok(resp)
            if obj:
                log('[layer] 协商成功 layer=%d dc_options=%d' % (
                    layer, len(obj.get('dc_options') or [])))
                opts = []
                for d in obj['dc_options']:
                    opts.append({
                        'id': d.get('id'),
                        'ip': d.get('ip_address'),
                        'port': d.get('port'),
                        'cdn': bool((d.get('flags') or 0) >> 3 & 1),
                        'media_only': bool((d.get('flags') or 0) >> 1 & 1),
                    })
                if opts:
                    with open(DCOPT_CACHE, 'w', encoding='utf-8') as f:
                        json.dump({'layer': layer, 'this_dc': obj.get('this_dc'),
                                   'webfile_dc_id': obj.get('webfile_dc_id'),
                                   'options': opts}, f, indent=2)
                with open(LAYER_CACHE, 'w', encoding='utf-8') as f:
                    json.dump({'layer': layer}, f)
                await client.close()
                return layer, obj
            log('[layer] %d 解析失败，继续' % layer)
            await client.close()
        except Exception as e:
            last_err = e
            log('[layer] %d 异常 %s' % (layer, e))
            try:
                await client.close()
            except Exception:
                pass
    raise SystemExit('layer 协商失败，最后错误: %s' % last_err)


def cached_layer():
    if os.path.exists(LAYER_CACHE):
        try:
            return json.load(open(LAYER_CACHE, 'r', encoding='utf-8'))['layer']
        except Exception:
            return None
    return None


async def open_client(dc_id=None, proxy=None, log=None, layer=None):
    # 打开到指定 DC 的已初始化客户端；候选地址逐个尝试
    keys = load_keys()
    dc_id = dc_id or keys['mainDc']
    auth_key = key_for_dc(dc_id)
    if not auth_key:
        raise KeyError('无 dc%d 的 auth_key' % dc_id)
    layer = layer or cached_layer()
    if not layer:
        layer, _ = await negotiate(proxy=proxy, log=log or (lambda *a: None))
    last = None
    for round_ in (0, 1):
        for ip, port in dc_candidates(dc_id):
            client = TelegramClient(auth_key, dc_id, ip, port, proxy=proxy, log=log, layer=layer)
            try:
                await client.conn.connect()
                await client.init(layer)
                return client
            except Exception as e:
                last = e
                try:
                    await client.close()
                except Exception:
                    pass
        if round_ == 0:
            # 首轮全失败：重新协商地址，成功才写缓存，失败保留原文件
            try:
                layer, _ = await negotiate(proxy=proxy, log=log or (lambda *a: None))
                if log:
                    log('[dc] 地址已刷新，重试 dc%d' % dc_id)
            except Exception as e:
                last = e
                break
    raise IOError('dc%d 全部候选地址连接失败: %s' % (dc_id, last))


def _peer_from_obj(obj):
    # 从 TL 对象里提取 peer 标识
    name = obj.get('_')
    if name == 'peerChannel':
        return ('channel', obj['channel_id'])
    if name == 'peerChat':
        return ('chat', obj['chat_id'])
    if name == 'peerUser':
        return ('user', obj['user_id'])
    return (None, None)


def _find_in_lists(obj, ctor, key='id'):
    for k in ('chats', 'users', 'messages'):
        for it in (obj.get(k) or []):
            if it.get('_') == ctor:
                return it
    return None


async def resolve_channel(client, link):
    # 解析 t.me 链接为 (channel_id, access_hash, message_id)
    import re
    text = link.strip()
    m = re.search(r't\.me/(?:s/)?c/(\d+)(?:/(\d+))?', text)
    if m:
        channel_id = int(m.group(1))
        msg_id = int(m.group(2)) if m.group(2) else None
        ah = await find_access_hash(client, channel_id)
        return channel_id, ah, msg_id
    m = re.search(r't\.me/(?:s/)?([A-Za-z0-9_]{3,})(?:/(\d+))?', text)
    if not m:
        raise ValueError('无法识别的 t.me 链接: %s' % text)
    username = m.group(1)
    msg_id = int(m.group(2)) if m.group(2) else None
    resp = await client.raw_call('contacts.resolveUsername', {'username': username})
    obj, _ = client.parse(resp)
    ch = _find_in_lists(obj, 'channel')
    if ch:
        return ch['id'], ch.get('access_hash'), msg_id
    raise ValueError('用户名 %s 未解析到频道' % username)


async def find_access_hash(client, channel_id):
    # 在会话列表里找频道 access_hash（/c/ 链接必须已在会话中）
    offset_peer = {'_': 'inputPeerEmpty'}
    offset_id = 0
    for _ in range(20):
        resp = await client.raw_call('messages.getDialogs', {
            'offset_date': 0, 'offset_id': offset_id, 'offset_peer': offset_peer,
            'limit': 100, 'hash': 0,
        })
        obj, _ = client.parse(resp)
        for ch in (obj.get('chats') or []):
            if ch.get('id') == channel_id and ch.get('_') == 'channel':
                return ch.get('access_hash')
        msgs = obj.get('messages') or []
        if len(msgs) < 100:
            break
        offset_id = msgs[-1].get('id') or 0
        if not offset_id:
            break
    # 会话列表没有时，按裸 ID 直接问一次服务器
    try:
        resp = await client.raw_call('channels.getChannels', {
            'id': [('inputChannel', {'channel_id': channel_id, 'access_hash': 0})],
        })
        obj, _ = client.parse(resp)
        for ch in (obj.get('chats') or []):
            if ch.get('id') == channel_id and ch.get('_') == 'channel':
                return ch.get('access_hash')
    except Exception:
        pass
    raise ValueError('会话列表未找到频道 %d（需已加入该频道）' % channel_id)


async def get_message(client, channel_id, access_hash, msg_id):
    resp = await client.raw_call('channels.getMessages', {
        'channel': ('inputChannel', {'channel_id': channel_id, 'access_hash': access_hash}),
        'id': [('inputMessageID', {'id': msg_id})],
    })
    obj, _ = client.parse(resp)
    msgs = obj.get('messages') or []
    if not msgs:
        raise ValueError('消息不存在')
    return msgs[0], obj


def extract_media(msg, layer_obj=None):
    # 从 message 提取可下载媒体规格
    media = msg.get('media')
    if not media:
        return None
    kind = media.get('_')
    if kind == 'messageMediaDocument':
        doc = media.get('document')
        if not doc:
            return None
        attrs = doc.get('attributes') or []
        name = ''
        is_video = False
        is_audio = False
        w = h = 0
        duration = 0
        for a in attrs:
            if a.get('_') == 'documentAttributeFilename':
                name = a.get('file_name') or ''
            elif a.get('_') == 'documentAttributeVideo':
                is_video = True
                w, h = a.get('w') or 0, a.get('h') or 0
                duration = a.get('duration') or 0
            elif a.get('_') == 'documentAttributeAudio':
                is_audio = True
        mime = doc.get('mime_type') or ''
        if not name:
            ext = mime.split('/')[-1] if '/' in mime else 'bin'
            name = 'doc_%d.%s' % (doc.get('id'), ext)
        kind_out = 'video' if is_video else ('audio' if is_audio else 'document')
        return {
            'kind': kind_out,
            'dc': doc.get('dc_id'),
            'location': {
                'volume_id': 0,
                'local_id': 0,
                'id': doc.get('id'),
                'access_hash': doc.get('access_hash'),
            },
            'file_reference': (doc.get('file_reference') or b'').hex(),
            'size': doc.get('size') or 0,
            'name': name,
            'mime': mime,
            'loc_type': 'd',
            'width': w, 'height': h, 'duration': duration,
        }
    if kind == 'messageMediaPhoto':
        photo = media.get('photo')
        if not photo:
            return None
        sizes = photo.get('sizes') or []
        best = None
        best_px = -1
        for s in sizes:
            kind = s.get('_')
            if kind == 'photoSize':
                px = (s.get('w') or 0) * (s.get('h') or 0)
                size = s.get('size') or 0
            elif kind == 'photoSizeProgressive':
                px = (s.get('w') or 0) * (s.get('h') or 0)
                arr = s.get('sizes') or []
                size = arr[-1] if arr else 0
                s = dict(s, size=size)
            else:
                continue
            if px > best_px:
                best_px = px
                best = s
        if not best:
            return None
        return {
            'kind': 'photo',
            'dc': photo.get('dc_id'),
            'location': {
                'volume_id': 0,
                'local_id': 0,
                'id': photo.get('id'),
                'access_hash': photo.get('access_hash'),
            },
            'file_reference': (photo.get('file_reference') or b'').hex(),
            'size': best.get('size') or 0,
            'name': 'photo_%d_%s.jpg' % (photo.get('id'), best.get('type') or 'x'),
            'mime': 'image/jpeg',
            'thumb_size': best.get('type') or 'x',
            'loc_type': 'p',
            'width': best.get('w') or 0,
            'height': best.get('h') or 0,
        }
    return None


def build_location_input(spec):
    # 按 loc_type 选择 InputFileLocation
    loc = spec['location']
    fref = bytes.fromhex(spec['file_reference']) if spec.get('file_reference') else b''
    lt = spec.get('loc_type')
    if lt == 'p':
        return ('inputPhotoFileLocation', {
            'id': loc['id'], 'access_hash': loc['access_hash'],
            'file_reference': fref,
            'thumb_size': spec.get('thumb_size') or loc.get('thumb_size') or 'y',
        })
    if lt == 'w' or ('secret' in loc and not loc.get('access_hash')):
        return ('inputFileLocation', {
            'volume_id': loc.get('volume_id') or 0,
            'local_id': loc.get('local_id') or 0,
            'secret': loc['secret'],
            'file_reference': fref,
        })
    return ('inputDocumentFileLocation', {
        'id': loc['id'], 'access_hash': loc['access_hash'],
        'file_reference': fref,
        'thumb_size': spec.get('thumb_size') or '',
    })


def align_limit(limit, remaining=None):
    # upload.getFile 实测约束：limit 必须是 4096*2^k，上限 1048576
    # 若已知剩余字节，则 limit 取不超过剩余的最大合法值，避免 OFFSET_INVALID
    if remaining is not None and remaining > 0:
        size = MIN_CHUNK
        best = MIN_CHUNK
        while size <= remaining and size <= MAX_LIMIT:
            best = size
            size <<= 1
        return best
    size = MIN_CHUNK
    while size < limit and size < MAX_LIMIT:
        size <<= 1
    return min(size, MAX_LIMIT)


async def get_file_chunk(client, spec, offset, limit, total_size=None):
    # 取一块文件数据；limit 按剩余字节对齐到 4096*2^k，避免越界 OFFSET_INVALID
    want = limit
    remaining = None
    if total_size:
        remaining = total_size - offset
    limit = align_limit(limit, remaining)
    loc = build_location_input(spec)
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = await client.raw_call('upload.getFile', {
                'location': loc,
                'offset': offset,
                'limit': limit,
            })
            break
        except T.MtprotoError as e:
            dc = _migrate_dc(e.message)
            if not dc or 'FILE' not in e.message or attempt > 2 or dc == client.dc_id:
                raise
            await client.migrate_to(dc)
    obj, _ = client.parse(resp)
    name = obj.get('_')
    if name == 'upload.file':
        data = obj.get('bytes') or b''
        return data[:want]
    if name == 'upload.fileCdnRedirect':
        raise RuntimeError('CDN_REDIRECT dc=%s token=%s' % (
            obj.get('dc_id'), (obj.get('file_token') or b'').hex()[:32]))
    raise RuntimeError('upload.getFile 返回异常构造: %s' % name)


async def iter_messages(client, channel_id, access_hash, limit=20, offset_id=0, flt='inputMessagesFilterVideo'):
    # 拉频道历史消息
    resp = await client.raw_call('messages.getHistory', {
        'peer': ('inputPeerChannel', {'channel_id': channel_id, 'access_hash': access_hash}),
        'offset_id': offset_id, 'offset_date': 0, 'add_offset': 0,
        'limit': limit, 'max_id': 0, 'min_id': 0, 'hash': 0,
    })
    obj, _ = client.parse(resp)
    return obj.get('messages') or []


def make_proxy(spec_text):
    # 解析 --socks5 参数为 (host, port, user, pass)
    if not spec_text:
        return None
    parts = spec_text.split(',')
    host, port = parts[0].split(':')
    item = [host, int(port)]
    if len(parts) > 1:
        item.append(parts[1])
    if len(parts) > 2:
        item.append(parts[2])
    return tuple(item)
