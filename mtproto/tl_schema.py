# TL 序列化层：解析 api.tl 生成构造表，小端、string 四字节对齐
import os
import re
import struct

VECTOR_ID = 0x1CB5C415
NULL_ID = 0x56730BCC
BOOL_TRUE_ID = 0x997275B5
BOOL_FALSE_ID = 0xBC799737

# 固定 4 字节宽度的基础类型
_BASIC = {
    'int': 4, 'Int': 4, 'long': 8, 'Long': 8,
    'int128': 16, 'int256': 32, 'double': 8,
    'Bool': 4, 'True': 4, 'bool': 4, '#': 4,
}

_class_cache = {}
_field_cache = {}


def _strip_comment(line):
    # 去掉 // 行注释
    idx = line.find('//')
    return line[:idx] if idx >= 0 else line


def load_schema(tl_path):
    # 解析 TL 文件，返回 (ctor_id -> 类定义, 类名 -> [ctor_id])
    classes = {}
    by_name = {}
    if not os.path.exists(tl_path):
        raise IOError('TL 文件缺失: %s' % tl_path)
    with open(tl_path, 'r', encoding='utf-8', errors='replace') as f:
        text = f.read()
    # 先合并成语句：以 ; 结尾
    for raw in text.split(';'):
        stmt = ' '.join(_strip_comment(x) for x in raw.splitlines()).strip()
        if not stmt or '=' not in stmt:
            continue
        left, right = stmt.split('=', 1)
        left = left.strip()
        result = right.strip()
        if not left or left.startswith('---'):
            continue
        # 函数（返回 !X 或带 ? 泛型）不入类表
        m = re.match(r'^([A-Za-z_][A-Za-z0-9_.]*)(?:#([0-9a-fA-F]+))?\s*(.*)$', left, re.S)
        if not m:
            continue
        name, hexid, body = m.group(1), m.group(2), m.group(3)
        if '!' in result or '{' in body:
            continue
        if not hexid:
            continue
        cid = int(hexid, 16)
        fields = _parse_fields(body)
        classes[cid] = {'id': cid, 'name': name, 'fields': fields, 'result': result}
        by_name.setdefault(name, []).append(cid)
    return classes, by_name


def _parse_fields(body):
    # 按空白切分字段声明，支持 flags.N?type 与 Vector<...>
    body = body.strip()
    if not body:
        return []
    tokens = []
    depth = 0
    cur = ''
    for ch in body:
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
        if ch.isspace() and depth == 0:
            if cur:
                tokens.append(cur)
                cur = ''
        else:
            cur += ch
    if cur:
        tokens.append(cur)
    out = []
    for tok in tokens:
        if ':' not in tok:
            continue
        fname, ftype = tok.split(':', 1)
        bit = None
        flagword = 'flags'
        if '?' in ftype:
            cond, ftype = ftype.split('?', 1)
            if '.' in cond:
                flagword, idx = cond.split('.', 1)
                bit = int(idx)
            else:
                flagword, bit = 'flags', 0
        out.append((fname, ftype, bit, flagword))
    return out


class TLWriter(object):
    # TL 序列化器
    def __init__(self, classes=None, by_name=None):
        self.buf = bytearray()
        self.classes = classes or {}
        self.by_name = by_name or {}

    def raw(self, b):
        self.buf += b

    def int_(self, v):
        self.buf += struct.pack('<i', int(v) & 0xFFFFFFFF if v >= 0 else int(v))

    def uint(self, v):
        self.buf += struct.pack('<I', int(v) & 0xFFFFFFFF)

    def long_(self, v):
        self.buf += struct.pack('<q', int(v))

    def double_(self, v):
        self.buf += struct.pack('<d', float(v))

    def bytes_(self, b):
        # TL bytes/string 编码
        n = len(b)
        if n < 254:
            self.buf.append(n)
            self.buf += b
            pad = (4 - (n + 1) % 4) % 4
        else:
            self.buf.append(254)
            self.buf += struct.pack('<I', n)[0:3]
            self.buf += b
            pad = (4 - n % 4) % 4
        if pad:
            self.buf += b'\x00' * pad

    def string_(self, s):
        if isinstance(s, str):
            s = s.encode('utf-8')
        self.bytes_(s)

    def ctor(self, cid):
        self.uint(cid)

    def bool_(self, v):
        self.uint(BOOL_TRUE_ID if v else BOOL_FALSE_ID)

    def vector(self, items, writer_fn):
        self.uint(VECTOR_ID)
        self.uint(len(items))
        for i, item in enumerate(items):
            writer_fn(self, item, i)

    # 按 schema 写一个对象：obj = {"_": "类名", 字段...} 或 (类名, 参数字典)
    def write_obj(self, obj):
        if isinstance(obj, tuple):
            name, args = obj
        else:
            name, args = obj['_'], obj
        ids = self.by_name.get(name)
        if not ids:
            raise KeyError('未知构造: %s' % name)
        cid = ids[0]
        cls = self.classes[cid]
        self.uint(cid)
        self._write_fields(cls['fields'], args)

    def _write_fields(self, fields, args):
        # 先按入参计算 flags/flags2
        flags = 0
        flags2 = 0
        for fname, ftype, bit, flagword in fields:
            if bit is None:
                continue
            if ftype in ('true', 'Bool') or ftype.startswith('Vector<') or ftype not in ('int', 'long', 'double', 'string', 'bytes', '#', 'Int', 'Long'):
                if ftype in ('true', 'Bool'):
                    present = bool(args.get(fname))
                else:
                    present = args.get(fname) is not None
            else:
                present = args.get(fname) is not None
            if present:
                if flagword == 'flags':
                    flags |= (1 << bit)
                else:
                    flags2 |= (1 << bit)
        for fname, ftype, bit, flagword in fields:
            if ftype == '#' and fname in ('flags', 'flags2'):
                self.uint(flags if fname == 'flags' else flags2)
                continue
            if bit is not None:
                cur = flags if flagword == 'flags' else flags2
                if not (cur >> bit) & 1:
                    continue
            val = args.get(fname)
            if ftype == 'true':
                # flags.N?true 不占字节
                continue
            self._write_value(ftype, val)

    def _write_value(self, ftype, val):
        if ftype in ('int', 'Int'):
            self.int_(val if val is not None else 0)
        elif ftype in ('long', 'Long'):
            self.long_(val if val is not None else 0)
        elif ftype == 'int128':
            self.raw(val)
        elif ftype == 'int256':
            self.raw(val)
        elif ftype == 'double':
            self.double_(val if val is not None else 0.0)
        elif ftype in ('string', 'bytes'):
            if ftype == 'string':
                self.string_(val or '')
            else:
                self.bytes_(val or b'')
        elif ftype in ('Bool', 'true', 'bool'):
            self.bool_(bool(val))
        elif ftype.startswith('Vector<'):
            inner = ftype[len('Vector<'):-1]
            items = val or []
            self.uint(VECTOR_ID)
            self.uint(len(items))
            for it in items:
                self._write_value(inner, it)
        else:
            # 嵌套对象：val 为 (类名, 参数字典) 或 dict
            if val is None:
                self.uint(NULL_ID)
            else:
                self.write_obj(val)


class TLReader(object):
    # TL 反序列化器
    def __init__(self, data, classes, by_name, pos=0):
        self.data = data
        self.pos = pos
        self.classes = classes
        self.by_name = by_name

    def need(self, n):
        if self.pos + n > len(self.data):
            raise ValueError('TL 读取越界 pos=%d need=%d len=%d' % (self.pos, n, len(self.data)))

    def uint(self):
        self.need(4)
        v = struct.unpack('<I', self.data[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def int_(self):
        self.need(4)
        v = struct.unpack('<i', self.data[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def long_(self):
        self.need(8)
        v = struct.unpack('<q', self.data[self.pos:self.pos + 8])[0]
        self.pos += 8
        return v

    def double_(self):
        self.need(8)
        v = struct.unpack('<d', self.data[self.pos:self.pos + 8])[0]
        self.pos += 8
        return v

    def raw(self, n):
        self.need(n)
        b = self.data[self.pos:self.pos + n]
        self.pos += n
        return b

    def bytes_(self):
        self.need(1)
        n = self.data[self.pos]
        self.pos += 1
        if n == 254:
            self.need(3)
            n = struct.unpack('<I', self.data[self.pos:self.pos + 3] + b'\x00')[0]
            self.pos += 3
            pad = (4 - n % 4) % 4
        else:
            pad = (4 - (n + 1) % 4) % 4
        b = self.raw(n)
        if pad:
            self.raw(pad)
        return b

    def string_(self):
        return self.bytes_().decode('utf-8', 'replace')

    def read_obj(self):
        # 读一个 TL 对象，返回 (类名, 字典) 或标量
        cid = self.uint()
        if cid == VECTOR_ID:
            cnt = self.uint()
            items = []
            for _ in range(cnt):
                items.append(self.read_obj())
            return {'_': 'vector', 'items': items}
        if cid == NULL_ID:
            return None
        if cid == BOOL_TRUE_ID:
            return True
        if cid == BOOL_FALSE_ID:
            return False
        cls = self.classes.get(cid)
        if not cls:
            raise KeyError('未知构造 id=%08x pos=%d' % (cid, self.pos - 4))
        obj = {'_': cls['name'], 'ctor': cid}
        flags = 0
        flags2 = 0
        for fname, ftype, bit, flagword in cls['fields']:
            if ftype == '#' and fname == 'flags':
                flags = self.uint()
                obj['flags'] = flags
                continue
            if ftype == '#' and fname == 'flags2':
                flags2 = self.uint()
                obj['flags2'] = flags2
                continue
            if bit is not None:
                cur = flags if flagword == 'flags' else flags2
                if not (cur >> bit) & 1:
                    continue
                if ftype == 'true':
                    # flags.N?true 不占字节，置 True
                    obj[fname] = True
                    continue
            obj[fname] = self.read_value(ftype)
        return obj

    def read_value(self, ftype):
        if ftype in ('int', 'Int'):
            return self.int_()
        if ftype in ('long', 'Long'):
            return self.long_()
        if ftype == 'int128':
            return self.raw(16)
        if ftype == 'int256':
            return self.raw(32)
        if ftype == 'double':
            return self.double_()
        if ftype == 'string':
            return self.string_()
        if ftype == 'bytes':
            return self.bytes_()
        if ftype in ('Bool', 'bool'):
            cid = self.uint()
            return cid == BOOL_TRUE_ID
        if ftype == 'true':
            self.uint()
            return True
        if ftype.startswith('Vector<'):
            inner = ftype[len('Vector<'):-1]
            cid = self.uint()
            if cid != VECTOR_ID:
                # 某些 schema 用裸 vector
                self.pos -= 4
                return [self.read_obj()]
            cnt = self.uint()
            return [self.read_value(inner) for _ in range(cnt)]
        return self.read_obj()


def load_ref_schema():
    # 读取打包的 api.tl
    base = os.path.dirname(os.path.abspath(__file__))
    tl = os.path.join(base, 'ref', 'api.tl')
    return load_schema(tl)
