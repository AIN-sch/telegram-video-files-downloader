# tdata 只读提取器：解 key_datas 得 localKey，再解账号文件得各 DC auth_key
import argparse
import hashlib
import json
import os
import struct
import sys

from Crypto.Cipher import AES

TDF_MAGIC = b'TDF$'
KEY_DATA_MAGIC = 0x4B443200
DBI_MTP_AUTHORIZATION = 0x4B
WIDE_IDS_TAG = 0xFFFFFFFFFFFFFFFF


def _default_tdata():
    # 未指定时按系统默认安装位置拼 tdata 路径
    appdata = os.environ.get('APPDATA') or ''
    if appdata:
        return os.path.join(appdata, 'Telegram Desktop', 'tdata')
    return os.path.join(os.path.expanduser('~'), '.local', 'share',
                        'TelegramDesktop', 'tdata')


DEFAULT_TDATA = _default_tdata()
AUTH_KEY_SIZE = 256
SALT_SIZE = 32

# 生产 DC 默认地址，configs 解析失败时兜底
DEFAULT_DCS = {
    1: ('149.154.175.53', 443),
    2: ('149.154.167.51', 443),
    3: ('149.154.175.100', 443),
    4: ('149.154.167.91', 443),
    5: ('91.108.56.130', 443),
}


def log(lines, msg):
    lines.append(msg)
    print(msg)


def ige_decrypt(key, iv, data):
    # AES-256-IGE 解密，等价 openssl AES_ige_encrypt(enc=AES_DECRYPT)
    if len(data) % 16:
        raise ValueError('ige 数据长度非 16 倍数')
    aes = AES.new(key, AES.MODE_ECB)
    iv1 = iv[:16]
    iv2 = iv[16:32]
    out = bytearray()
    for off in range(0, len(data), 16):
        ct = data[off:off + 16]
        x = bytes(a ^ b for a, b in zip(ct, iv2))
        p = aes.decrypt(x)
        p = bytes(a ^ b for a, b in zip(p, iv1))
        out += p
        iv1 = ct
        iv2 = p
    return bytes(out)


def ige_encrypt(key, iv, data):
    # AES-256-IGE 加密，仅用于自检 roundtrip
    if len(data) % 16:
        raise ValueError('ige 数据长度非 16 倍数')
    aes = AES.new(key, AES.MODE_ECB)
    iv1 = iv[:16]
    iv2 = iv[16:32]
    out = bytearray()
    for off in range(0, len(data), 16):
        pt = data[off:off + 16]
        x = bytes(a ^ b for a, b in zip(pt, iv1))
        c = aes.encrypt(x)
        c = bytes(a ^ b for a, b in zip(c, iv2))
        out += c
        iv1 = c
        iv2 = pt
    return bytes(out)


def prepare_aes_oldmtp(auth_key, msg_key, send):
    # tdesktop AuthKey::prepareAES_oldmtp，返回 (aesKey32, aesIV32)
    x = 0 if send else 8
    k = auth_key
    sa = hashlib.sha1(msg_key + k[x:x + 32]).digest()
    sb = hashlib.sha1(k[32 + x:48 + x] + msg_key + k[48 + x:64 + x]).digest()
    sc = hashlib.sha1(k[64 + x:96 + x] + msg_key).digest()
    sd = hashlib.sha1(msg_key + k[96 + x:128 + x]).digest()
    aes_key = sa[0:8] + sb[8:20] + sc[4:16]
    aes_iv = sa[8:20] + sb[0:8] + sc[16:20] + sd[0:8]
    return aes_key, aes_iv


def create_local_key(passcode, salt):
    # tdesktop CreateLocalKey：SHA512(salt+passcode+salt) 作口令，PBKDF2-HMAC-SHA512 出 256 字节
    h = hashlib.sha512(salt + passcode + salt).digest()
    iterations = 1 if not passcode else 100000
    return hashlib.pbkdf2_hmac('sha512', h, salt, iterations, AUTH_KEY_SIZE)


def decrypt_local(encrypted, key, dbg, tag):
    # tdesktop DecryptLocal：前 16 字节为明文 SHA1 前 16 字节，其后为 IGE 密文
    if len(encrypted) <= 16 or (len(encrypted) & 0x0F):
        raise ValueError('%s 密文长度非法: %d' % (tag, len(encrypted)))
    full_len = len(encrypted) - 16
    enc_key = encrypted[:16]
    enc_data = encrypted[16:]
    aes_key, aes_iv = prepare_aes_oldmtp(key, enc_key, send=False)
    dbg.append('[%s] msgKey=%s' % (tag, enc_key.hex()))
    dbg.append('[%s] aesKey=%s' % (tag, aes_key.hex()))
    dbg.append('[%s] aesIV =%s' % (tag, aes_iv.hex()))
    decrypted = ige_decrypt(aes_key, aes_iv, enc_data)
    dbg.append('[%s] plainFirst32=%s' % (tag, decrypted[:32].hex()))
    check = hashlib.sha1(decrypted).digest()[:16]
    dbg.append('[%s] sha1Check=%s expect=%s %s' % (
        tag, check.hex(), enc_key.hex(), 'OK' if check == enc_key else 'MISMATCH'))
    if check != enc_key:
        raise ValueError('%s SHA1 校验失败，密钥错误' % tag)
    data_len = struct.unpack('<I', decrypted[:4])[0]
    dbg.append('[%s] dataLen=%d fullLen=%d' % (tag, data_len, full_len))
    if data_len > len(decrypted) or data_len < 4:
        raise ValueError('%s 明文长度字段非法: %d' % (tag, data_len))
    return decrypted[4:data_len]


class BlobReader(object):
    # QDataStream(Qt_5_1) 序列化 QByteArray：uint32 大端长度 + 原字节，0xFFFFFFFF 表示 null
    def __init__(self, buf, pos=0):
        self.buf = buf
        self.pos = pos

    def blob(self):
        if self.pos + 4 > len(self.buf):
            raise ValueError('blob 长度越界')
        n = struct.unpack('>I', self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        if n == 0xFFFFFFFF:
            return b''
        if self.pos + n > len(self.buf):
            raise ValueError('blob 数据越界 n=%d' % n)
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def u32le(self):
        v = struct.unpack('<I', self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def i32le(self):
        v = struct.unpack('<i', self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def u64le(self):
        v = struct.unpack('<Q', self.buf[self.pos:self.pos + 8])[0]
        self.pos += 8
        return v

    # QDataStream 版本 Qt_5_1 默认大端
    def u32(self):
        v = struct.unpack('>I', self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def i32(self):
        v = struct.unpack('>i', self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def u64(self):
        v = struct.unpack('>Q', self.buf[self.pos:self.pos + 8])[0]
        self.pos += 8
        return v


def read_tdf(path):
    # 读 TDF$ 文件：magic(4) + version(int32) + blob... + md5(16)
    raw = open(path, 'rb').read()
    if raw[:4] != TDF_MAGIC:
        raise ValueError('%s 不是 TDF$ 文件' % path)
    version = struct.unpack('<i', raw[4:8])[0]
    return raw, version, BlobReader(raw, 8)


def parse_key_datas(path, dbg):
    raw, version, rd = read_tdf(path)
    dbg.append('[key_datas] len=%d version=%d' % (len(raw), version))
    open_salt = rd.blob()
    open_key_enc = rd.blob()
    info_enc = rd.blob()
    trailer = rd.blob()
    dbg.append('[key_datas] openSalt=%s' % open_salt.hex())
    dbg.append('[key_datas] openKeyEnc len=%d head=%s' % (len(open_key_enc), open_key_enc[:32].hex()))
    dbg.append('[key_datas] infoEnc len=%d' % len(info_enc))
    dbg.append('[key_datas] trailer=%s' % trailer.hex())
    if len(open_salt) != SALT_SIZE:
        raise ValueError('openSalt 长度异常: %d' % len(open_salt))
    # QDataStream 默认大端，trailer 内的 magic/committed/wrapCount 均为大端
    magic, fmt, committed, wrap_count = struct.unpack('>IIII', trailer[:16])
    dbg.append('[key_datas] trailer magic=%08x fmt=%d committed=%d wraps=%d' % (
        magic, fmt, committed, wrap_count))
    if magic != KEY_DATA_MAGIC:
        raise ValueError('trailer magic 不匹配: %08x' % magic)
    return {
        'version': version,
        'openSalt': open_salt,
        'openKeyEncrypted': open_key_enc,
        'infoEncrypted': info_enc,
        'wraps': wrap_count,
        'committed': committed,
    }


def find_account_file(tdata_dir):
    # 账号文件与 key_datas 同级，文件名形如 <16位HEX>s 且非固定名单
    known = {'key_datas', 'settingss', 'prefix', 'usertag', 'countries',
             'shortcuts-custom.json', 'shortcuts-default.json'}
    cand = []
    for name in os.listdir(tdata_dir):
        p = os.path.join(tdata_dir, name)
        if not os.path.isfile(p) or name in known:
            continue
        if not name.endswith('s'):
            continue
        if len(name) != 17:
            continue
        cand.append((os.path.getsize(p), p))
    cand.sort()
    return [p for _, p in cand]


def parse_mtp_authorization(plain, dbg):
    # serializeMtpAuthorization: wideTag(u64) userId(u64) mainDcId(i32) keys[] keysToDestroy[]，QDataStream 大端
    if len(plain) < 20:
        raise ValueError('mtp 授权块过短: %d' % len(plain))
    tag, user_id, main_dc = struct.unpack('>QQi', plain[:20])
    dbg.append('[mtp] wideTag=%016x userId=%d mainDc=%d' % (tag, user_id, main_dc))
    if tag != WIDE_IDS_TAG:
        raise ValueError('wideTag 不匹配: %016x' % tag)

    def read_keys(pos, label):
        if pos + 4 > len(plain):
            raise ValueError('%s 计数越界' % label)
        cnt = struct.unpack('>i', plain[pos:pos + 4])[0]
        pos += 4
        dbg.append('[mtp] %s count=%d' % (label, cnt))
        keys = []
        for _ in range(cnt):
            if pos + 4 + AUTH_KEY_SIZE > len(plain):
                raise ValueError('%s 密钥越界' % label)
            dc = struct.unpack('>i', plain[pos:pos + 4])[0]
            pos += 4
            key = plain[pos:pos + AUTH_KEY_SIZE]
            pos += AUTH_KEY_SIZE
            keys.append((dc, key))
            dbg.append('[mtp] %s dc=%d keyHead=%s' % (label, dc, key[:8].hex()))
        return keys, pos

    keys, pos = read_keys(20, 'keys')
    try:
        drop, pos = read_keys(pos, 'destroy')
    except Exception as e:
        dbg.append('[mtp] destroy 段解析跳过: %s' % e)
        drop = []
    return user_id, main_dc, keys, drop


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--tdata', default=DEFAULT_TDATA, help='tdata 目录，缺省取安装目录')
    ap.add_argument('--out', default=None)
    ap.add_argument('--debug', default=None)
    ap.add_argument('--passcode', default='')
    args = ap.parse_args()

    base = os.path.dirname(os.path.abspath(__file__))
    out_path = args.out or os.path.join(base, 'keys.json')
    dbg_path = args.debug or os.path.join(base, 'debug.txt')
    dbg = []

    kd = parse_key_datas(os.path.join(args.tdata, 'key_datas'), dbg)
    wrap_key = create_local_key(args.passcode.encode(), kd['openSalt'])
    dbg.append('[derive] wrapKey=%s' % wrap_key.hex())
    local_key = decrypt_local(kd['openKeyEncrypted'], wrap_key, dbg, 'localKey')
    dbg.append('[localKey] len=%d value=%s' % (len(local_key), local_key.hex()))
    if len(local_key) != AUTH_KEY_SIZE:
        raise ValueError('localKey 长度异常: %d' % len(local_key))

    result = None
    used = None
    errors = []
    for path in find_account_file(args.tdata):
        name = os.path.basename(path)
        try:
            raw, version, rd = read_tdf(path)
            dbg.append('[account %s] len=%d version=%d' % (name, len(raw), version))
            enc = rd.blob()
            plain = decrypt_local(enc, local_key, dbg, 'account:' + name)
            dbg.append('[account %s] plainLen=%d head=%s' % (name, len(plain), plain[:16].hex()))
            r = BlobReader(plain, 0)
            block_id = r.u32()
            dbg.append('[account %s] blockId=%#x' % (name, block_id))
            if block_id != DBI_MTP_AUTHORIZATION:
                raise ValueError('blockId 非 mtp 授权块: %#x' % block_id)
            body = r.blob()
            dbg.append('[account %s] bodyLen=%d' % (name, len(body)))
            user_id, main_dc, keys, drop = parse_mtp_authorization(body, dbg)
            if keys:
                result = (user_id, main_dc, keys, drop)
                used = name
                break
        except Exception as e:
            errors.append('%s: %s' % (name, e))
            dbg.append('[account %s] 失败: %s' % (name, e))

    if not result:
        open(dbg_path, 'w', encoding='utf-8').write('\n'.join(dbg) + '\n')
        print('未提取到 auth_key，各账号文件错误:')
        for e in errors:
            print('  ' + e)
        return 2

    user_id, main_dc, keys, drop = result
    dcs = []
    seen = set()
    for dc, key in keys:
        if dc in seen:
            continue
        seen.add(dc)
        ip, port = DEFAULT_DCS.get(dc, ('149.154.167.51', 443))
        dcs.append({
            'dc': dc,
            'ip': ip,
            'port': port,
            'key': key.hex(),
            'key_id': hashlib.sha1(key).digest()[12:20][::-1].hex(),
            'nonzero': any(key),
        })
    dcs.sort(key=lambda x: x['dc'])

    payload = {
        'source': used,
        'userId': user_id,
        'mainDc': main_dc,
        'verified': False,
        'dcs': dcs,
        'destroyKeys': len(drop),
        'tdataVersion': kd['version'],
        'hasPasscode': bool(kd['wraps']),
    }
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    open(dbg_path, 'w', encoding='utf-8').write('\n'.join(dbg) + '\n')

    print('keys.json -> %s' % out_path)
    for d in dcs:
        print('  dc%d %s:%d keylen=%d keyId=%s nonzero=%s' % (
            d['dc'], d['ip'], d['port'], len(d['key']) // 2, d['key_id'], d['nonzero']))
    return 0


if __name__ == '__main__':
    sys.exit(main())
