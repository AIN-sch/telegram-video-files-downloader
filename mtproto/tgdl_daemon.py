# 解析守护进程：命名管道收 t.me 链接，返回 tgdl:// 直链
import argparse
import asyncio
import collections
import json
import logging
import os
import sys
import threading
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

PIPE_NAME = r'\\.\pipe\tgdl_resolve'
MUTEX_NAME = r'Global\tgdl_daemon'
LOG_DIR = os.path.join(HERE, 'logs')
LOG_PATH = os.path.join(LOG_DIR, 'daemon.log')
CACHE_SIZE = 500
def _proxy_cfg():
    # 本机 SOCKS5：地址、端口与账号密码均可由环境变量覆盖
    host = os.environ.get('TGDL_PROXY_HOST', '127.0.0.1')
    port = int(os.environ.get('TGDL_PROXY_PORT', '1080'))
    user = os.environ.get('TGDL_PROXY_USER') or None
    pwd = os.environ.get('TGDL_PROXY_PASS') or None
    if user is None:
        return (host, port)
    return (host, port, user, pwd)


DEFAULT_PROXY = _proxy_cfg()

log = logging.getLogger('tgdl')


def setup_log():
    os.makedirs(LOG_DIR, exist_ok=True)
    log.setLevel(logging.INFO)
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    fh = logging.FileHandler(LOG_PATH, encoding='utf-8')
    fh.setFormatter(fmt)
    log.addHandler(fh)
    sh = logging.StreamHandler(sys.stdout)
    sh.setFormatter(fmt)
    log.addHandler(sh)


class LruCache(object):
    # 极简 LRU，key 为链接字符串
    def __init__(self, size):
        self.size = size
        self.data = collections.OrderedDict()
        self.lock = threading.Lock()

    def get(self, key):
        with self.lock:
            if key in self.data:
                self.data.move_to_end(key)
                return self.data[key]
            return None

    def put(self, key, value):
        with self.lock:
            self.data[key] = value
            self.data.move_to_end(key)
            while len(self.data) > self.size:
                self.data.popitem(last=False)

    def __len__(self):
        return len(self.data)


CACHE = LruCache(CACHE_SIZE)
RESOLVE_RETRY = 3
RESOLVE_BACKOFF = 1.5


def resolve_sync(link, proxy=None):
    # 复用 tg.py 的解析路径，一次调用独立事件循环
    import mtp_client as C
    import fetcher

    async def run():
        client = await C.open_client(proxy=proxy or DEFAULT_PROXY, log=None)
        try:
            channel_id, access_hash, msg_id = await C.resolve_channel(client, link)
            if msg_id is None:
                raise ValueError('链接需包含消息 id，例如 https://t.me/xxx/123')
            msg, _env = await C.get_message(client, channel_id, access_hash, msg_id)
            spec = C.extract_media(msg)
            if not spec:
                raise ValueError('该消息无媒体')
            uri = fetcher.spec_to_uri(spec['kind'], spec['dc'], spec['location'],
                                      spec['file_reference'], spec['size'],
                                      spec['name'], spec['mime'], spec.get('thumb_size'))
            return {
                'uri': uri,
                'name': spec['name'],
                'size': spec['size'],
                'mime': spec['mime'],
                'kind': spec['kind'],
                'dc': spec['dc'],
                'msg_id': msg_id,
                'channel': channel_id,
            }
        finally:
            await client.close()

    return asyncio.run(run())


def handle_request(line):
    # 处理一行请求，返回一行响应 JSON（不含换行）
    try:
        req = json.loads(line.decode('utf-8', 'replace'))
    except Exception as e:
        return json.dumps({'error': 'bad json: %s' % e}, ensure_ascii=True).encode('ascii')
    link = (req.get('link') or '').strip()
    if not link:
        return json.dumps({'error': 'missing link'}, ensure_ascii=True).encode('ascii')

    hit = CACHE.get(link)
    if hit:
        log.info('cache hit %s' % link)
        return json.dumps(hit, ensure_ascii=True).encode('ascii')

    t0 = time.time()
    last = None
    # 代理刚起或瞬断时重试，避免把一次性网络抖动当成失败
    for attempt in range(RESOLVE_RETRY):
        try:
            res = resolve_sync(link)
            res['cached'] = False
            res['elapsed_ms'] = int((time.time() - t0) * 1000)
            CACHE.put(link, res)
            log.info('resolved %s msg=%s dc=%s size=%s %dms' % (
                link, res['msg_id'], res['dc'], res['size'], res['elapsed_ms']))
            return json.dumps(res, ensure_ascii=True).encode('ascii')
        except Exception as e:
            last = e
            log.error('resolve fail %s attempt=%d : %s' % (link, attempt + 1, e))
            if attempt + 1 < RESOLVE_RETRY:
                time.sleep(RESOLVE_BACKOFF)
    log.error(traceback.format_exc())
    return json.dumps({'error': str(last)}, ensure_ascii=True).encode('ascii')


def _pipe_security():
    # 显式放开管道 DACL，避免提权启动后普通进程连不上
    import win32security
    import ntsecuritycon

    sd = win32security.SECURITY_DESCRIPTOR()
    dacl = win32security.ACL()
    world = win32security.ConvertStringSidToSid('S-1-1-0')
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                             ntsecuritycon.FILE_ALL_ACCESS, world)
    sd.SetSecurityDescriptorDacl(True, dacl, False)
    return sd


def run_server():
    import win32pipe
    import win32file
    import win32security
    import win32api
    import pywintypes

    sd = _pipe_security()

    while True:
        try:
            sa = win32security.SECURITY_ATTRIBUTES()
            sa.bInheritHandle = False
            sa.SECURITY_DESCRIPTOR = sd
            pipe = win32pipe.CreateNamedPipe(
                PIPE_NAME,
                win32pipe.PIPE_ACCESS_DUPLEX,
                win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                win32pipe.PIPE_UNLIMITED_INSTANCES,
                65536, 65536, 0, sa)
            log.info('管道已创建，等待连接 %s' % PIPE_NAME)
            win32pipe.ConnectNamedPipe(pipe, None)
            log.info('客户端已连接')
            buf = b''
            while True:
                try:
                    _hr, chunk = win32file.ReadFile(pipe, 65536)
                except pywintypes.error as e:
                    # 109 = ERROR_BROKEN_PIPE，客户端关闭写入端
                    log.info('读取结束 code=%s' % (e.args[0],))
                    break
                if not chunk:
                    break
                buf += chunk
                if b'\n' in buf:
                    break
            line = buf.split(b'\n')[0].strip()
            if line:
                resp = handle_request(line)
                try:
                    win32file.WriteFile(pipe, resp + b'\n')
                    win32file.FlushFileBuffers(pipe)
                except pywintypes.error as e:
                    log.warning('写回失败 code=%s' % (e.args[0],))
            try:
                win32pipe.DisconnectNamedPipe(pipe)
            except Exception:
                pass
            try:
                win32api.CloseHandle(pipe)
            except Exception:
                pass
        except pywintypes.error as e:
            log.warning('管道异常 code=%s %s，1s 后重建' % (e.args[0], e.args[1] if len(e.args) > 1 else ''))
            time.sleep(1)
        except Exception as e:
            log.error('守护循环异常: %s' % e)
            log.error(traceback.format_exc())
            time.sleep(1)


def single_instance():
    # Global 互斥体防多开
    import win32event
    import win32api
    import pywintypes
    try:
        handle = win32event.CreateMutex(None, True, MUTEX_NAME)
        err = win32api.GetLastError()
        if err == 183:  # ERROR_ALREADY_EXISTS
            return None
        return handle
    except pywintypes.error:
        return None


def do_probe(link):
    # 自检：连一次管道、发一条请求、打印响应
    import win32file
    import win32pipe
    import pywintypes
    payload = json.dumps({'link': link}, ensure_ascii=False).encode('utf-8') + b'\n'
    try:
        handle = win32file.CreateFile(
            PIPE_NAME,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0, None, win32file.OPEN_EXISTING, 0, None)
    except pywintypes.error as e:
        print('连接管道失败 code=%s：守护进程未运行？' % (e.args[0],))
        return 2
    try:
        win32pipe.SetNamedPipeHandleState(
            handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
        win32file.WriteFile(handle, payload)
        win32file.FlushFileBuffers(handle)
        buf = b''
        while b'\n' not in buf:
            try:
                _hr, chunk = win32file.ReadFile(handle, 65536)
            except pywintypes.error as e:
                print('读取响应失败 code=%s' % (e.args[0],))
                return 3
            if not chunk:
                break
            buf += chunk
        text = buf.decode('utf-8', 'replace').strip()
        print(text)
        try:
            obj = json.loads(text)
        except Exception:
            return 4
        return 0 if 'uri' in obj else 5
    finally:
        try:
            win32file.CloseHandle(handle)
        except Exception:
            pass


def main():
    ap = argparse.ArgumentParser(description='t.me 链接解析守护进程（命名管道）')
    ap.add_argument('--probe', action='store_true', help='自检：连一次管道并打印响应')
    ap.add_argument('--link', default='', help='--probe 使用的公开频道链接')
    args = ap.parse_args()
    setup_log()

    if args.probe:
        return do_probe(args.link)

    mutex = single_instance()
    if mutex is None:
        print('已有实例在运行，退出')
        return 1
    log.info('ready pipe=%s layer=%s cache=%d' % (PIPE_NAME, _cached_layer(), CACHE_SIZE))
    print('ready pipe=%s' % PIPE_NAME, flush=True)
    try:
        run_server()
    except KeyboardInterrupt:
        log.info('收到中断，退出')
    return 0


def _cached_layer():
    try:
        import mtp_client as C
        return C.cached_layer()
    except Exception:
        return None


if __name__ == '__main__':
    sys.exit(main())
