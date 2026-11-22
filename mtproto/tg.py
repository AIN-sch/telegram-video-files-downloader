# -*- coding: utf-8 -*-
# CLI：t.me 链接解析为 tgdl:// 直链 + 规格，以及按规格/直链下载
import argparse
import asyncio
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fetcher
import mtp_client as C

DEFAULT_PROXY = ('127.0.0.1', 1085)


def emit(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


async def cmd_resolve(args):
    proxy = C.make_proxy(args.socks5) if args.socks5 else DEFAULT_PROXY
    client = await C.open_client(dc_id=args.dc, proxy=proxy, log=lambda s: print(s, file=sys.stderr))
    try:
        channel_id, access_hash, msg_id = await C.resolve_channel(client, args.link)
        print('[resolve] channel=%d access_hash=%s msg_id=%s' % (channel_id, access_hash, msg_id),
              file=sys.stderr)
        if msg_id is None:
            msgs = await C.iter_messages(client, channel_id, access_hash, limit=args.limit)
            out = []
            for m in msgs:
                spec = C.extract_media(m)
                if spec:
                    out.append(_spec_out(spec, m, channel_id, access_hash))
            emit({'peer': args.link, 'count': len(out), 'items': out})
            return 0
        msg, env = await C.get_message(client, channel_id, access_hash, msg_id)
        spec = C.extract_media(msg)
        if not spec:
            emit({'peer': args.link, 'msg_id': msg_id, 'error': '该消息无媒体'})
            return 1
        info = _spec_out(spec, msg, channel_id, access_hash)
        emit(info)
        if args.out:
            with open(args.out, 'w', encoding='utf-8') as f:
                json.dump(info, f, ensure_ascii=False, indent=2)
            print('[resolve] 已写入 %s' % args.out, file=sys.stderr)
        return 0
    finally:
        await client.close()


def _spec_out(spec, msg, channel_id, access_hash):
    # 组装对外的 JSON：含 uri 与 spec
    uri = fetcher.spec_to_uri(spec['kind'], spec['dc'], spec['location'],
                              spec['file_reference'], spec['size'],
                              spec['name'], spec['mime'], spec.get('thumb_size'))
    src = {
        'kind': 'mtproto',
        'dc': spec['dc'],
        'location': spec['location'],
        'file_reference': spec['file_reference'],
        'size': spec['size'],
        'mime': spec['mime'],
        'name': spec['name'],
    }
    return {
        'peer': 'channel/%d' % channel_id,
        'msg_id': msg.get('id'),
        'kind': spec['kind'],
        'file_name': spec['name'],
        'size': spec['size'],
        'mime': spec['mime'],
        'direct_url': None,
        'downloader': 'mtproto',
        'uri': uri,
        'spec': src,
        'width': spec.get('width') or 0,
        'height': spec.get('height') or 0,
        'duration': spec.get('duration') or 0,
        'thumb_size': spec.get('thumb_size'),
    }


async def cmd_download(args):
    target = args.target
    if target.startswith('tgdl://'):
        src = await fetcher.resolve_uri(target)
        name = src.get('name') or 'file.bin'
    else:
        with open(target, 'r', encoding='utf-8') as f:
            info = json.load(f)
        src = info.get('spec') or info
        name = info.get('file_name') or src.get('name') or 'file.bin'
        if isinstance(src.get('location'), dict) and 'file_reference' in src:
            pass
    out_dir = args.out_dir or os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    out_path = args.out or os.path.join(out_dir, name)
    proxy = C.make_proxy(args.socks5) if args.socks5 else DEFAULT_PROXY
    meta, _ = await fetcher.open_source(src, proxy=proxy, log=lambda s: None)
    print('[dl] dc=%s size=%s mime=%s name=%s' % (src['dc'], src.get('size'), src.get('mime'), name),
          file=sys.stderr)
    res = await fetcher.download_spec(src, out_path, proxy=proxy, threads=args.threads, resume=not args.no_resume)
    emit(res)
    return 0


async def cmd_info(args):
    keys = C.load_keys()
    layer = C.cached_layer()
    emit({'mainDc': keys['mainDc'], 'userId': keys.get('userId'),
          'dcs': [{'dc': d['dc'], 'ip': d['ip'], 'port': d['port']} for d in keys['dcs']],
          'layer': layer})
    return 0


async def cmd_getfile(args):
    # 按 spec/uri 从指定 offset 取一段并落盘，用于区间下载与断点校验
    if args.target.startswith('tgdl://'):
        src = await fetcher.resolve_uri(args.target)
    else:
        info = json.load(open(args.target, 'r', encoding='utf-8'))
        src = info.get('spec') or info
    proxy = C.make_proxy(args.socks5) if args.socks5 else DEFAULT_PROXY
    meta, it = await fetcher.open_source(src, start_offset=args.offset,
                                        length=args.length, proxy=proxy)
    total = 0
    with open(args.out, 'wb') as f:
        async for chunk in it:
            f.write(chunk)
            total += len(chunk)
    print(json.dumps({'offset': args.offset, 'bytes': total, 'out': args.out,
                      'meta': meta}, ensure_ascii=False))
    return 0


def main():
    ap = argparse.ArgumentParser(description='独立 MTProto 客户端：t.me -> tgdl:// -> 下载')
    ap.add_argument('--socks5', default=None,
                    help='SOCKS5，host:port 或 host:port,user,pass；默认 127.0.0.1:1085')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('resolve', help='解析 t.me 链接，输出含 uri 的 JSON')
    p.add_argument('link')
    p.add_argument('--out', default=None)
    p.add_argument('--dc', type=int, default=None)
    p.add_argument('--limit', type=int, default=20)
    p.set_defaults(func=cmd_resolve)

    p = sub.add_parser('download', help='按 info.json 或 tgdl:// 下载')
    p.add_argument('target')
    p.add_argument('--out-dir', default=None)
    p.add_argument('--out', default=None)
    p.add_argument('--threads', type=int, default=1)
    p.add_argument('--no-resume', action='store_true')
    p.set_defaults(func=cmd_download)

    p = sub.add_parser('getfile', help='取区间数据，验证 offset 对齐')
    p.add_argument('target')
    p.add_argument('--offset', type=int, default=0)
    p.add_argument('--length', type=int, default=4096)
    p.add_argument('--out', required=True)
    p.set_defaults(func=cmd_getfile)

    p = sub.add_parser('info', help='显示 keys.json 与 layer')
    p.set_defaults(func=cmd_info)

    args = ap.parse_args()
    return asyncio.run(args.func(args))


if __name__ == '__main__':
    sys.exit(main())
