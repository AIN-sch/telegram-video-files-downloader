#!/usr/bin/env python
# tgdl：主窗口收链接，每粘一条开一个独立下载窗口

import os
import sys
import time
import ctypes
import subprocess

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 配置：首次用自己填
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

TGDL_DIR = os.path.join(ROOT, "relay")      # 放 client.py
SPEC_DIR = os.path.join(ROOT, "spec")       # 放 tgdl_uri.py
OUT_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "Telegram")

# 也可用环境变量覆盖，省得改代码
CERT_PIN = os.environ.get("TGDL_PIN", "")
SERVER_HOST = os.environ.get("TGDL_HOST", "127.0.0.1")
SERVER_PORT = int(os.environ.get("TGDL_PORT", "8443"))
THREADS = int(os.environ.get("TGDL_THREADS", "1"))
PIPE_NAME = os.environ.get("TGDL_PIPE", r"\\.\pipe\tgdl_resolve")

WORKER_FLAG = "--worker"
W = 78


# 杂项
def human(n):
    if n is None:
        return "?"
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d%s" % (n, unit)) if unit == "B" else ("%.1f%s" % (n, unit))
        n /= 1024.0


def dur(sec):
    sec = int(sec)
    h, sec = divmod(sec, 3600)
    m, s = divmod(sec, 60)
    if h:
        return "%d小时%d分" % (h, m)
    if m:
        return "%d分%d秒" % (m, s)
    return "%d秒" % s


def set_title(text):
    try:
        ctypes.windll.kernel32.SetConsoleTitleW(text)
    except Exception:
        pass


def sha256_of(path, bufsize=1 << 20):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(bufsize)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def disp_width(text):
    # 中日韩字符占两列，其余一列
    w = 0
    for ch in text:
        o = ord(ch)
        if (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF or
            0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF or
            0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60 or
            0xFFE0 <= o <= 0xFFE6):
            w += 2
        else:
            w += 1
    return w


def pad_to(text, width):
    return text + " " * max(0, width - disp_width(text))


def row(k, v):
    # 标签对齐到固定列，值超宽按显示宽度折行
    pad = 12
    head = "  " + pad_to(k, pad)
    if v is None or v == "":
        return head + "-"
    text = str(v)
    avail = W - 2 - pad
    if disp_width(text) <= avail:
        return head + text

    out, cur, line_w = [], [], 0
    for ch in text:
        cw = disp_width(ch)
        if line_w + cw > avail:
            out.append("".join(cur))
            cur, line_w = [], 0
        cur.append(ch)
        line_w += cw
    if cur:
        out.append("".join(cur))

    lines = [head + out[0]]
    for seg in out[1:]:
        lines.append("  " + " " * pad + seg)
    return "\n".join(lines)


def rule(ch="─"):
    return ch * W


def decode_uri(uri):
    try:
        if SPEC_DIR not in sys.path:
            sys.path.insert(0, SPEC_DIR)
        import tgdl_uri
        return tgdl_uri.decode(uri)
    except Exception:
        return {}


def resolve_tme(link, timeout=20.0):
    # 把 t.me 消息地址交给解析守护进程换成 tgdl://
    if not PIPE_NAME:
        return None
    try:
        import json
        with open(PIPE_NAME, "r+b", buffering=0) as f:
            f.write((json.dumps({"link": link}) + "\n").encode("utf-8"))
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                chunk = f.read(4096)
                if not chunk:
                    break
                buf += chunk
                if buf.endswith(b"\n"):
                    break
            data = json.loads(buf.decode("utf-8", "replace").strip() or "{}")
            return data.get("uri")
    except Exception as e:
        print("  [解析] 失败：%r" % (e,))
        return None


def pause(msg="按任意键关闭本窗口"):
    print()
    print("  %s" % msg, end="", flush=True)
    try:
        if sys.platform == "win32":
            import msvcrt
            msvcrt.getch()
        else:
            input()
    except Exception:
        time.sleep(30)
    print()


# 下载窗口
def run_worker(argv):
    if not argv:
        print("worker 缺少链接")
        return 2

    uri = argv[0]
    out_dir = argv[1] if len(argv) > 1 else OUT_DIR

    info = decode_uri(uri)
    name = info.get("name") or "download.bin"
    size = info.get("size") or 0
    dc = info.get("dc")
    mime = info.get("mime") or ""
    kind = info.get("kind") or ""
    final = os.path.join(out_dir, name)
    kind_name = {"d": "文档 / 视频 / 音频", "p": "图片", "w": "webFile", "m": "贴纸"}.get(kind, kind or "-")

    set_title("下载中  %s" % name)

    print(rule("═"))
    print(" " * ((W - 8) // 2) + "T G D L  下 载 器")
    print(rule("═"))
    print(row("文件名", name))
    print(row("大小", "%s  (%s 字节)" % (human(size), size) if size else "-"))
    print(row("格式", mime or "-"))
    print(row("类型", kind_name))
    print(row("数据DC", dc if dc is not None else "-"))
    print(row("直链", uri))
    print(row("保存到", final))
    print(row("开始", time.strftime("%Y-%m-%d %H:%M:%S")))
    print(rule())

    if not os.path.isdir(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    if TGDL_DIR not in sys.path:
        sys.path.insert(0, TGDL_DIR)
    try:
        import client as tgdl
    except Exception as e:
        print("\n加载 client.py 失败：%r" % (e,))
        print("检查配置 TGDL_DIR = %s" % TGDL_DIR)
        pause()
        return 3

    print()
    saved = sys.argv
    sys.argv = [
        "client.py", "--uri", uri, "--out", out_dir,
        "--threads", str(THREADS), "--resume",
    ]
    if CERT_PIN:
        sys.argv += ["--pin", CERT_PIN]
    sys.argv += ["--host", SERVER_HOST, "--port", str(SERVER_PORT)]

    t0 = time.time()
    code = 0
    try:
        code = tgdl.main() or 0
    except SystemExit as e:
        code = e.code if isinstance(e.code, int) else 1
    except Exception as e:
        print("\n异常：%r" % (e,))
        code = 1
    finally:
        sys.argv = saved

    dt = time.time() - t0
    ok = os.path.exists(final) and os.path.getsize(final) > 0
    fsize = os.path.getsize(final) if ok else 0
    avg = fsize / dt if dt > 0 and fsize else 0

    print()
    print(rule("═"))
    print(" " * ((W - 6) // 2) + ("下 载 完 成" if ok else "下 载 未 完 成"))
    print(rule("═"))
    print(row("文件名", name))
    if ok:
        print(row("大小", "%s  (%d 字节)" % (human(fsize), fsize)))
        print(row("格式", mime or "-"))
        print(row("Sha256", sha256_of(final)))
    print(row("直链", uri))
    if ok:
        print(row("保存到", final))
    print(row("耗时", "%s  (%.1f 秒)" % (dur(dt), dt)))
    if ok:
        print(row("平均", "%s/s" % human(avg)))
    print(rule("═"))

    if ok and code == 0:
        set_title("完成  %s" % name)
        pause()
        return 0

    print()
    print("  重跑同一条链接会自动续传")
    set_title("失败  %s" % name)
    pause()
    return code or 1


# 主窗口
def spawn_worker(uri):
    if not os.path.isdir(TGDL_DIR):
        print("  配置错误：relay 目录不存在 —— %s" % TGDL_DIR)
        return False
    args = [sys.executable, os.path.abspath(__file__), WORKER_FLAG, uri, OUT_DIR]
    flags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10) if sys.platform == "win32" else 0
    subprocess.Popen(args, creationflags=flags, close_fds=True)
    return True


def normalize(line):
    t = (line or "").strip().strip("\"'`<>").strip()
    if not t:
        return None, "空输入"
    if t.lower().startswith("tgdl://"):
        return t, None
    if t.startswith("https://t.me/") or t.startswith("https://telegram.me/"):
        print("  消息地址，正在换直链…")
        uri = resolve_tme(t)
        if not uri:
            return None, "解析失败，先跑 tgdl_daemon.py"
        return uri, None
    return None, "不是 tgdl:// 或 t.me 链接"


def main():
    if WORKER_FLAG in sys.argv:
        i = sys.argv.index(WORKER_FLAG)
        return run_worker(sys.argv[i + 1:])

    set_title("tgdl")
    print(rule("═"))
    print(" " * ((W - 8) // 2) + "T G D L  下 载 器")
    print(rule("═"))
    print(row("保存到", OUT_DIR))
    print(row("服务端", "%s:%s   并行 %d" % (SERVER_HOST, SERVER_PORT, THREADS)))
    print(rule())
    print("  右键消息复制链接，粘到下面回车。直接粘 https://t.me/... 也行。")
    print("  输入 q 退出。")
    print(rule("═"))
    print()

    n = 0
    while True:
        try:
            line = input("  直链 > ")
        except (EOFError, KeyboardInterrupt):
            print("\n  已退出。")
            return 0

        if line.strip().lower() in ("q", "quit", "exit"):
            print("  已退出。")
            return 0
        if not line.strip():
            continue

        uri, err = normalize(line)
        if err:
            print("  x %s\n" % err)
            continue

        info = decode_uri(uri)
        print("  ok %s" % (info.get("name") or "(未知文件名)"))
        print("     %s · DC%s" % (human(info.get("size") or 0), info.get("dc", "?")))
        if spawn_worker(uri):
            n += 1
            print("     -> 已开下载窗口（第 %d 个）\n" % n)
        else:
            print("     x 拉起失败\n")


if __name__ == "__main__":
    sys.exit(main())
