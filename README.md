# Telegram 视频 / 文件 直链下载器

事情的起因很简单。在 Telegram 上找资料，文件都挺大，官方客户端下起来慢得难受。一个 200MB 的压缩包要磨半天，中途断了还得从头来。

既然能下，那下载地址到底是什么？能不能把直链拿出来，用自己的机器、自己的带宽去拉？

逆向了一圈，结论是：**能**，但和大部分人想的不一样。

Telegram 的用户媒体（聊天里发的视频、图片、文件）**没有 HTTP 直链**。抓包抓不到一个 `https://...mp4` 可以直接丢给 IDM 或 aria2。下载走的是 MTProto 协议，在加密的 TCP 连接里一块一块取数据，每块都要带上 `file_reference` 这类服务端签发的凭证。想要"直链"，就得自己实现这套取块逻辑。

这个仓库做的就是这件事：

1. 从已登录的 Telegram Desktop 里把 MTProto 的 `auth_key` 取出来（不用重新登录，不用 api_id / api_hash）；
2. 在客户端进程里挂一个 hook，让「复制链接」复制出来的不再是 `t.me` 消息地址，而是自定义的 `tgdl://` 规格字符串；
3. 写一个 MTProto 客户端，按这个规格把字节真真切切取下来；
4. 再搭一条加密回传通道，让远端 VPS 把文件拉好、加密推回本地。

最终效果：右键一条消息 → 复制链接 → 粘到下载器里 → 跑满带宽落盘。

`ffprobe` 验证过下载到的文件，`h264 + aac`，时长、分辨率、字节数全都对得上，不是坏文件。

---

## 先说环境

网上大部分教程都默认机器能直连 Telegram。我的实际情况不是这样。

**测试环境是一台家用主机加一台跨国 VPS。**

- 家用主机：Windows。Telegram Desktop 装在上面，账号也登录在这台。
- 跨国 VPS：Linux，在境外。能直接连通 Telegram 的各个 DC，带宽比家宽大。

为什么这么配：本地直连 Telegram 的 DC 不通（或者通但慢到没法用），必须经代理出去。VPS 天然在墙外，让它拉文件比本地拉快得多。

整条链路：

```
家用主机（Windows）  ──加密隧道──>  跨国 VPS（Linux）  ──MTProto──>  Telegram DC
      │                                    │
      └────────── 加密回传 ────────────────┘
```

这不是 VPN，是下载加速器。

远端 VPS 只做一件事：替本地把文件拉下来，再用另开的加密通道回传。它不提供上网代理功能，也不会让本地变得能直接访问 Telegram。本地要正常打开 Telegram 并使用账号，仍需自行准备 VPN，这部分与本仓库无关。

- 想翻墙 → 自行准备 VPN
- 想下文件快 → VPS 从 Telegram DC 拉，加密推回，这才是本仓库做的事

为什么不直接挂 VPN 下：VPN 只是让本机能访问 Telegram，带宽仍是家宽的带宽。VPS 在境外，它与 Telegram DC 之间的链路和家宽出境完全是两条路，实测快三到四倍，这是本方案的价值所在。

**本方案不依赖特定 VPN。** 本身能直连 Telegram 的话，可以把 VPS 那一段整段砍掉，只在本地跑 MTProto 客户端，`--direct` 一个参数切过去就行。反过来，如果 VPS 的入站端口被云厂商安全组挡着（踩过这个坑），就借一条已有的 SOCKS5 隧道出网，功能等价，速率略低，`--via-socks` 打开即可。

两种接法都实测跑通过。

---

## 版本兼容性（先看这段）

**所有 RVA 只对特定版本成立，换版本必须重算。**

本方案在 **Telegram Desktop 7.4.4.0**（内部 build `7004004`，PE 时间戳 2026-11-13）上做出来。

| 组件 | 是否受版本影响 |
|---|---|
| `inject/` 里的 hook RVA（`0x47E3C50`） | **强相关**，换版本几乎必崩 |
| `ADDRESSES.h` 里的偏移表 | **强相关** |
| `mtproto/` 协议层 | 弱相关，只跟 `layer` 有关 |
| `spec/` `relay/` `tools/` | 无影响，纯脚本 |

**版本比 7.4.4.0 新时，注入那一步大概率直接用不了**，因为 RVA 全变了。表现是：hook 装到错误地址导致启动崩溃，或者 hook 装上了但永远不触发。

判断当前版本：

```powershell
(Get-Item '.\Telegram.exe').VersionInfo.FileVersion
```

- **7.4.4.0** → 直接用，RVA 对得上
- **7.4.x 其他小版本** → 可能有偏移漂移，按下节重算
- **更高版本 / 8.x** → 必须重算

### 怎么重算

RVA 会变，但**定位链路与版本无关**：

1. 用 IDA 打开新版 `Telegram.exe`，等自动分析跑完（257MB 的样本约二十分钟）
2. 字符串窗搜 `AddCopyLinkAction`，命中一串 lambda 的 mangled name
3. 挑带 `??_R4...6B@` 的那个（vtable 组），记下地址
4. 该地址往前 8 字节是 `COL`（Complete Object Locator），它有一个指向自己的引用
5. 在 `.rdata` 全域搜这个自引用指针值，唯一命中处即 vtable 起址
6. 对 vtable 做交叉引用，唯一命中点在菜单构建函数内，形如 `lea rax, off_XXXX`
7. 该指令所在函数就是挂点，`RVA = VA - ImageBase`
8. 用 capstone 确认入口首字节，**按真实指令边界算补丁长度**，不要按"至少 5 字节"猜

```python
# 确认前几条指令边界
from capstone import *
md = Cs(CS_ARCH_X86, CS_MODE_64)
for ins in md.disasm(code_bytes, base_va):
    print(hex(ins.address), ins.bytes.hex(), ins.mnemonic, ins.op_str)
    if ins.address - base_va > 20:
        break
```

新 RVA 写进 `inject/src/hook.cpp` 的 `HOOK_RVA` 和 `ADDRESSES.h`，重编即可。

**协议层只跟 `layer` 有关。** Telegram 提升 layer 后，改 `mtproto/mtp_client.py` 里的 `SCHEMA_LAYER`，再对着新的 `api.tl` 核一遍字段顺序。当前用 `233`。

首次运行会自动调 `help.getConfig`，把 DC 地址与 layer 写入 `mtproto/dc_options.json` 和 `mtproto/layer.json`。这两个文件是本机运行时缓存，含账号所在 DC，已列入 `.gitignore`，不随仓库分发。

---

## 目录

```
.
├── tdata/          从 tdata 取 auth_key
├── mtproto/        MTProto 协议实现 + 取块 + 解析守护进程
├── spec/           tgdl:// 直链的编解码
├── relay/          远端加密回传通道（服务端 + 客户端）
├── inject/         客户端注入：让「复制链接」变直链
├── tools/          粘链接就下的外壳
└── docs/           逐步操作说明
```

---

## 快速上手

### 0. 依赖

```bash
python -m pip install pycryptodome cryptography
```

Windows 侧编译注入 DLL 还需要 MinGW-w64（x64，GCC 13 以上）。没有也能用，只是拿不到「右键复制直链」那一步，改成手动 `tg.py resolve` 一样能下。

### 1. 取 auth_key

```bash
python tdata/extract.py --out keys.json
```

只对**已登录、且未设本地密码**的 tdata 生效。设了密码要传 `--passcode`。

这一步只读，不改动 tdata 里任何文件。产出的 `keys.json` 是 5 个 DC 的 256 字节 auth_key，等同于账号凭证，不要外传、不要进仓库。

### 2. 装远端通道

```bash
# 生成自签证书，--cn 必须与客户端 TGDL_SNI 一致
python relay/gencert.py --out ./keys --cn www.microsoft.com

# 上传
scp -r relay keys <USER>@<HOST>:/home/<USER>/tgdl/

# 远端起服务
ssh <USER>@<HOST>
export TGDL_PSK='32 字节以上随机串'
cd /home/<USER>/tgdl
python3 server.py --listen 0.0.0.0:8443 --cert keys/cert.pem --key keys/key.pem --print-pin
```

`--print-pin` 会打印证书 SHA256，客户端拿它做 pinning。

### 3. 拉文件

```bash
export TGDL_PSK='同一个串'
export TGDL_PIN='上一步打印的指纹'
export TGDL_HOST='<HOST>'

python relay/client.py --uri "tgdl://1/2/d/<LOC_B64>/<FREF_B64>/12345/<NAME_B64>/<MIME_B64>" --out ./dl
```

`--out` 给目录时，文件名从 URI 里自动取，不用手写。

入站端口被挡时加 `--via-socks`，走本机已有的 SOCKS5 出网；`TGDL_SOCKS_PORT` 指定端口，缺省 1080。外部隧道模块用 `--via-tunnel` 加载，模块名由 `TGDL_TUNNEL_MODULE` 指定，需自行实现 `open_tunnel(host, port, timeout)` 并返回已连通的 socket。

### 4. 挂上右键菜单（可选，Windows）

```powershell
cd inject
.\build.ps1            # 编 launcher + hook.dll
.\install.ps1          # 备份、部署、改快捷方式
```

装完用 `tgdl_launch.exe` 启动 Telegram（快捷方式会自动指过去），右键任意消息点「复制链接」，剪贴板里就是 `tgdl://`。

卸载：

```powershell
.\restore.ps1
```

### 5. 外壳

```bash
python tools/tgdl.py
```

开个终端收链接，粘一条回车，自动开新窗口下载，主窗口继续等下一条。

---

## 几个必须知道的坑

这些是实打实踩出来的，文档里查不到：

1. **`upload.getFile` 的 `limit` 必须是 4096 的 2 的幂。** 官方文档写 512KB 上限，实际能到 1MB。传 12288 这种非 2 的幂会直接 `LIMIT_INVALID`。
2. **DC 地址要用 `help.getConfig` 里的。** 从 tdata 读到的那批 IP 是历史值，有的已经连不上。
3. **`msg_id` 必须严格递增。** 常驻进程复用连接时，同一纳秒连发两次会触发 `MSGID_DECREASE_RETRY`。
4. **`photo` 的 location 只有 `id + access_hash`。** 老版本的三元组（volume_id / local_id / secret）现在恒为 0，用错了会 `FILE_REFERENCE_EXPIRED`。
5. **DLL 侧加载在 Telegram 上不成立。** 启动早期调了 `SetDefaultDllDirectories`，exe 目录不再优先；`d3dcompiler_47.dll` 那条路也被 Qt 抢先加载并缓存。最后改用启动器 `CreateRemoteThread` 注入才通。
6. **多分片容易把单条隧道压断。** 4 线程跑 200MB 的文件断在 3.4%，降到单线程跑完全程。

第 5 条和第 6 条最耗时，`docs/` 里写了完整过程，包括哪些路走不通、为什么走不通。

---

## 免责

仅供技术研究与个人学习。用它下载什么内容、下载谁的内容，由使用者自行负责，与本仓库无关。

---

## 交流

QQ 群：**1102821216**

bug 肯定也有。遇到了自己私下修一下，作者本人很懒，主打一个能用就行。
