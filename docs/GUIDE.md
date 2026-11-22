# 逐步操作

按顺序做，每一步都能单独验证。卡住了先看该节的「怎么确认」。

---

## 一、先判 Telegram 能不能改

动手前判三件事：有没有壳、有没有加密、有没有自校验。判错后面全白干。

```powershell
python -c "
import pefile, math
from collections import Counter
pe = pefile.PE(r'<Telegram.exe>', fast_load=True)
for s in pe.sections:
    d = s.get_data(); c = Counter(d); n = len(d)
    ent = -sum((v/n) * math.log2(v/n) for v in c.values()) if d else 0
    print('%-10s VA=0x%08X  ent=%.3f' % (s.Name.rstrip(b'\0').decode(), s.VirtualAddress, ent))
"
```

看熵。`.text` 在 6.5 附近、`.data` 在 5 左右、有个节全零，这是正常编译产物的样子。某一节熵接近 8 说明被压缩过，即加壳。

再看自校验：

```powershell
python -c "
d = open(r'<Telegram.exe>', 'rb').read()
for t in [b'WinVerifyTrust', b'wintrust', b'CryptVerifySignature']:
    print(t, d.count(t))
"
```

全 0 说明它不检查自身签名。改完签名失效，程序照常运行。

**怎么确认**：`.text` 熵 6.x、上述三个字符串全 0 命中，可以动手。

---

## 二、取 auth_key

登录态存在 `tdata` 里，加密方式是 AES-256-IGE，密钥由 passcode + salt 推出。

未设本地密码时 passcode 为空串，可直接解。

```bash
python tdata/extract.py \
  --tdata "%APPDATA%\Telegram Desktop\tdata" \
  --out keys.json
```

**怎么确认**：脚本会打印每个 DC 的 key 前 8 字节。真 key 不可能是全零或全同值，五条互不相同即为正确。

解不开的常见原因：

- 设了本地密码 → 加 `--passcode '<密码>'`
- Portable 模式 → tdata 可能在别的目录，确认路径
- 程序正在运行 → 先退干净，锁文件会导致读取失败

这一步只读，不改 tdata 任何东西。产出的 `keys.json` 等同账号凭证，不外传。

---

## 三、MTProto 客户端

### 3.1 加密层

| 项 | 值 |
|---|---|
| auth_key_id | `SHA1(auth_key)` 取低 8 字节 |
| msg_key | v2 为 `SHA256(...)` 中间截 16 字节，偏移与 v1 不同 |
| 加密 | AES-256-IGE，key/iv 拼接顺序容易搞反 |
| layer | 233 |

layer 用错会直接崩在 schema 解析上，服务端返回的构造体变了。

### 3.2 取块

```
upload.getFile(
    location=<FileLocation>,
    offset=<字节偏移>,
    limit=<4096 * 2^k，最大 1048576>
)
```

**limit 约束**：必须是 4096 的 2 的幂。4096 / 8192 / ... / 524288 / 1048576 都可用，12288 这类直接 `LIMIT_INVALID`。官方文档写的 512KB 上限已过时。

**offset 越界**会 `OFFSET_INVALID`，最后一块按剩余字节下取：

```python
remaining = total - offset
limit = min(limit, remaining)
```

### 3.3 DC 地址

不要用 keys.json 里那批 IP，那是历史值。正确做法是调 `help.getConfig`，从 `dc_options` 取。

连不上的典型症状是 SOCKS5 返回 `reply=4`（host unreachable），此时换列表里下一个地址重试。

### 3.4 msg_id

高 32 位为 unix 秒，低 32 位为纳秒计数，同一条连接上必须严格递增。

常驻进程最容易出这个问题：同一纳秒连发两次，或系统时钟回拨，服务端返回 `MSGID_DECREASE_RETRY`。修法很土但管用：

```python
if mid <= last:
    mid = last + 4
last = mid
```

### 3.5 photo 的 location

当前 layer 的 `Photo` 只给 `id`、`access_hash`、`file_reference`、`dc_id`，`volume_id` / `local_id` 恒为 0。

取块必须用 `inputPhotoFileLocation(id, access_hash, file_reference, thumb_size)`。用 `inputDocumentFileLocation` 会 `FILE_REFERENCE_EXPIRED`。

`thumb_size` 常见值：`m`（小）、`x`（中）、`y`（大）、`w`。一般用 `y`。

### 3.6 file_reference 是易失的

每次 `channels.getMessages` 都可能返回新的 `file_reference`。24 小时内取块不会过期，超了要重新 resolve。

URI 里必须带上它，过期就重新解析一次链接。

**怎么确认**：跑 `python mtproto/tg.py resolve "https://t.me/<频道>/<消息ID>"`，能打出 DC、大小、文件名即通。再用 `download` 拿到的文件跑 `ffprobe`，`h264 + aac` 这种就对了。

---

## 四、定义 tgdl:// 格式

没有 HTTP 直链，自定义一个能自我描述的 URI：

```
tgdl://<版本>/<DC>/<类型>/<location_b64>/<file_reference_b64>/<大小>/<文件名_b64>/<MIME_b64>
```

`location` 按类型打包成紧凑二进制（小端）：

| 类型 | 布局 | 长度 |
|---|---|---|
| `d` 文档/视频/音频 | `volume_id:u64` `local_id:i32` `id:i64` `access_hash:i64` | 28 |
| `p` 图片 | `id:i64` `access_hash:i64` `thumb_len:u8` `thumb_utf8` | 17+n |
| `w` webFile | `id:i64` `access_hash:i64` | 16 |
| `m` 贴纸 | `len:u16` `bytes` | 2+n |

base64 用 url-safe 并去掉填充，一条链接一百二十来个字符，塞剪贴板刚好。

编解码在 `spec/tgdl_uri.py`，单文件无依赖，可直接抄。

**怎么确认**：`decode(encode(x)) == x`，字段逐个比对，尤其 `access_hash` 为负数的情况。

---

## 五、让「复制链接」变直链

> 本节所有 RVA 只在 **Telegram Desktop 7.4.4.0（build 7004004）** 上验证过。
> 版本更新后注入这步大概率直接用不了，先看 README 的「版本兼容性」重算 RVA。

### 5.1 走不通的两条路

两个方向都试过，都失败，写下来省得重走。

**version.dll 侧加载。** Telegram 只 delay-import 了三个函数，看着很合适。但程序启动早期调了 `SetDefaultDllDirectories`，DLL 搜索路径被限制到 System32 那批受控目录，exe 目录不再优先，最终加载的仍是 `C:\Windows\SYSTEM32\VERSION.dll`。

**d3dcompiler_47.dll 替换。** 程序按全路径加载 `modules\x64\d3d\` 下那份，理论上能换。实际是 Qt/ANGLE 在更早阶段已用裸名加载 System32 那份并缓存，等程序按路径加载时模块已存在，直接命中缓存。

判断最终加载了哪个，看程序自己的日志：

```powershell
Select-String '<安装目录>\log.txt' -Pattern 'DirectX compiler'
# 指向 C:\Windows\SYSTEM32\... 说明自制那份没被用上
```

或直接看进程模块：

```powershell
(Get-Process Telegram).Modules | ? ModuleName -like 'd3dcompiler*' | Select ModuleName, FileName
```

### 5.2 改用启动器注入

不依赖任何搜索顺序，自己开进程自己注入：

```
CreateProcessW(exe, ..., CREATE_SUSPENDED)
VirtualAllocEx + WriteProcessMemory(LoadLibraryW 的完整路径)
CreateRemoteThread(LoadLibraryW)
ResumeThread
```

参数原样透传。检测到已有实例则不重复注入，直接 ShellExecute 原 exe，交给它的单实例逻辑。

快捷方式改为指向 launcher，图标保持原样。

### 5.3 挂点选择

`inject/src/hook.cpp` 挂的是菜单工厂 `RVA 0x47E3C50`，入口指令：

```
48 89 5C 24 10    mov [rsp+0x10], rbx      ← 正好 5 字节
```

5 字节装不下 14 字节的绝对跳转，因此用二级跳：目标处写 `E9 rel32` 跳到附近分配的 relay 页，relay 里再用 `FF 25` 绝对跳进 DLL。

**蹦床要修 rsp 位移。** 蹦床经 `call` 进入，rsp 比原函数入口低 8，被搬过去的 `[rsp+disp]` 全部错位。本例只搬一条指令，直接改 disp 最省事：

```c
if (stolen_len == 5 && stolen[0] == 0x48 && stolen[1] == 0x89 &&
    stolen[2] == 0x5C && stolen[3] == 0x24) {
    mem[i++] = 0x48; mem[i++] = 0x89; mem[i++] = 0x5C; mem[i++] = 0x24;
    mem[i++] = (BYTE)(stolen[4] - 8);      // disp8 减 8
}
```

### 5.4 为什么不改菜单文字

最初想直接加一个「复制直链」的项。实测发现菜单标签由**云端语言包**下发，二进制里 `lng_context_copy_link` 这类键 ASCII 与 UTF-16 均为 0 命中，本地没有可改的字符串。若要从菜单容器对象里扫 QString，又依赖随版本漂移的结构偏移，强改会崩。

于是换思路：**不碰菜单，事后接管**。

hook 只记录菜单被打开的时刻，剪贴板线程发现 `t.me` 链接且处在该时间窗内，就调本地守护进程换成 `tgdl://`。对光标位置、语言、消息类型均不敏感，也不碰宿主数据结构。

效果一样，风险低一个数量级。

### 5.5 SEH

MinGW 没有 MSVC 的 `__try / __except`，用向量化异常处理配合 `setjmp / longjmp` 顶上。只接管访存与算术类异常，其余照常上抛。

**铁律：hook 里不管探测成不成功，原函数必须被调用。** 这里栽过一次——异常后直接 `return 0`，调用方拿不到 `QAction*`，进程静默退出，日志里什么都看不出来。

**怎么确认**：看 `tgdl_patch.log`，应出现 `hook INSTALLED` 与 `ready`；右键一条消息点「复制链接」，剪贴板应为 `tgdl://` 开头。

---

## 六、加密回传通道

### 6.1 为什么要这一段

VPS 拉下来的文件要回到本机。FTP/HTTP 是明文；SCP 能用但没法断点续传，也不好做多线程。

自写一个，四层：

| 层 | 做法 |
|---|---|
| 传输 | TLS 1.3，自签证书 |
| 身份 | 证书 sha256 pinning，防中间人换证书 |
| 认证 | 双方各出一个 nonce，HMAC(PSK) 互验，带时间戳防重放 |
| 数据 | HKDF 从 PSK 派生会话密钥，每帧 AES-256-GCM，seq 严格递增 |

帧格式：

```
TGD1 | seq:u64 | type:u8 | len:u32 | ciphertext | tag:16
```

AAD 取前 17 字节头，seq 乱序或重复直接断链。

类型：`AUTH=1 PING=2 GET=3 DATA=4 META=5 DONE=6 ERR=7`，单帧 DATA 不超过 256KB。

### 6.2 源做成可插拔

服务端不关心字节从哪来，只看 `fetcher.open_source`：

```python
async def open_source(spec, start_offset=0, length=None):
    # 返回 (meta, 异步迭代器)，迭代器按 offset 顺序吐 bytes
```

接 HTTP 源就写一个 HTTP 版本，接 MTProto 就 import `mtproto/fetcher.py`。`import` 外面包 try，缺了只剩 HTTP 模式，不影响其他。

### 6.3 端口不通怎么办

VPS 入站端口被云安全组挡住很常见。症状是 `tcpdump` 一个 SYN 都抓不到，本地却显示连不上。

两条路：

1. 云控制台放行端口，客户端直连。
2. 借一条已有 SOCKS5 出网，功能等价，速率略低。

### 6.4 线程数控制

实测 4 线程跑 200MB 会把单条隧道压断，断在 3.4%；降到 1 线程跑完全程。

多线程要用的话，先确认隧道带得动，或让每个分片各走一条独立连接。

**怎么确认**：`client.py` 下完会打 sha256，与源文件一致即可。

---

## 七、收尾

装完注入后，日常三步：

1. 用 launcher 启动 Telegram
2. 右键消息 → 复制链接
3. 粘给 `tools/tgdl.py`

卸载：`inject/restore.ps1`，会把快捷方式改回去并删掉注入的文件。`Telegram.exe` 与 `tdata` 全程未动。

---

## 排错表

| 现象 | 原因 | 处置 |
|---|---|---|
| `MSGID_DECREASE_RETRY` | msg_id 未递增 | 强制 `mid = last + 4` |
| `LIMIT_INVALID` | limit 不是 4096×2^k | 按 2 的幂取，上限 1048576 |
| `OFFSET_INVALID` | offset+limit 越界 | 按剩余字节下取 |
| `FILE_REFERENCE_EXPIRED` | file_reference 过期 | 重新 resolve |
| `FILE_MIGRATE_n` | 文件在别的 DC | 切到目标 DC 重试 |
| SOCKS5 `reply=4` | DC 地址不可达 | 换 `dc_options` 里其他地址 |
| 下载中途断链 | 多分片压垮隧道 | 降线程数，`--resume` 续 |
| 进程启动即退 | hook 异常后未调原函数 | 保证原函数必被调用 |
| 注入 DLL 未生效 | `SetDefaultDllDirectories` | 改用启动器注入 |
