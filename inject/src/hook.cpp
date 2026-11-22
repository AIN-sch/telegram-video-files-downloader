/* tgdl_hook.dll：接管「复制链接」，把 t.me 地址换成 tgdl:// 直链 */
/* 挂点 RVA 仅对 Telegram Desktop 7.4.4.0 (build 7004004) 成立，换版本按 README 重算 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <csetjmp>
#include <cstdarg>
#include <cstdio>
#include <cstring>

#define HOOK_RVA        0x47E3C50ULL   /* Menu 工厂，复制链接项由此创建 */
#define HOOK_STEAL      5              /* mov [rsp+0x10], rbx */

#define TGDL_LOG_NAME   L"tgdl_patch.log"
#define TGDL_PIPE_NAME  L"\\\\.\\pipe\\tgdl_resolve"

#define LOG_LINE_MAX          1024
#define CONSOLE_LINES_PER_SEC 200
#define CLIP_POLL_MS          120
#define ARM_WINDOW_MS         15000
#define PIPE_TIMEOUT_MS       8000

/* GCC x64 无 __try/__except，用向量化异常处理 + setjmp/longjmp 等价替代 */
#define SEH_FRAME_MAX 8
#define SEH_CODE_NONE 0

typedef struct SehFrame_
{
    jmp_buf jb;
    int     armed;
} SehFrame;

static __thread SehFrame g_seh[SEH_FRAME_MAX];
static __thread int      g_seh_depth = 0;
static __thread DWORD    g_seh_code  = SEH_CODE_NONE;

static LONG CALLBACK TgVeh(PEXCEPTION_POINTERS pi)
{
    if (pi == NULL || pi->ExceptionRecord == NULL)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    if (g_seh_depth <= 0)
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    switch (pi->ExceptionRecord->ExceptionCode)
    {
    case EXCEPTION_ACCESS_VIOLATION:
    case EXCEPTION_IN_PAGE_ERROR:
    case EXCEPTION_DATATYPE_MISALIGNMENT:
    case EXCEPTION_ILLEGAL_INSTRUCTION:
    case EXCEPTION_PRIV_INSTRUCTION:
    case EXCEPTION_INT_DIVIDE_BY_ZERO:
    case EXCEPTION_FLT_DIVIDE_BY_ZERO:
    case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        break;
    default:
        return EXCEPTION_CONTINUE_SEARCH;
    }

    int idx = g_seh_depth - 1;
    if (idx >= 0 && idx < SEH_FRAME_MAX && g_seh[idx].armed)
    {
        g_seh[idx].armed = 0;
        g_seh_code = pi->ExceptionRecord->ExceptionCode;
        longjmp(g_seh[idx].jb, 1);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static void TgSehInstall(void)
{
    static volatile LONG once = 0;
    if (InterlockedCompareExchange(&once, 1, 0) == 0)
    {
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        AddVectoredExceptionHandler(1, &TgVeh);
    }
}

void TgLog(const char *fmt, ...);

static void TgSehFault(const char *where)
{
    TgLog("[SEH] contained fault 0x%08lX at %s",
          (unsigned long)g_seh_code, where != NULL ? where : "?");
    g_seh_code = SEH_CODE_NONE;
}

#define TG_TRY_ENTER()                                                         \
    do {                                                                       \
        int t_slot = g_seh_depth;                                              \
        if (t_slot < SEH_FRAME_MAX) {                                          \
            if (setjmp(g_seh[t_slot].jb) != 0) {                               \
                g_seh_depth = t_slot;                                          \
                TgSehFault(__FUNCTION__);                                      \
                goto tg_seh_fail;                                              \
            }                                                                  \
            g_seh[t_slot].armed = 1;                                           \
            g_seh_depth = t_slot + 1;                                          \
        }                                                                      \
    } while (0)

#define TG_TRY_LEAVE()                                                         \
    do {                                                                       \
        if (g_seh_depth > 0) {                                                 \
            g_seh_depth--;                                                     \
            g_seh[g_seh_depth].armed = 0;                                      \
        }                                                                      \
    } while (0)

static wchar_t          g_log_path[MAX_PATH];
static CRITICAL_SECTION g_log_cs;
static int      g_log_ready = 0;
static HANDLE   g_con  = INVALID_HANDLE_VALUE;
static HANDLE   g_file = INVALID_HANDLE_VALUE;
static ULONGLONG g_win_start = 0;
static unsigned  g_win_lines = 0;
static unsigned  g_win_drop  = 0;

static void TgConsoleOpen(void)
{
    if (GetConsoleWindow() == NULL)
    {
        if (AllocConsole() == FALSE)
        {
            return;
        }
        SetConsoleTitleW(L"tgdl hook");
    }
    g_con = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, 0, NULL);
    if (g_con != INVALID_HANDLE_VALUE)
    {
        SetConsoleTextAttribute(g_con, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    }
}

static void TgBuildLogPath(void)
{
    DWORD  n     = GetModuleFileNameW(NULL, g_log_path, MAX_PATH);
    wchar_t *sep = NULL;

    g_log_path[0] = L'\0';
    if (n == 0 || n >= MAX_PATH)
    {
        return;
    }
    sep = wcsrchr(g_log_path, L'\\');
    if (sep == NULL)
    {
        return;
    }
    sep[1] = L'\0';
    wcsncat(g_log_path, TGDL_LOG_NAME,
            MAX_PATH - wcslen(g_log_path) - 1);
}

static void TgLogInit(void)
{
    static volatile LONG once = 0;

    if (InterlockedCompareExchange(&once, 1, 0) != 0)
    {
        return;
    }
    InitializeCriticalSection(&g_log_cs);
    g_log_ready = 1;
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    TgConsoleOpen();
    TgBuildLogPath();
    g_file = CreateFileW(g_log_path, FILE_APPEND_DATA,
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    g_win_start = GetTickCount64();
}

static void TgConWrite(const char *line, size_t len)
{
    if (g_con == INVALID_HANDLE_VALUE || len == 0)
    {
        return;
    }
    ULONGLONG now = GetTickCount64();
    if (now - g_win_start >= 1000ULL)
    {
        if (g_win_drop != 0)
        {
            char note[128];
            int m = snprintf(note, sizeof(note),
                             "[console throttle] %u lines suppressed\r\n", g_win_drop);
            if (m > 0)
            {
                DWORD w = 0;
                WriteConsoleA(g_con, note, (DWORD)m, &w, NULL);
            }
        }
        g_win_start = now;
        g_win_lines = 0;
        g_win_drop  = 0;
    }
    if (g_win_lines >= CONSOLE_LINES_PER_SEC)
    {
        g_win_drop++;
        return;
    }
    g_win_lines++;

    DWORD w = 0;
    WriteConsoleA(g_con, line, (DWORD)len, &w, NULL);
}

void TgLog(const char *fmt, ...)
{
    char body[LOG_LINE_MAX];
    int  n = 0;

    TgLogInit();

    SYSTEMTIME st;
    GetLocalTime(&st);
    n = snprintf(body, sizeof(body), "[%02u:%02u:%02u.%03u][t%05lu] ",
                 (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
                 (unsigned)st.wMilliseconds, (unsigned long)GetCurrentThreadId());
    if (n < 0)
    {
        return;
    }
    if (n > (int)sizeof(body) - 4)
    {
        n = (int)sizeof(body) - 4;
    }

    va_list ap;
    va_start(ap, fmt);
    int vn = vsnprintf(body + n, sizeof(body) - (size_t)n - 2, fmt, ap);
    va_end(ap);
    if (vn < 0)
    {
        return;
    }
    n += vn;
    if (n > (int)sizeof(body) - 3)
    {
        n = (int)sizeof(body) - 3;
    }
    body[n++] = '\r';
    body[n++] = '\n';
    body[n]   = '\0';

    if (g_log_ready)
    {
        EnterCriticalSection(&g_log_cs);
    }
    if (g_file != INVALID_HANDLE_VALUE)
    {
        DWORD w = 0;
        WriteFile(g_file, body, (DWORD)n, &w, NULL);
        FlushFileBuffers(g_file);
    }
    TgConWrite(body, (size_t)n);
    if (g_log_ready)
    {
        LeaveCriticalSection(&g_log_cs);
    }
}

static void TgHexDump(const char *tag, const void *p, int len)
{
    const BYTE *b = (const BYTE *)p;
    char line[256];
    int  n = 0;

    if (p == NULL || len <= 0 || len > 64)
    {
        TgLog("%s dump skipped ptr=%p len=%d", tag, p, len);
        return;
    }
    n = snprintf(line, sizeof(line), "%s", tag);
    for (int i = 0; i < len && n > 0 && n < (int)sizeof(line) - 4; i++)
    {
        n += snprintf(line + n, sizeof(line) - (size_t)n, " %02X", b[i]);
    }
    TgLog("%s", line);
}

static void TgWsToAscii(const wchar_t *src, char *dst, size_t cap)
{
    size_t i = 0;

    if (dst == NULL || cap == 0)
    {
        return;
    }
    if (src == NULL)
    {
        dst[0] = '\0';
        return;
    }
    for (; src[i] != L'\0' && i + 1 < cap; i++)
    {
        wchar_t c = src[i];
        dst[i] = (c >= 0x20 && c < 0x7F) ? (char)c : '.';
    }
    dst[i] = '\0';
}

static void *TgAllocNear(const void *anchor, size_t size)
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    ULONG_PTR anchor_v = (ULONG_PTR)anchor;
    ULONG_PTR gran     = (ULONG_PTR)si.dwAllocationGranularity;
    const ULONG_PTR kWindow = 0x60000000ULL;

    ULONG_PTR low  = (anchor_v > kWindow) ? (anchor_v - kWindow) : gran;
    ULONG_PTR high = anchor_v + kWindow;

    low = (low + gran - 1) & ~(gran - 1);

    for (ULONG_PTR delta = 0; delta < kWindow; delta += gran)
    {
        ULONG_PTR cands[2];
        int cnt = 0;
        if (anchor_v + delta < high)
        {
            cands[cnt++] = anchor_v + delta;
        }
        if (anchor_v > low + delta)
        {
            cands[cnt++] = anchor_v - delta;
        }
        for (int i = 0; i < cnt; i++)
        {
            void *p = VirtualAlloc((LPVOID)cands[i], size,
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
            if (p != NULL)
            {
                return p;
            }
        }
    }
    return NULL;
}

typedef INT64 (WINAPI *PFN_MenuFactory)(void *, void *, void *, void *, void *);

static PFN_MenuFactory g_orig       = NULL;
static volatile LONG   g_armed_tick = 0;
static volatile LONG   g_hook_calls = 0;
static volatile LONG   g_clip_hits  = 0;

static void TgBuildAbsJump(BYTE *dst, const void *target)
{
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    memcpy(dst + 6, &target, sizeof(void *));
}

/* 蹦床：修正 rsp 相对位移后 jmp 回 target+steal。
 *
 * 蹦床经 call 进入，此时 rsp 比原函数入口低 8 字节（call 压入的返回地址），
 * 因此被搬走的指令里所有 [rsp+disp] 都要减 8 才能指向同一内存位置。
 * 本 hook 只搬 1 条 mov [rsp+0x10],rbx，改写为 mov [rsp+0x08],rbx 即可。
 * 蹦床末尾用 jmp 而不是 ret，rsp 全程不变，target+steal 处的栈布局与未 hook 时一致。 */
static BYTE *TgBuildTrampoline(BYTE *target, const BYTE *stolen, int stolen_len)
{
    SIZE_T total = (SIZE_T)stolen_len + 14 + 16;
    BYTE *mem = (BYTE *)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE);
    if (mem == NULL)
    {
        return NULL;
    }

    SIZE_T i = 0;

    if (stolen_len == 5 && stolen[0] == 0x48 && stolen[1] == 0x89 &&
        stolen[2] == 0x5C && stolen[3] == 0x24)
    {
        /* mov [rsp+disp8], rbx  → disp8 减 8 */
        mem[i++] = 0x48;
        mem[i++] = 0x89;
        mem[i++] = 0x5C;
        mem[i++] = 0x24;
        mem[i++] = (BYTE)(stolen[4] - 8);
    }
    else
    {
        memcpy(mem + i, stolen, (size_t)stolen_len);
        i += (SIZE_T)stolen_len;
    }

    const void *back = (const void *)(target + stolen_len);
    TgBuildAbsJump(mem + i, back);
    i += 14;

    FlushInstructionCache(GetCurrentProcess(), mem, i);
    TgLog("[hook] trampoline disp patched: %02X %02X %02X %02X %02X",
          mem[0], mem[1], mem[2], mem[3], mem[4]);
    return mem;
}

static int TgPipeResolve(const wchar_t *link, wchar_t *uriOut, size_t uriCap)
{
    if (link == NULL || uriOut == NULL || uriCap < 8)
    {
        return 0;
    }
    uriOut[0] = L'\0';

    HANDLE h = CreateFileW(TGDL_PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE)
    {
        TgLog("[pipe] open failed gle=%lu (daemon 未运行或无权限)",
              (unsigned long)GetLastError());
        return 0;
    }

    char req[2048];
    char linkA[1600];
    TgWsToAscii(link, linkA, sizeof(linkA));
    int rn = snprintf(req, sizeof(req), "{\"link\":\"%s\"}\n", linkA);
    if (rn <= 0)
    {
        CloseHandle(h);
        return 0;
    }

    DWORD wrote = 0;
    if (!WriteFile(h, req, (DWORD)rn, &wrote, NULL) || wrote != (DWORD)rn)
    {
        TgLog("[pipe] write failed gle=%lu", (unsigned long)GetLastError());
        CloseHandle(h);
        return 0;
    }

    char resp[8192];
    DWORD got = 0;
    if (!ReadFile(h, resp, (DWORD)sizeof(resp) - 1, &got, NULL) || got == 0)
    {
        TgLog("[pipe] read failed gle=%lu", (unsigned long)GetLastError());
        CloseHandle(h);
        return 0;
    }
    CloseHandle(h);
    resp[got] = '\0';

    char *key = strstr(resp, "\"uri\"");
    if (key == NULL)
    {
        TgLog("[pipe] no uri: %.240s", resp);
        return 0;
    }
    char *p = strchr(key, ':');
    if (p == NULL)
    {
        return 0;
    }
    p++;
    while (*p == ' ' || *p == '\t')
    {
        p++;
    }
    if (*p != '"')
    {
        return 0;
    }
    p++;
    char *end = strchr(p, '"');
    if (end == NULL)
    {
        return 0;
    }
    *end = '\0';

    if (MultiByteToWideChar(CP_UTF8, 0, p, -1, uriOut, (int)uriCap) <= 0)
    {
        uriOut[0] = L'\0';
        return 0;
    }
    return 1;
}

static int TgReadClipboardText(wchar_t *out, size_t cap)
{
    int ok = 0;

    out[0] = L'\0';
    if (!OpenClipboard(NULL))
    {
        return 0;
    }
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h != NULL)
    {
        const wchar_t *p = (const wchar_t *)GlobalLock(h);
        if (p != NULL)
        {
            size_t i = 0;
            for (; p[i] != L'\0' && i + 1 < cap; i++)
            {
                out[i] = p[i];
            }
            out[i] = L'\0';
            if (i > 0)
            {
                ok = 1;
            }
            GlobalUnlock(h);
        }
    }
    CloseClipboard();
    return ok;
}

static int TgWriteClipboardText(const wchar_t *text)
{
    if (text == NULL)
    {
        return 0;
    }
    size_t n = wcslen(text);
    if (n == 0 || n > 6000)
    {
        return 0;
    }
    if (!OpenClipboard(NULL))
    {
        return 0;
    }
    int ok = 0;
    if (EmptyClipboard())
    {
        HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (n + 1) * sizeof(wchar_t));
        if (h != NULL)
        {
            void *dst = GlobalLock(h);
            if (dst != NULL)
            {
                memcpy(dst, text, n * sizeof(wchar_t));
                ((wchar_t *)dst)[n] = L'\0';
                GlobalUnlock(h);
                if (SetClipboardData(CF_UNICODETEXT, h) != NULL)
                {
                    ok = 1;
                }
                else
                {
                    GlobalFree(h);
                }
            }
            else
            {
                GlobalFree(h);
            }
        }
    }
    CloseClipboard();
    return ok;
}

static INT64 WINAPI TgMenuFactoryHook(void *a1, void *a2, void *a3, void *a4, void *a5)
{
    INT64 r = 0;
    LONG n = 0;

    TG_TRY_ENTER();
    {
        n = InterlockedIncrement(&g_hook_calls);
        InterlockedExchange(&g_armed_tick,
                            (LONG)((GetTickCount64() & 0x7FFFFFFF) | 1));
        if (n <= 3 || (n % 100) == 0)
        {
            TgLog("[menu] #%ld built, clipboard may arm", n);
        }
    }
    TG_TRY_LEAVE();

    /* 原函数必须被调用，参数原样透传 */
    r = g_orig(a1, a2, a3, a4, a5);

    if (0)
    {
        goto tg_seh_fail;
    }
    return r;

tg_seh_fail:
    if (g_orig != NULL)
    {
        r = g_orig(a1, a2, a3, a4, a5);
    }
    return r;
}

static int TgIsTmeLink(const wchar_t *s)
{
    return wcsncmp(s, L"https://t.me/", 13) == 0 ||
           wcsncmp(s, L"https://telegram.me/", 20) == 0;
}

static void TgStripQuery(const wchar_t *src, wchar_t *dst, size_t cap)
{
    size_t i = 0;

    if (dst == NULL || cap == 0)
    {
        return;
    }
    dst[0] = L'\0';
    if (src == NULL)
    {
        return;
    }
    for (; src[i] != L'\0' && i + 1 < cap; i++)
    {
        if (src[i] == L'?' || src[i] == L'#')
        {
            break;
        }
        dst[i] = src[i];
    }
    dst[i] = L'\0';
}

static DWORD WINAPI TgClipboardThread(LPVOID param)
{
    (void)param;

    wchar_t prev[4096];
    wchar_t cur[4096];

    prev[0] = L'\0';
    TgLog("[clip] watcher started poll=%dms window=%dms", CLIP_POLL_MS, ARM_WINDOW_MS);

    for (;;)
    {
        if (TgReadClipboardText(cur, 4096) && wcscmp(cur, prev) != 0)
        {
            wcscpy(prev, cur);

            LONG armed = InterlockedCompareExchange(&g_armed_tick, 0, 0);
            ULONGLONG now = GetTickCount64();
            int fresh = (armed != 0) &&
                        ((ULONG)(now - (ULONGLONG)(unsigned)armed) < ARM_WINDOW_MS);

            if (fresh && TgIsTmeLink(cur) && wcsstr(cur, L"tgdl://") == NULL)
            {
                InterlockedExchange(&g_armed_tick, 0);

                wchar_t clean[4096];
                wchar_t uri[4096];
                TgStripQuery(cur, clean, 4096);
                if (TgPipeResolve(clean, uri, 4096))
                {
                    if (TgWriteClipboardText(uri))
                    {
                        wcscpy(prev, uri);
                        LONG k = InterlockedIncrement(&g_clip_hits);
                        TgLog("[clip] #%ld -> %.200ls", k, uri);
                        Beep(1200, 60);
                    }
                    else
                    {
                        TgLog("[clip] set clipboard failed");
                    }
                }
                else
                {
                    TgLog("[clip] resolve failed, kept t.me link");
                    Beep(400, 90);
                }
            }
            else
            {
                TgLog("[clip] changed len=%d tme=%d",
                      (int)wcslen(cur), TgIsTmeLink(cur));
            }
        }
        Sleep(CLIP_POLL_MS);
    }
    return 0;
}

static int TgInstallHook(void)
{
    HMODULE base = GetModuleHandleW(NULL);
    if (base == NULL)
    {
        return 0;
    }

    BYTE *target = (BYTE *)base + HOOK_RVA;

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(target, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT)
    {
        TgLog("[hook] target not committed ptr=%p", (void *)target);
        return 0;
    }

    BYTE orig[HOOK_STEAL];
    memcpy(orig, target, HOOK_STEAL);
    TgHexDump("[hook] steer bytes", orig, HOOK_STEAL);

    BYTE *relay = (BYTE *)TgAllocNear(target, 4096);
    if (relay == NULL)
    {
        TgLog("[hook] relay alloc failed");
        return 0;
    }

    BYTE *tramp = TgBuildTrampoline(target, orig, HOOK_STEAL);
    if (tramp == NULL)
    {
        TgLog("[hook] trampoline alloc failed");
        return 0;
    }
    g_orig = (PFN_MenuFactory)tramp;

    TgBuildAbsJump(relay, (const void *)&TgMenuFactoryHook);
    FlushInstructionCache(GetCurrentProcess(), relay, 14);

    LONG_PTR delta = (LONG_PTR)relay - (LONG_PTR)(target + 5);
    if (delta > 0x7FFFFFFFLL || delta < -0x7FFFFFFFLL)
    {
        TgLog("[hook] relay out of rel32 range delta=%lld", (long long)delta);
        return 0;
    }

    DWORD old = 0;
    if (!VirtualProtect(target, HOOK_STEAL, PAGE_EXECUTE_READWRITE, &old))
    {
        TgLog("[hook] VirtualProtect failed gle=%lu", (unsigned long)GetLastError());
        return 0;
    }

    BYTE patch[HOOK_STEAL];
    patch[0] = 0xE9;
    LONG rel32 = (LONG)delta;
    memcpy(patch + 1, &rel32, 4);
    memcpy(target, patch, HOOK_STEAL);
    FlushInstructionCache(GetCurrentProcess(), target, HOOK_STEAL);

    DWORD tmp = 0;
    VirtualProtect(target, HOOK_STEAL, old, &tmp);

    TgLog("[hook] INSTALLED target=%p relay=%p tramp=%p steal=%d rel32=0x%08lX",
          (void *)target, (void *)relay, (void *)tramp,
          HOOK_STEAL, (unsigned long)(ULONG)rel32);
    return 1;
}

static DWORD WINAPI TgWorker(LPVOID param)
{
    (void)param;
    TgLogInit();
    TgSehInstall();

    wchar_t self[MAX_PATH];
    char    selfA[MAX_PATH];
    DWORD   n = GetModuleFileNameW(NULL, self, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
    {
        self[0] = L'\0';
    }
    TgWsToAscii(self, selfA, sizeof(selfA));

    TgLog("==================================================");
    TgLog("TGDL HOOK LOADED  build=3.0.0 passive");
    TgLog("==================================================");
    TgLog("[init] host   : %s", selfA);
    TgLog("[init] pid    : %lu", (unsigned long)GetCurrentProcessId());
    TgLog("[init] target : rva=0x%llX steal=%d", (unsigned long long)HOOK_RVA, HOOK_STEAL);
    TgLog("[init] mode   : clipboard takeover (menu untouched)");

    int ok = TgInstallHook();
    TgLog("[init] hook installed=%d", ok);

    HANDLE th = CreateThread(NULL, 0, &TgClipboardThread, NULL, 0, NULL);
    if (th != NULL)
    {
        CloseHandle(th);
    }
    TgLog("[init] ready");

    return 0;
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    (void)lpvReserved;

    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE th = CreateThread(NULL, 0, &TgWorker, NULL, 0, NULL);
        if (th != NULL)
        {
            CloseHandle(th);
        }
    }
    return TRUE;
}

extern "C" __declspec(dllexport)
const char * __stdcall TgdlHookVersion(void)
{
    return "tgdl-hook/3.0.0-passive+gcc13.1-x64";
}
