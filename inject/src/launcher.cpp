/* tgdl_launch.exe：挂起方式启动 Telegram.exe，注入 tgdl_hook.dll 后自身退出 */
/* 不依赖 DLL 搜索顺序或签名校验，命令行参数原样透传 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <shellapi.h>
#include <cstdio>
#include <cstring>

#define TGDL_TARGET_NAME L"Telegram.exe"
#define TGDL_HOOK_NAME   L"tgdl_hook.dll"
#define TGDL_LOG_NAME    L"tgdl_patch.log"
#define MUTEX_SWALLOW_MS 2500

static wchar_t g_self_dir[MAX_PATH];
static wchar_t g_target[MAX_PATH];
static wchar_t g_dll[MAX_PATH];
static wchar_t g_log_path[MAX_PATH];
static HANDLE  g_log = INVALID_HANDLE_VALUE;

/* 按自身所在目录拼出目标、DLL 与日志路径 */
static void ResolvePaths(void)
{
    DWORD  n     = GetModuleFileNameW(NULL, g_self_dir, MAX_PATH);
    wchar_t *sep = NULL;

    g_self_dir[0] = L'\0';
    if (n == 0 || n >= MAX_PATH)
    {
        return;
    }
    sep = wcsrchr(g_self_dir, L'\\');
    if (sep == NULL)
    {
        return;
    }
    sep[1] = L'\0';
    wcsncpy(g_target, g_self_dir, MAX_PATH - 1);
    wcsncat(g_target, TGDL_TARGET_NAME, MAX_PATH - wcslen(g_target) - 1);
    wcsncpy(g_dll, g_self_dir, MAX_PATH - 1);
    wcsncat(g_dll, TGDL_HOOK_NAME, MAX_PATH - wcslen(g_dll) - 1);
    wcsncpy(g_log_path, g_self_dir, MAX_PATH - 1);
    wcsncat(g_log_path, TGDL_LOG_NAME, MAX_PATH - wcslen(g_log_path) - 1);
}

static void LogLine(const char *fmt, ...)
{
    char body[1024];
    int  off = 0;

    SYSTEMTIME st;
    GetLocalTime(&st);
    off = snprintf(body, sizeof(body), "[%02u:%02u:%02u.%03u] ",
                   (unsigned)st.wHour, (unsigned)st.wMinute,
                   (unsigned)st.wSecond, (unsigned)st.wMilliseconds);
    if (off < 0)
    {
        return;
    }

    va_list ap;
    va_start(ap, fmt);
    int vn = vsnprintf(body + off, sizeof(body) - (size_t)off - 3, fmt, ap);
    va_end(ap);
    if (vn < 0)
    {
        return;
    }
    off += vn;
    if (off > (int)sizeof(body) - 3)
    {
        off = (int)sizeof(body) - 3;
    }
    body[off++] = '\r';
    body[off++] = '\n';
    body[off]   = '\0';

    if (g_log != INVALID_HANDLE_VALUE)
    {
        DWORD wrote = 0;
        WriteFile(g_log, body, (DWORD)off, &wrote, NULL);
        FlushFileBuffers(g_log);
    }
}

static void LogOpen(void)
{
    g_log = CreateFileW(g_log_path,
                        FILE_APPEND_DATA,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
}

static HANDLE g_console = INVALID_HANDLE_VALUE;

static void ConsoleOpen(void)
{
    if (GetConsoleWindow() == NULL)
    {
        if (AllocConsole() == FALSE)
        {
            return;
        }
        SetConsoleTitleW(L"tgdl launcher");
    }
    g_console = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            NULL, OPEN_EXISTING, 0, NULL);
}

static void ConWrite(const char *s)
{
    if (g_console == INVALID_HANDLE_VALUE)
    {
        return;
    }
    DWORD wrote = 0;
    WriteConsoleA(g_console, s, (DWORD)strlen(s), &wrote, NULL);
}

static void LogBoth(const char *fmt, ...)
{
    char body[1024];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    LogLine("%s", body);
    ConWrite(body);
    ConWrite("\r\n");
}

/* 已存在 Telegram 实例时只把命令行转发过去，让单实例逻辑生效 */
static int ForwardToRunningInstance(void)
{
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == NULL)
    {
        return 1;
    }

    SHELLEXECUTEINFOW si;
    ZeroMemory(&si, sizeof(si));
    si.cbSize = sizeof(si);
    si.fMask  = SEE_MASK_NOCLOSEPROCESS;
    si.lpVerb = L"open";
    si.lpFile = g_target;

    /* 首参数是 launcher 自身，必须跳过 */
    if (argc > 1)
    {
        si.lpParameters = argv[1];
    }
    si.nShow = SW_SHOWNORMAL;

    LogBoth("HOOK SKIP: telegram already running, forwarding command line");
    BOOL ok = ShellExecuteExW(&si);
    LogBoth("forward ShellExecuteEx=%ld gle=%lu", (long)ok, (unsigned long)GetLastError());
    if (si.hProcess != NULL)
    {
        CloseHandle(si.hProcess);
    }
    LocalFree(argv);
    return 0;
}

static int InjectAndRun(void)
{
    wchar_t cmdline[32768];
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (argv == NULL)
    {
        LogBoth("LAUNCH FAIL: CommandLineToArgvW gle=%lu", (unsigned long)GetLastError());
        return 2;
    }

    /* 重建命令行：目标 exe + launcher 收到的全部参数 */
    int n = swprintf(cmdline, 32768, L"\"%ls\"", g_target);
    if (n <= 0)
    {
        LocalFree(argv);
        return 2;
    }
    for (int i = 1; i < argc; i++)
    {
        int m = swprintf(cmdline + n, (size_t)(32768 - n), L" \"%ls\"", argv[i]);
        if (m <= 0)
        {
            break;
        }
        n += m;
    }
    LocalFree(argv);

    LogBoth("LAUNCH cmdline: %ls", cmdline);

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    BOOL ok = CreateProcessW(g_target, cmdline, NULL, NULL, FALSE,
                             CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                             NULL, g_self_dir, &si, &pi);
    if (!ok)
    {
        LogBoth("LAUNCH FAIL: CreateProcessW gle=%lu", (unsigned long)GetLastError());
        return 3;
    }
    LogBoth("LAUNCH pid=%lu suspended", (unsigned long)pi.dwProcessId);

    /* 写入 DLL 路径，然后远程调用 LoadLibraryW */
    const wchar_t *dll = g_dll;
    SIZE_T bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(pi.hProcess, NULL, bytes,
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote == NULL)
    {
        LogBoth("INJECT FAIL: VirtualAllocEx gle=%lu", (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote, dll, bytes, &written) || written != bytes)
    {
        LogBoth("INJECT FAIL: WriteProcessMemory gle=%lu", (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC loadLib = k32 ? GetProcAddress(k32, "LoadLibraryW") : NULL;
    if (loadLib == NULL)
    {
        LogBoth("INJECT FAIL: LoadLibraryW unresolved");
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    /* 按字节拷贝函数指针，避开 FARPROC 到线程原型的类型转换告警 */
    LPTHREAD_START_ROUTINE start_fn = NULL;
    memcpy(&start_fn, &loadLib, sizeof(loadLib));

    HANDLE th = CreateRemoteThread(pi.hProcess, NULL, 0, start_fn, remote, 0, NULL);
    if (th == NULL)
    {
        LogBoth("INJECT FAIL: CreateRemoteThread gle=%lu", (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 4;
    }

    DWORD wait = WaitForSingleObject(th, 20000);
    DWORD modBase = 0;
    if (wait == WAIT_OBJECT_0)
    {
        GetExitCodeThread(th, &modBase);
    }
    CloseHandle(th);

    if (modBase == 0)
    {
        LogBoth("INJECT FAIL: remote LoadLibraryW returned NULL wait=%lu", (unsigned long)wait);
        VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        return 5;
    }
    LogBoth("INJECT OK: tgdl_hook.dll base=0x%08lX", (unsigned long)modBase);

    VirtualFreeEx(pi.hProcess, remote, 0, MEM_RELEASE);

    if (ResumeThread(pi.hThread) == (DWORD)-1)
    {
        LogBoth("RESUME FAIL gle=%lu", (unsigned long)GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 6;
    }
    LogBoth("RESUME ok, launcher exiting");

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

int wmain(void)
{
    ResolvePaths();
    ConsoleOpen();
    LogOpen();

    LogBoth("=== tgdl_launch start pid=%lu ===", (unsigned long)GetCurrentProcessId());

    /* 目标文件与 hook DLL 必须存在 */
    if (GetFileAttributesW(g_target) == INVALID_FILE_ATTRIBUTES)
    {
        LogBoth("LAUNCH FAIL: target missing");
        return 7;
    }
    if (GetFileAttributesW(g_dll) == INVALID_FILE_ATTRIBUTES)
    {
        LogBoth("LAUNCH FAIL: hook dll missing %ls", g_dll);
        return 7;
    }

    /* 已有实例时交给单实例逻辑，避免重复注入 */
    HANDLE probe = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\bacdea0964705717ba4509b541a84234");
    if (probe != NULL)
    {
        CloseHandle(probe);
        int rc = ForwardToRunningInstance();
        if (g_log != INVALID_HANDLE_VALUE)
        {
            CloseHandle(g_log);
        }
        return rc;
    }

    int rc = InjectAndRun();
    if (rc != 0)
    {
        LogBoth("=== tgdl_launch failed rc=%d ===", rc);
    }
    if (g_log != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_log);
    }
    return rc;
}

