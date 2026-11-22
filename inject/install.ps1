# install.ps1：部署 launcher 注入链路
# Telegram.exe 只读校验，快捷方式改指 launcher，可重复执行，-DryRun 只打印不落盘

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipShortcuts
)


# Telegram 安装目录：环境变量 TGDL_TGDIR 优先，其次常见默认位置
function Get-TgDir {
    if ($env:TGDL_TGDIR) { return $env:TGDL_TGDIR }
    $c = @(
        (Join-Path $env:LOCALAPPDATA "Telegram Desktop"),
        (Join-Path $env:APPDATA "Telegram Desktop"),
        "D:\Telegram Desktop",
        "C:\Telegram Desktop",
        (Join-Path $env:ProgramFiles "Telegram Desktop")
    )
    foreach ($d in $c) { if (Test-Path (Join-Path $d "Telegram.exe")) { return $d } }
    throw "找不到 Telegram.exe，用 `$env:TGDL_TGDIR 指定安装目录"
}

$ErrorActionPreference = 'Stop'

$Root     = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backup   = Join-Path $Root 'backup'
$LogDir   = Join-Path (Split-Path -Parent $Root) 'logs'
$LogTxt   = Join-Path $LogDir 'install.log'

$TgDir    = (Get-TgDir)
$TgExe    = Join-Path $TgDir 'Telegram.exe'
$Launcher = Join-Path $Root 'tgdl_launch.exe'
$HookSrc  = Join-Path $Root 'tgdl_hook.dll'

# 部署侧文件名：hook DLL 在目标机统一叫 tgdl_hook.dll
$DstLauncher = Join-Path $TgDir 'tgdl_launch.exe'
$DstHook     = Join-Path $TgDir 'tgdl_hook.dll'
$PatchLog    = Join-Path $TgDir 'tgdl_patch.log'

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Text)
    Write-Host $Text
    if (-not $DryRun) {
        Add-Content -Path $LogTxt -Value $Text -Encoding UTF8
    }
}

$Stamp = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
$Mode  = if ($DryRun) { 'DRY-RUN' } else { 'APPLY' }
if (-not $DryRun) {
    "=== install.ps1 $Stamp mode=$Mode ===" | Set-Content $LogTxt -Encoding UTF8
} else {
    Write-Host "=== install.ps1 $Stamp mode=$Mode ==="
}


Write-Log ''
Write-Log '--- step 0: preconditions ---'

if (-not (Test-Path $TgExe))    { throw "target exe missing: $TgExe" }
if (-not (Test-Path $Launcher)) { throw "artifact missing, run build.ps1: $Launcher" }
if (-not (Test-Path $HookSrc))  { throw "artifact missing, run build.ps1: $HookSrc" }

$ExeHashBefore  = (Get-FileHash $TgExe -Algorithm SHA256).Hash
$ExeMtimeBefore = (Get-Item $TgExe).LastWriteTimeUtc
Write-Log "exe_before   : $ExeHashBefore"
Write-Log "exe_mtime    : $ExeMtimeBefore"

$Baseline = Join-Path $Backup 'hash_before.txt'
if (Test-Path $Baseline) {
    $Line = Get-Content $Baseline | Select-String -Pattern 'Telegram\.exe'
    if ($Line) {
        $Want = ($Line.Line -split '\s+')[-1]
        Write-Log "exe_baseline : $Want"
        if ($Want -ne $ExeHashBefore) {
            throw "Telegram.exe already differs from baseline: $ExeHashBefore"
        }
    }
}

$alreadyLauncher = Test-Path $DstLauncher
$alreadyHook     = Test-Path $DstHook
Write-Log "launcher_present : $alreadyLauncher"
Write-Log "hook_present     : $alreadyHook"


Write-Log ''
Write-Log '--- step 1: stop running telegram ---'

$Running = @(Get-Process -Name 'Telegram' -ErrorAction SilentlyContinue)
if ($Running.Count -gt 0) {
    Write-Log "running      : $($Running.Count) process(es) -> stopping"
    if (-not $DryRun) {
        $Running | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
    }
} else {
    Write-Log 'running      : none'
}


Write-Log ''
Write-Log '--- step 2: deploy launcher and hook ---'

function Copy-Artifact {
    param([string]$Src, [string]$Dst, [string]$Label)

    $srcHash = (Get-FileHash $Src -Algorithm SHA256).Hash
    if (Test-Path $Dst) {
        $dstHash = (Get-FileHash $Dst -Algorithm SHA256).Hash
        if ($dstHash -eq $srcHash) {
            Write-Log ("{0,-13}: up to date ({1})" -f $Label, $srcHash.Substring(0, 16))
            return
        }
        Write-Log ("{0,-13}: differs, overwriting" -f $Label)
    } else {
        Write-Log ("{0,-13}: absent, copying" -f $Label)
    }

    if (-not $DryRun) {
        Copy-Item -LiteralPath $Src -Destination $Dst -Force
        $after = (Get-FileHash $Dst -Algorithm SHA256).Hash
        if ($after -ne $srcHash) { throw "$Label copy verification failed" }
        Write-Log ("{0,-13}: deployed sha={1}" -f $Label, $after)
    } else {
        Write-Log ("{0,-13}: would copy {1} -> {2}" -f $Label, $Src, $Dst)
    }
}

Copy-Artifact -Src $Launcher -Dst $DstLauncher -Label 'launcher'
Copy-Artifact -Src $HookSrc  -Dst $DstHook     -Label 'hook'


Write-Log ''
Write-Log '--- step 3: shortcut retarget ---'

$ShortcutList = @(
    (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Telegram Desktop\Telegram.lnk'),
    'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Telegram Desktop\Telegram.lnk',
    (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Telegram.lnk'),
    (Join-Path $env:PUBLIC 'Desktop\Telegram.lnk')
)

if ($SkipShortcuts) {
    Write-Log 'shortcuts    : skipped by -SkipShortcuts'
} else {
    $sh = New-Object -ComObject WScript.Shell
    foreach ($lnk in $ShortcutList) {
        if (-not (Test-Path $lnk)) { continue }
        try {
            $s = $sh.CreateShortcut($lnk)
            $cur = $s.TargetPath
            if ($cur -eq $DstLauncher) {
                Write-Log "lnk_ok       : $lnk (already launcher)"
                continue
            }
            if ($cur -ne $TgExe) {
                Write-Log "lnk_skip     : $lnk (target=$cur, not telegram)"
                continue
            }
            Write-Log "lnk_retarget : $lnk"
            Write-Log "  from       : $cur"
            Write-Log "  to         : $DstLauncher"
            if (-not $DryRun) {
                $s.TargetPath       = $DstLauncher
                $s.Arguments        = ''
                $s.WorkingDirectory = $TgDir
                $s.IconLocation     = "$TgExe,0"
                $s.Save()
            }
        } catch {
            Write-Log "lnk_error    : $lnk $($_.Exception.Message)"
        }
    }
}


Write-Log ''
Write-Log '--- step 4: red line verification ---'

$ExeHashAfter  = (Get-FileHash $TgExe -Algorithm SHA256).Hash
$ExeMtimeAfter = (Get-Item $TgExe).LastWriteTimeUtc
Write-Log "exe_after    : $ExeHashAfter"
Write-Log "exe_stable   : $($ExeMtimeBefore -eq $ExeMtimeAfter)"

if ($ExeHashAfter -ne $ExeHashBefore)  { throw 'RED LINE violated: Telegram.exe hash changed' }
if ($ExeMtimeBefore -ne $ExeMtimeAfter) { throw 'RED LINE violated: Telegram.exe mtime changed' }

Write-Log "version_dll  : $(if (Test-Path (Join-Path $TgDir 'version.dll')) { 'PRESENT (unexpected, remove it)' } else { 'absent' })"
Write-Log "d3dcompiler  : $((Get-FileHash (Join-Path $TgDir 'modules\x64\d3d\d3dcompiler_47.dll') -Algorithm SHA256).Hash)"

Write-Log ''
Write-Log "mode         : $Mode"
Write-Log 'RESULT: OK'
if (-not $DryRun) {
    Write-Log "next: run $DstLauncher, then read $PatchLog"
}
