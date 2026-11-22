# restore.ps1：反向执行 install.ps1 的全部改动
# 快捷方式改回 Telegram.exe，删除 launcher 与 hook DLL，可重复执行，-DryRun 只打印不落盘

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$SkipShortcuts,
    [switch]$KeepLog
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

$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Backup = Join-Path $Root 'backup'
$LogDir = Join-Path (Split-Path -Parent $Root) 'logs'
$LogTxt = Join-Path $LogDir 'restore.log'

$TgDir       = (Get-TgDir)
$TgExe       = Join-Path $TgDir 'Telegram.exe'
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
    "=== restore.ps1 $Stamp mode=$Mode ===" | Set-Content $LogTxt -Encoding UTF8
} else {
    Write-Host "=== restore.ps1 $Stamp mode=$Mode ==="
}

Write-Log ''
Write-Log '--- step 0: preconditions ---'

if (-not (Test-Path $TgExe)) { throw "target exe missing: $TgExe" }

$ExeHashBefore  = (Get-FileHash $TgExe -Algorithm SHA256).Hash
$ExeMtimeBefore = (Get-Item $TgExe).LastWriteTimeUtc
Write-Log "exe_before   : $ExeHashBefore"


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
Write-Log '--- step 2: shortcut retarget back ---'

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
            if ($cur -eq $TgExe) {
                Write-Log "lnk_ok       : $lnk (already telegram)"
                continue
            }
            if ($cur -ne $DstLauncher) {
                Write-Log "lnk_skip     : $lnk (target=$cur)"
                continue
            }
            Write-Log "lnk_restore  : $lnk -> $TgExe"
            if (-not $DryRun) {
                $s.TargetPath       = $TgExe
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
Write-Log '--- step 3: remove injected artifacts ---'

$RemoveList = @($DstLauncher, $DstHook)
if (-not $KeepLog) { $RemoveList += $PatchLog }

foreach ($p in $RemoveList) {
    if (Test-Path $p) {
        Write-Log "removed      : $p"
        if (-not $DryRun) { Remove-Item -LiteralPath $p -Force }
    } else {
        Write-Log "removed      : none ($p absent)"
    }
}


Write-Log ''
Write-Log '--- step 4: hash verification ---'

$ExeHashAfter  = (Get-FileHash $TgExe -Algorithm SHA256).Hash
$ExeMtimeAfter = (Get-Item $TgExe).LastWriteTimeUtc
Write-Log "exe_after    : $ExeHashAfter"
Write-Log "exe_stable   : $($ExeMtimeBefore -eq $ExeMtimeAfter)"

if ($ExeHashAfter -ne $ExeHashBefore)   { throw 'RED LINE violated: Telegram.exe hash changed' }
if ($ExeMtimeBefore -ne $ExeMtimeAfter) { throw 'RED LINE violated: Telegram.exe mtime changed' }

$Baseline = Join-Path $Backup 'hash_before.txt'
if (Test-Path $Baseline) {
    $Line = Get-Content $Baseline | Select-String -Pattern 'Telegram\.exe'
    if ($Line) {
        $Want = ($Line.Line -split '\s+')[-1]
        Write-Log "exe_ref      : $Want"
        if ($Want -ne $ExeHashAfter) { throw 'Telegram.exe hash differs from recorded baseline' }
    }
}

Write-Log "launcher     : $(Test-Path $DstLauncher)"
Write-Log "hook_dll     : $(Test-Path $DstHook)"
Write-Log "version.dll  : $(Test-Path (Join-Path $TgDir 'version.dll'))"
Write-Log "d3dcompiler  : $((Get-FileHash (Join-Path $TgDir 'modules\x64\d3d\d3dcompiler_47.dll') -Algorithm SHA256).Hash)"

Write-Log ''
Write-Log "mode         : $Mode"
Write-Log 'RESULT: OK'
