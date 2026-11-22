# build.ps1：编译 hook DLL 与 launcher
# Werror 强制 0 警告 0 错误，不用 -w、不用 pragma 屏蔽

[CmdletBinding()]
param(
    [switch]$OnlyLauncher,
    [switch]$OnlyHook
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'

$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Src    = Join-Path $Root 'src'
$ObjDir = Join-Path $Root 'obj'
$LogDir = Join-Path (Split-Path -Parent $Root) 'logs'

$Gpp     = if ($env:TGDL_GXX) { $env:TGDL_GXX } else { "g++" }
$Objdump = if ($env:TGDL_OBJDUMP) { $env:TGDL_OBJDUMP } else { "objdump" }

if (-not (Get-Command $Gpp -ErrorAction SilentlyContinue))     { throw "toolchain missing: $Gpp （用 `$env:TGDL_GXX 指定完整路径）" }
if (-not (Get-Command $Objdump -ErrorAction SilentlyContinue)) { throw "toolchain missing: $Objdump （用 `$env:TGDL_OBJDUMP 指定完整路径）" }
foreach ($d in @($ObjDir, $LogDir)) {
    if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
}

$BuildLog = Join-Path $LogDir 'build.log'
$Stamp    = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
"=== build.ps1 $Stamp ===" | Set-Content $BuildLog -Encoding UTF8

function Write-BuildLog {
    param([string]$Text)
    Write-Host $Text
    Add-Content -Path $BuildLog -Value $Text -Encoding UTF8
}

$Global:BuildWarnings = 0
$Global:BuildErrors   = 0

function Invoke-Gpp {
    param(
        [string]$Label,
        [string[]]$GppArgs,
        [string]$OutFile
    )

    Write-BuildLog ''
    Write-BuildLog "--- $Label ---"
    Write-BuildLog "g++ $($GppArgs -join ' ')"

    $Prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    $Raw = & $Gpp @GppArgs 2>&1
    $Code = $LASTEXITCODE
    $ErrorActionPreference = $Prev

    foreach ($line in $Raw) {
        Add-Content -Path $BuildLog -Value ([string]$line) -Encoding UTF8
        Write-Host ([string]$line)
    }

    $W = @($Raw | Where-Object { [string]$_ -match 'warning:' })
    $E = @($Raw | Where-Object { [string]$_ -match 'error:|undefined reference|fatal error' })
    $Global:BuildWarnings += $W.Count
    $Global:BuildErrors   += $E.Count

    Write-BuildLog "exit=$Code warning=$($W.Count) error=$($E.Count)"
    if ($Code -ne 0 -or $E.Count -gt 0 -or $W.Count -gt 0) {
        throw "$Label failed (see $BuildLog)"
    }
    if (-not (Test-Path $OutFile)) {
        throw "$Label produced no artifact: $OutFile"
    }
}

$CommonArgs = @(
    '-std=c++17'
    '-O2'
    '-Wall'
    '-Wextra'
    '-Werror'
    '-static'
    '-static-libgcc'
    '-static-libstdc++'
    '-D_WIN32_WINNT=0x0A00'
    '-DWINVER=0x0A00'
)


if (-not $OnlyHook) {
    $LauncherSrc = Join-Path $Src 'launcher.cpp'
    $LauncherOut = Join-Path $Root 'tgdl_launch.exe'
    if (-not (Test-Path $LauncherSrc)) { throw "source missing: $LauncherSrc" }

    $Args = $CommonArgs + @('-municode', '-o', $LauncherOut, $LauncherSrc, '-lshell32')
    Invoke-Gpp -Label 'launcher' -GppArgs $Args -OutFile $LauncherOut
}


if (-not $OnlyLauncher) {
    $HookSrc = Join-Path $Src 'hook.cpp'
    $HookOut = Join-Path $Root 'tgdl_hook.dll'
    if (-not (Test-Path $HookSrc)) { throw "source missing: $HookSrc" }

    $Args = $CommonArgs + @('-shared', '-o', $HookOut, $HookSrc, '-lpsapi')
    Invoke-Gpp -Label 'hook' -GppArgs $Args -OutFile $HookOut

    $Exp = & $Objdump -p $HookOut 2>&1
    $ExportNames = @()
    foreach ($ln in $Exp) {
        if ([string]$ln -match '^\s*\[\s*\d+\]\s+(\S+)\s*$') { $ExportNames += $Matches[1] }
    }
    Write-BuildLog "hook exports : $(if ($ExportNames.Count) { $ExportNames -join ', ' } else { '(none)' })"

    # 不得引入 MinGW 运行期动态依赖
    foreach ($ln in ($Exp | Select-String -Pattern 'DLL Name:')) {
        $s = $ln.Line.Trim()
        Write-BuildLog "hook import  : $s"
        if ($s -match 'libwinpthread|libgcc_s|libstdc\+\+') {
            throw "unexpected dynamic dependency in hook dll: $s"
        }
    }
}


Write-BuildLog ''
Write-BuildLog "total warning : $Global:BuildWarnings"
Write-BuildLog "total error   : $Global:BuildErrors"
if ($Global:BuildWarnings -ne 0 -or $Global:BuildErrors -ne 0) {
    Write-BuildLog 'RESULT: FAIL'
    throw 'warning or error gate failed'
}

foreach ($n in @('tgdl_launch.exe', 'tgdl_hook.dll')) {
    $p = Join-Path $Root $n
    if (Test-Path $p) {
        $i = Get-Item $p
        Write-BuildLog "artifact      : $($i.Name)  size=$($i.Length)  sha256=$((Get-FileHash $p -Algorithm SHA256).Hash)"
    }
}
Write-BuildLog 'RESULT: OK'
