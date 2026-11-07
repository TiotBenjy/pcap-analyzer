#!/usr/bin/env pwsh
# NetSift — pilote de la toolchain conteneurisée pour Windows (PowerShell).
# Equivalent de x.sh. Docker Desktop ou Podman requis ; aucune toolchain Rust/Node sur l'hote.
#
#   ./x.ps1 image | check | test | cargo <args> | npm <args> | dev | shots [vue] | desktop | shell
#   ./x.ps1 -C <dir> <sous-commande>   execute avec <dir> comme racine (worktree)
#
# Variables d'env : ENGINE=docker|podman, NETSIFT_UI_PORT, NETSIFT_API_PORT, REBUILD=1, NO_SCCACHE=1
[CmdletBinding()]
param(
  [string]$C = "",
  [Parameter(Position=0)][string]$Cmd = "help",
  [Parameter(Position=1, ValueFromRemainingArguments=$true)][string[]]$Rest = @()
)
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$WorkDir = if ($C) { (Resolve-Path $C).Path } else { $Root }
$Image = "netsift-dev:latest"
$CacheVol = "netsift-cache"

function Get-Engine {
  if ($env:ENGINE) { return $env:ENGINE }
  if (Get-Command podman -ErrorAction SilentlyContinue) { return "podman" }
  if (Get-Command docker -ErrorAction SilentlyContinue) { return "docker" }
  throw "Ni podman ni docker n'est installe."
}
$Engine = Get-Engine

function Slug { (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::UTF8.GetBytes($WorkDir))) -Algorithm SHA1).Hash.Substring(0,12).ToLower() }
function Ensure-CacheVol { & $Engine volume inspect $CacheVol *> $null; if ($LASTEXITCODE -ne 0) { & $Engine volume create $CacheVol | Out-Null } }
function Image-Exists { & $Engine image inspect $Image *> $null; return ($LASTEXITCODE -eq 0) }
function Build-Image {
  Write-Host ">> Construction de l'image $Image avec $Engine (premiere fois : ~10 min)..."
  & $Engine build -t $Image -f "$Root/docker/Dockerfile" $Root
  if ($LASTEXITCODE -ne 0) { throw "Echec du build de l'image" }
}
function Ensure-Image { if ($env:REBUILD -eq "1" -or -not (Image-Exists)) { Build-Image } }

function Run-In {
  param([string[]]$Extra, [string]$Script, [switch]$Tty)
  Ensure-Image; Ensure-CacheVol
  $scc = if ($env:NO_SCCACHE -eq "1") { "" } else { "sccache" }
  $ttyFlag = if ($Tty) { @("-it") } else { @() }
  # Docker Desktop (Windows) : pas de mapping UID necessaire (gere par le VM). Podman : keep-id si dispo.
  $userArgs = @()
  if ($Engine -eq "podman") { $userArgs = @("--userns=keep-id") }
  $args = @("run","--rm") + $ttyFlag + $userArgs + @(
    "-v","${WorkDir}:/work:z",
    "-v","${CacheVol}:/cache:z",
    "-e","CARGO_TARGET_DIR=/cache/target/$(Slug)",
    "-e","CARGO_HOME=/cache/cargo",
    "-e","SCCACHE_DIR=/cache/sccache",
    "-e","RUSTC_WRAPPER=$scc",
    "-e","npm_config_cache=/cache/npm",
    "-e","PLAYWRIGHT_BROWSERS_PATH=/usr/local/pw-browsers",
    "-e","HOME=/tmp/home",
    "-w","/work"
  ) + $Extra + @($Image,"bash","-lc",$Script)
  & $Engine @args
  if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

function UiPort  { if ($env:NETSIFT_UI_PORT)  { $env:NETSIFT_UI_PORT }  else { 5173 + ([Convert]::ToInt32((Slug).Substring(0,2),16) % 40) } }
function ApiPort { if ($env:NETSIFT_API_PORT) { $env:NETSIFT_API_PORT } else { 7878 + ([Convert]::ToInt32((Slug).Substring(0,2),16) % 40) } }

$r = ($Rest -join " ")
switch ($Cmd) {
  "image"     { $env:REBUILD="1"; Build-Image }
  "shell"     { Run-In @() "bash" -Tty }
  "run"       { Run-In @() $r -Tty }
  "cargo"     { Run-In @() "cargo $r" -Tty }
  "test"      { Run-In @() "cargo nextest run $r" -Tty }
  "clippy"    { Run-In @() "cargo clippy --workspace --all-targets --all-features -- -D warnings $r" -Tty }
  "fmt"       { Run-In @() "cargo fmt --all $r" -Tty }
  "deny"      { Run-In @() "cargo deny check $r" -Tty }
  "npm"       { Run-In @() "cd ui && npm $r" -Tty }
  "ui"        { Run-In @() "cd ui && npm run $r" -Tty }
  "check"     { Run-In @() "set -e; cargo fmt --all --check; cargo clippy --workspace --all-targets --all-features -- -D warnings; cargo nextest run --workspace; if [ -f ui/package.json ]; then cd ui && (npm ci || npm install) && npm run -s lint && npm run -s typecheck && npm run -s test -- --run; fi; echo OK" }
  "dev" {
    $up = UiPort; $ap = ApiPort
    Write-Host ">> UI  : http://localhost:$up"
    Write-Host ">> API : http://localhost:$ap (loopback)"
    $extra = @("-p","127.0.0.1:${up}:${up}","-p","127.0.0.1:${ap}:${ap}",
               "-e","NETSIFT_UI_PORT=$up","-e","NETSIFT_API_PORT=$ap",
               "-v","${Root}/captures:/captures:ro,z")
    Run-In $extra "bash scripts/ct/dev.sh" -Tty
  }
  "shots"     { Run-In @() "bash scripts/ct/shots.sh $r" }
  "desktop"   { Run-In @() "bash scripts/ct/desktop.sh linux" }
  "geoip"     { Run-In @() "bash scripts/ct/geoip.sh" }
  default     { Get-Content "$Root/x.ps1" | Select-Object -Skip 2 -First 12 | ForEach-Object { $_ -replace '^#\s?','' } }
}
