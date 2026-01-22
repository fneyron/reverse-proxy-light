$ErrorActionPreference = "Stop"

$GoVersion = "1.22.6"
$GoZip = "go$GoVersion.windows-amd64.zip"
$GoUrl = "https://go.dev/dl/$GoZip"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$GoDir = Join-Path $Root ".go"
$GoZipPath = Join-Path $Root $GoZip
$GoRoot = Join-Path $GoDir "go"
$GoPath = Join-Path $Root ".gopath"

if (!(Test-Path $GoDir)) {
  New-Item -ItemType Directory -Path $GoDir | Out-Null
}

if (!(Test-Path $GoRoot)) {
  if (!(Test-Path $GoZipPath)) {
    Write-Host "Downloading Go $GoVersion..."
    Invoke-WebRequest -Uri $GoUrl -OutFile $GoZipPath
  }
  Write-Host "Extracting Go..."
  Expand-Archive -Path $GoZipPath -DestinationPath $GoDir -Force
}

$env:GOROOT = $GoRoot
$env:GOPATH = $GoPath
$env:Path = "$GoRoot\bin;" + $env:Path

Set-Location $Root

Write-Host "Downloading dependencies..."
& go mod download

Write-Host "Building local-proxy-go.exe..."
& go build -o local-proxy-go.exe .

Write-Host "Done: $Root\local-proxy-go.exe"
