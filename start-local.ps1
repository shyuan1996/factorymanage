$ErrorActionPreference = 'Stop'
$appRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $appRoot
Write-Host '工務掌握本機測試站啟動中：http://127.0.0.1:4173' -ForegroundColor Green
node .\server.js
