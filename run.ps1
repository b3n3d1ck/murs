# MURS launcher for Windows PowerShell.
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

$py = if (Get-Command python -ErrorAction SilentlyContinue) { "python" }
      elseif (Get-Command python3 -ErrorAction SilentlyContinue) { "python3" }
      else { $null }

if (-not $py) {
  Write-Error "python not found. Install Python 3.10+ and add it to PATH."
  exit 1
}

& $py -c "import reportlab" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "note: reportlab not installed - PDF output will be skipped." -ForegroundColor Yellow
  Write-Host "      install it with: $py -m pip install -r requirements.txt"
}

if (-not (Get-Command php -ErrorAction SilentlyContinue)) {
  Write-Host "note: php CLI not found - the local lab (--lab) will be unavailable." -ForegroundColor Yellow
}

& $py -m murs @args
