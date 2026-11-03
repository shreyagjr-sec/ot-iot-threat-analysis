param(
    [ValidateSet('demo', 'api', 'verify', 'tests')]
    [string]$Mode = 'demo'
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
$projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$existingPython = Join-Path (Split-Path $PSScriptRoot) '.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $projectPython) {
    $labPython = $projectPython
} elseif (Test-Path -LiteralPath $existingPython) {
    $labPython = $existingPython
} else {
    $labPython = (Get-Command python -ErrorAction Stop).Source
}
switch ($Mode) {
    'demo' { & $labPython -m otlab.demo }
    'api' { & $labPython -m uvicorn otlab.api:create_app --factory --host 127.0.0.1 --port 8001 }
    'verify' { & $labPython verify_api.py }
    'tests' { & $labPython -m unittest discover -s tests -v }
}
if ($LASTEXITCODE -ne 0) { throw "Lab command failed with exit code $LASTEXITCODE" }
