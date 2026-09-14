$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checker = Join-Path $PSScriptRoot 'check_public_release.py'

try {
    $pythonCommand = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
}
catch {
    [Console]::Error.Write("public release check failed: Python unavailable`n")
    exit 2
}

try {
    & $pythonCommand.Source $checker '--repo' $repositoryRoot
    $checkerExitCode = $LASTEXITCODE
}
catch {
    [Console]::Error.Write("public release check failed: Python unavailable`n")
    exit 2
}

exit $checkerExitCode
