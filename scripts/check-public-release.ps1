$ErrorActionPreference = 'Stop'

$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$checker = Join-Path $PSScriptRoot 'check_public_release.py'

& python $checker --repo $repositoryRoot
$checkerExitCode = $LASTEXITCODE
if ($checkerExitCode -ne 0) {
    exit $checkerExitCode
}

exit 0
