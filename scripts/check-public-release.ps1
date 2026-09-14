$ErrorActionPreference = 'Stop'

try {
    $repositoryRootCandidate = [System.IO.Path]::Combine($PSScriptRoot, '..')
    $checkerCandidate = [System.IO.Path]::Combine($PSScriptRoot, 'check_public_release.py')
    $repositoryRoot = (Resolve-Path -LiteralPath $repositoryRootCandidate).Path
    $checker = (Resolve-Path -LiteralPath $checkerCandidate).Path
    $pythonCommand = Get-Command python -CommandType Application -ErrorAction Stop | Select-Object -First 1
}
catch {
    [Console]::Error.Write("public release check failed: startup error`n")
    exit 2
}

try {
    & $pythonCommand.Source $checker '--repo' $repositoryRoot
    $checkerExitCode = $LASTEXITCODE
}
catch {
    [Console]::Error.Write("public release check failed: startup error`n")
    exit 2
}

exit $checkerExitCode
