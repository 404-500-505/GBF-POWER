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
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $pythonCommand.Source
    $startInfo.UseShellExecute = $false
    $startInfo.ArgumentList.Add($checker)
    $startInfo.ArgumentList.Add('--repo')
    $startInfo.ArgumentList.Add($repositoryRoot)
    $process = [System.Diagnostics.Process]::Start($startInfo)
    if ($null -eq $process) {
        throw 'Python process did not start'
    }
    $process.WaitForExit()
    exit $process.ExitCode
}
catch {
    [Console]::Error.Write("public release check failed: Python unavailable`n")
    exit 2
}
