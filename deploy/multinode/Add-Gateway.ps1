[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$ParametersFile)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Resolve-InputFile([string]$Path) {
    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Input is not a file: $Path" }
    return $resolved.Path
}

function Read-Endpoint($Value) {
    $target = [string]$Value.target
    $port = [int]$Value.port
    if ($target -notmatch '^[A-Za-z_][A-Za-z0-9_-]*@[A-Za-z0-9.-]+$' -or $port -lt 1 -or $port -gt 65535) {
        throw 'Invalid SSH endpoint'
    }
    [pscustomobject]@{
        Target = $target
        Port = $port
        Identity = Resolve-InputFile ([string]$Value.identity_file)
        KnownHosts = Resolve-InputFile ([string]$Value.known_hosts)
    }
}

function Ssh-BaseArgs($Endpoint) {
    @('-F','none','-i',$Endpoint.Identity,'-o','BatchMode=yes','-o','IdentitiesOnly=yes',
      '-o','StrictHostKeyChecking=yes','-o',("UserKnownHostsFile=" + $Endpoint.KnownHosts))
}

$parameterPath = Resolve-InputFile $ParametersFile
$settings = Get-Content -LiteralPath $parameterPath -Raw -Encoding UTF8 | ConvertFrom-Json
$gateway = Read-Endpoint $settings.gateway_ssh
$control = Read-Endpoint $settings.control_ssh
$binary = Resolve-InputFile ([string]$settings.binary)
$gatewayTemplate = Resolve-InputFile ([string]$settings.gateway_config_template)
$rules = Resolve-InputFile ([string]$settings.gateway_rules)
$controlTemplate = Resolve-InputFile ([string]$settings.control_config_template)
$node = $settings.node
if ([string]$node.id -notin @('tokyo_cn2','osaka')) { throw 'Unsupported node id' }
if ([string]$node.public_host -notmatch '^[A-Za-z0-9.-]+$') { throw 'Invalid public gateway host' }
if ([int]$node.port -lt 1 -or [int]$node.port -gt 65535) { throw 'Invalid gateway port' }
if ([string]$node.username -notmatch '^[A-Za-z0-9_-]{1,32}$') { throw 'Invalid gateway username' }
if ([string]$node.control_url -notmatch '^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/?$') { throw 'Invalid control URL' }
if ([string]$node.control_certificate_sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid control certificate pin' }
if ([long]$node.capacity_bps -lt 100000) { throw 'Invalid node capacity' }

$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$gatewayInstaller = Resolve-InputFile (Join-Path $repo 'deploy/gateway/install.sh')
$gatewayService = Resolve-InputFile (Join-Path $repo 'deploy/systemd/gbf-gateway.service')
$controlInstaller = Resolve-InputFile (Join-Path $repo 'deploy/control/install.sh')
$controlService = Resolve-InputFile (Join-Path $repo 'deploy/systemd/gbf-control.service')
$nonce = [Guid]::NewGuid().ToString('N')
$remote = "/tmp/gbf-power-$nonce"
$temporaryControlConfig = [IO.Path]::GetTempFileName()
$gatewayBase = Ssh-BaseArgs $gateway
$controlBase = Ssh-BaseArgs $control

try {
    & ssh.exe @gatewayBase -p $gateway.Port $gateway.Target "umask 077; mkdir -p '$remote/deploy/gateway' '$remote/deploy/systemd'" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare gateway staging directory' }
    foreach ($item in @(
        @($binary,"$remote/gbf-activation"), @($gatewayTemplate,"$remote/gateway.json"),
        @($rules,"$remote/rules.json"), @($gatewayInstaller,"$remote/deploy/gateway/install.sh"),
        @($gatewayService,"$remote/deploy/systemd/gbf-gateway.service"))) {
        & scp.exe @gatewayBase -P $gateway.Port -- $item[0] ($gateway.Target + ':' + $item[1]) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Gateway upload failed' }
    }
    $installCommand = "sudo bash '$remote/deploy/gateway/install.sh' --binary '$remote/gbf-activation' --config-template '$remote/gateway.json' --rules '$remote/rules.json' --node-id '$($node.id)' --control-url '$($node.control_url)' --control-cert-sha256 '$($node.control_certificate_sha256)' --capacity-bps '$($node.capacity_bps)'"
    $publicOutput = & ssh.exe @gatewayBase -p $gateway.Port $gateway.Target $installCommand
    if ($LASTEXITCODE -ne 0) { throw 'Gateway installation failed' }
    $hostPublic = [string]($publicOutput | Where-Object { $_ -like 'HOST_PUBLIC_KEY=*' } | Select-Object -Last 1)
    $nodePublic = [string]($publicOutput | Where-Object { $_ -like 'NODE_PUBLIC_KEY=*' } | Select-Object -Last 1)
    if (-not $hostPublic -or -not $nodePublic) { throw 'Gateway did not return both public keys' }
    $hostPublic = $hostPublic.Substring('HOST_PUBLIC_KEY='.Length)
    $nodePublic = $nodePublic.Substring('NODE_PUBLIC_KEY='.Length)
    if ($hostPublic -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$' -or $nodePublic -notmatch '^ssh-ed25519 [A-Za-z0-9+/]+={0,2}$') {
        throw 'Gateway returned malformed public key material'
    }

    $controlJson = Get-Content -LiteralPath $controlTemplate -Raw -Encoding UTF8
    foreach ($required in @('${GATEWAY_NODE_ID}','${GATEWAY_PUBLIC_HOST}','${GATEWAY_PORT}','${GATEWAY_USERNAME}','${GATEWAY_HOST_PUBLIC_KEY}','${GATEWAY_NODE_PUBLIC_KEY}')) {
        if (-not $controlJson.Contains($required)) { throw "Control template is missing $required" }
    }
    $controlJson = $controlJson.Replace('${GATEWAY_NODE_ID}', [string]$node.id)
    $controlJson = $controlJson.Replace('${GATEWAY_PUBLIC_HOST}', [string]$node.public_host)
    $controlJson = $controlJson.Replace('${GATEWAY_PORT}', [string]$node.port)
    $controlJson = $controlJson.Replace('${GATEWAY_USERNAME}', [string]$node.username)
    $controlJson = $controlJson.Replace('${GATEWAY_HOST_PUBLIC_KEY}', $hostPublic).Replace('${GATEWAY_NODE_PUBLIC_KEY}', $nodePublic)
    $controlJson | ConvertFrom-Json | Out-Null
    [IO.File]::WriteAllText($temporaryControlConfig, $controlJson, [Text.UTF8Encoding]::new($false))

    & ssh.exe @controlBase -p $control.Port $control.Target "umask 077; mkdir -p '$remote/deploy/control' '$remote/deploy/systemd'" | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot prepare control staging directory' }
    foreach ($item in @(
        @($temporaryControlConfig,"$remote/control.json"), @($controlInstaller,"$remote/deploy/control/install.sh"),
        @($controlService,"$remote/deploy/systemd/gbf-control.service"))) {
        & scp.exe @controlBase -P $control.Port -- $item[0] ($control.Target + ':' + $item[1]) | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Control upload failed' }
    }
    $updateCommand = "sudo bash '$remote/deploy/control/install.sh' --binary /usr/local/lib/gbf-power/gbf-activation --config '$remote/control.json' --tls-cert /etc/gbf-power/control/tls.crt --tls-key /etc/gbf-power/control/tls.key"
    & ssh.exe @controlBase -p $control.Port $control.Target $updateCommand
    if ($LASTEXITCODE -ne 0) { throw 'Control configuration update failed' }
    Write-Host "Gateway $($node.id) installed and registered. Only public keys crossed the SSH boundary."
}
finally {
    Remove-Item -LiteralPath $temporaryControlConfig -Force -ErrorAction SilentlyContinue
    & ssh.exe @gatewayBase -p $gateway.Port $gateway.Target "rm -rf -- '$remote'" 2>$null | Out-Null
    & ssh.exe @controlBase -p $control.Port $control.Target "rm -rf -- '$remote'" 2>$null | Out-Null
}
