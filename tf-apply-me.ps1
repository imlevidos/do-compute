<#
.VERSION 2023.10.19
#>

param(
    [switch]${Auto-Approve},
    [switch]$ReInit,
    [string]$TerraformPath = 'tf',
    [switch]$ShutDown,
    [switch]$AuthOnly,
    [switch]$TfEnvPsActive, # rename to -DownloadTerraform ?
    [string]$VarFile,
    [string[]]$TfApplyArgs,
    [ValidateSet('apply', 'plan', 'destroy')][string]$Action = 'apply'
)

$InformationPreference = 'SilentlyContinue'
Write-Debug "Args: $args"

function Get-TerraformVersion {
    $Backend = Get-TerraformBackendType

    $Version = switch ($Backend) {
        "remote" { Get-TerraformVersionRemote; Break }
        "cloud" { Get-TerraformVersionRemote; Break }
        Default { Get-TerraformVersionText }
    }
    
    if ($null -eq $Version) {
        $Version = '1'
    }

    return $Version
    # ## Method 1: versions.tf
    # if (!(Test-Path versions.tf)) {
    #     return
    # }

    # $vtf = Get-Content versions.tf
    # $search = $vtf | Select-String 'required_version.*?(\d+)\.(\d+)\.(\d+)'

    # if (!$search) {
    #     Write-Debug 'Version cannot be determined from versions.tf'
    #     return
    # }

    # $groups = $search.Matches
    # $null, $major, $minor, $bugfix = $groups.Groups
    # $result = "$major.$minor.$bugfix"
    # Write-Verbose "Detected terraform version from versions.tf: $result"

    # return $result

    # ## Method 2: Terraform state pull:
    # Write-Debug 'Attempting to detect version from the Terraform state'
    # $search = tf state pull | Select-String -Pattern '^  "terraform_version": \"(\d+)\.(\d+)\.(\d+)\"'
    # $groups = $search.Matches
    # $null, $major, $minor, $bugfix = $groups.Groups
    # $result = "$major.$minor.$bugfix"
    # Write-Debug "Detected version from state: $result"
    # return $result
}

function Get-TerraformVersionText {
    $Content = Get-Content "*.tf" -ErrorAction Continue
    if ($null -eq $Content) {
        return $null
    }

    $Pattern = 'required_version\s*=\s*\"[~>=\s]*(\d+)(\.\d+)?(\.\d+)?\"'
    $Search = $Content | Select-String -Pattern $Pattern
    $SearchMatches = $Search.Matches

    Write-Verbose "Matches: $SearchMatches"

    If ($null -eq $SearchMatches) {
        Return $null
    }

    $Major = $SearchMatches[0].Groups[1]
    $Minor = $SearchMatches[0].Groups[2]
    $Bugfix = $SearchMatches[0].Groups[3]

    $Result = "${Major}${Minor}${Bugfix}"

    Write-Debug "Detected Terraform version from text: $Result"
    return $Result
}

function Get-TerraformBackendType {
    $Content = Get-Content -Raw *.tf -ErrorAction SilentlyContinue
    if ($null -eq $Content) {
        Write-Debug "Get-TerraformBackendType: no Terraform files found"
        return $null
    }
    $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*backend\s*\"([a-z]+)\"'
    if ($Null -eq $Search.Matches) {
        # Second attempt, look for `cloud` syntax
        $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*(cloud)'
    }
    if ($Null -eq $Search.Matches) {
        Write-Debug "Detected backend: None"
        return $Null
    }
    $Backend = $Search.Matches[0].Groups[1].Value
    Write-Debug "Detected backend: $Backend"
    return $Backend
}

function Get-TfeToken {
    $CliConfigFile = "$env:APPDATA/terraform.rc"
    if (!(Test-Path $CliConfigFile)) {
        Throw "Not found: $CliConfigFile"
    }
    $Server = '.*'
    $Pattern = "credentials\s*`"$Server`"\s*{[\s\n]*token\s*=\s*\`"(.*)`""
    $Search = Get-Content -Raw $CliConfigFile | Select-String -Pattern $Pattern
    if ($Null -eq $Search.Matches) {
        Throw "Error extracting token from cli config: $CliConfigFile"
    }
    $Result = $Search.Matches.Groups[1].Value
    return $Result
}

function Get-TfeWorkspace {
    param(
        [string]$Server,
        [string]$Organization,
        [string]$Workspace,
        [string]$Token
    )

    $Headers = @{
        "Authorization" = "Bearer $TOKEN"
        "Content-Type"  = "application/vnd.api+json"
    }
    
    $URL = "https://$Server/api/v2/organizations/$Organization/workspaces/$Workspace"
    
    $Response = Invoke-RestMethod -Uri $URL -Headers $Headers -ErrorAction Stop
    $Result = $Response.Data

    return $Result
}

function Get-TerraformRemoteDetails {
    $Content = Get-Content -Raw *.tf 
    $Search = $Content | Select-String -Pattern 'terraform\s*{[\s\n]*backend\s*\"[a-z]+\"\s*{[\s\n]*hostname\s*=\s*\"(.*)\"[\s\n]*organization\s*=\s*\"(.*)\"[\s\n]*workspaces\s*{[\s\n]*(?:#.*\n)\s*name\s*=\s*\"(.*)\"'

    if ($null -eq $Search) {
        Throw "Unable to get Terraform Remote details from code."
    }

    $Result = @{
        "Server"       = $Search.Matches[0].Groups[1].Value
        "Organization" = $Search.Matches[0].Groups[2].Value
        "Workspace"    = $Search.Matches[0].Groups[3].Value
    }

    Write-Debug "Detected Terraform remote settings from code: $($Result | Out-String)"

    return $Result
}

function Get-TerraformVersionRemote {
    $Token = Get-TfeToken

    $RepoConfigFile = './.terraform/terraform.tfstate'
    if (!(Test-Path $RepoConfigFile)) {
        & terraform init | Write-Debug
        # Throw "Not found: $RepoConfigFile"
    }

    if (!(Test-Path $RepoConfigFile)) {
        $Result = Get-TerraformRemoteDetails
        $Server = $Result.Server
        $Organization = $Result.Organization
        $Workspace = $Result.Workspace
    }
    else {
        $Config = Get-Content $RepoConfigFile | ConvertFrom-Json
        $Server = $Config.backend.config.hostname
        $Organization = $Config.backend.config.organization
        $Workspace = $Config.backend.config.workspaces[0].name
    }

    $Params = @{
        "Server"       = $Server
        "Organization" = $Organization
        "Workspace"    = $Workspace
        "Token"        = $Token
    }

    $WorkspaceData = Get-TfeWorkspace @Params
    $Result = $WorkspaceData.attributes.'terraform-version'
    Write-Verbose "$($WorkspaceData.attributes)"
    Write-Debug "Detected Terraform version from remote: $Result"
    return $Result
}

function Get-LatestTerraformVersion {
    <#
        Query Terraform website for the latest version matching $Version
    #>
    param(
        $Version
    )

    $dotCount = ($Version | Select-String -Pattern '\.' -AllMatches).Matches.Count
    Write-Verbose "Version: $Version`tDotCount: $dotCount"
    if ($dotCount -ge 2) {
        return $Version
    }

    Write-Debug "Got partial version, looking up the latest version for: $Version"
    $proxy = [System.Net.WebRequest]::DefaultWebProxy
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    
    $proxyUriBuilder = New-Object System.UriBuilder
    $proxyUriBuilder.Scheme = $proxy.Address.Scheme
    $proxyUriBuilder.Host = $proxy.Address.Host
    $proxyUriBuilder.Port = $proxy.Address.Port
    $proxyUri = $proxyUriBuilder.Uri                                                  
    $TfUrl = "https://releases.hashicorp.com/terraform/"
    $Response = Invoke-WebRequest -Uri $TfUrl -Proxy $ProxyUri -ErrorAction Stop
    $Versions = $Response.Links.innerText
    $Versions = $Versions | Where-Object { $_ -like 'terraform*' -and $_ -NotLike '*-*' }
    $SortedVersions = $Versions | Sort-Object -Descending -Property {
        $VersionComponents = ($_ -replace 'terraform_') -split '\.'
        [version]::new($VersionComponents[0], $VersionComponents[1], $VersionComponents[2])
    }
    $LatestVersion = $SortedVersions | Where-Object { $_ -like "terraform_$Version*" } | Select-Object -First 1
    $Version = $LatestVersion -replace 'terraform_', ''
    Write-Debug "Latest version is: $Version"

    return $Version
}

function Invoke-TerraformDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$OutDir = "$env:TEMP/.tf.env.ps"
    )

    $InformationPreference = 'Continue'

    $Version = Get-LatestTerraformVersion -Version $Version

    $TfPath = "$OutDir/tf-$Version.exe"

    if (Test-Path $TfPath) {
        Write-Debug "Terraform version already cached: $TfPath"
        return $TfPath
    }

    $TfArchive = $TfPath -replace '\.exe$', '.zip'
    if (!(Test-Path -Path $OutDir -PathType Container)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'x86' { '386' }
        default { Throw "CPU Architecture cannot be determined: $env:PROCESSOR_ARCHITECTURE" }
    }

    $proxy = [System.Net.WebRequest]::DefaultWebProxy
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    
    $proxyUriBuilder = New-Object System.UriBuilder
    $proxyUriBuilder.Scheme = $proxy.Address.Scheme
    $proxyUriBuilder.Host = $proxy.Address.Host
    $proxyUriBuilder.Port = $proxy.Address.Port
    $proxyUri = $proxyUriBuilder.Uri                                                  

    $TfUrl = "https://releases.hashicorp.com/terraform/${Version}/terraform_${Version}_windows_${arch}.zip"
    
    Write-Information "Downloading Terraform v${Version} to: $TfPath"
    Invoke-WebRequest -Uri $TfUrl -OutFile $TfArchive -Proxy $ProxyUri -ErrorAction Stop
    Expand-Archive -Path $TfArchive -DestinationPath $OutDir -Force -ErrorAction Stop
    Remove-Item -Path $TfArchive
    Rename-Item -Path "$OutDir/terraform.exe" -NewName $TfPath

    # Test
    $Test = & $TfPath version
    if ($LASTEXITCODE -ne 0) {
        Throw "Terraform download unsuccessful: $TfPath`nExit code: $LASTEXITCODE"
    }
    if ([string]::IsNullOrEmpty($Test)) {
        Throw "Terraform version didn't generate any output. Try running manually? $TfPath"
    }
    if ($Test[0] -notlike "*$Version") {
        Throw "Unexpected terraform version: $TfPath`n$Test"
    }

    Write-Information "Terraform download successful: $TfPath"
    return $TfPath
}

function Get-IsGoogleTokenRequired {
    $Content = Get-Content -Raw *.tf
    $Search = $Content | Select-String -Pattern 'variable\s*"GOOGLE_ACCESS_TOKEN"\s*{'
    $IsGoogleTokenRequired = $Null -ne $Search.Matches
    Write-Debug "GOOGLE_ACCESS_TOKEN required: $IsGoogleTokenRequired"
    return $IsGoogleTokenRequired
}

function Invoke-TerraformInit {
    param(
        [bool]$Reconfigure = $true,
        [string]$BackendType
    )
    $InformationPreference = 'Continue'

    Write-Debug "Attempting: terraform init for backend type: $BackendType"
    if (Test-Path -Path './tf-init.ps1') {
        Write-Information 'Running custom tf-init.ps1'
        & .\tf-init.ps1
    }
    else {
        $TfCmd = @($TerraformPath, 'init')

        if ($BackendType -eq 'gcs') {
            $TfCmd += "-backend-config=`"access_token=$env:TF_VAR_GOOGLE_ACCESS_TOKEN`""
        } 
        if ($Reconfigure -and $BackendType -notin @('remote', 'cloud')) {
            $TfCmd += '-reconfigure'
        }

        Write-Output "Executing: $($TfCmd -join ' ')"
        Invoke-Expression "& $TfCmd"
    }

    return $LASTEXITCODE
}

function Invoke-TerraformProviderLockFix {
    $Params = "providers lock -platform=windows_amd64 -platform=darwin_amd64 -platform=linux_amd64" -split ' '
    $TfCmd = @($TerraformPath)
    $TfCmd += $Params
    Write-Host "Attempting providers lock fix.."
    Write-Debug "Exec: $($TfCmd -join ' ')"
    Invoke-Expression "& $TfCmd"
}

function Remove-StateLock {
    param(
        # Mandatory
        [Parameter(Mandatory = $true)][string]$LockPath
    )

    Write-Information "Detected lock path: $lockPath"
    $response = Read-Host -Prompt 'Delete? (y/n)'
    if ($response -ne 'y') {
        exit 1
    }

    & gcloud storage rm $LockPath
}


###
###  Start
###

$files = Get-ChildItem -Path *.tf -File -ErrorAction SilentlyContinue
if ($null -eq $files) {
    Throw "No terraform files found."
}

$IsTfEnvPsEffective = $TfEnvPsActive -or ($env:TF_ENV_PS_ACTIVE -eq 'true' -and !$PSBoundParameters.ContainsKey('TfEnvPsActive'))
$InvokeTfDlParams = @{}
if ($env:TF_ENV_PS_DIR) {
    $InvokeTfDlParams['OutDir'] = $env:TF_ENV_PS_DIR
}

if ($IsTfEnvPsEffective) {
    $Version = Get-TerraformVersion
    Write-Output "Detected Terraform Version: $Version"
    $TerraformPath = Invoke-TerraformDownload -Version $Version @InvokeTfDlParams
    Write-Output "Terraform path: $TerraformPath"
    $ExeDir = Split-Path $TerraformPath
    if ($env:PATH -notlike "*${ExeDir}*") {
        if ($env:PATH[-1] -ne ';') {
            $env:PATH += ';'
        }
        $env:PATH += "${ExeDir};"
    }
    $env:TF = $TerraformPath
}

$InitCompleted = $false

if ($Action -eq 'plan') {
    $args += '-detailed-exitcode'
}

$IsGoogleTokenRequired = Get-IsGoogleTokenRequired
$BackendType = Get-TerraformBackendType

if ($IsGoogleTokenRequired) {
    $env:TF_VAR_GOOGLE_ACCESS_TOKEN = "$(gcloud auth print-access-token)"
    $env:GOOGLE_ACCESS_TOKEN = $env:TF_VAR_GOOGLE_ACCESS_TOKEN  
}
if ($AuthOnly) {
    Invoke-TerraformInit -BackendType $BackendType
    exit 0
}

if ($ReInit) {
    Invoke-TerraformInit -BackendType $BackendType
    $InitCompleted = $true
}


# Check the validity of the token if the file exists.
# No longer needed because we're doing auth at each run, but useful code to keep around.
# if (Test-Path -Path 'token-google.secret') {
#   $token = Get-Content -Path 'token-google.secret'
#   try {
#     $response = Invoke-WebRequest -Uri "https://oauth2.googleapis.com/tokeninfo?access_token=$token" -Method Get
#     Write-Host "Token is valid`n"
#   }
#   catch {
#     if ($_.Exception.Response.StatusCode -eq 400) {
#       $content = $_.Exception.Response.GetResponseStream()
#       $reader = New-Object System.IO.StreamReader($content)
#       $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
#       if ($responseBody.error -eq 'invalid_token') {
#         Write-Host 'Token is likely expired, attempting to refersh token'
#         $env:PYTHONWARNINGS = 'ignore'
#         gcloud auth print-access-token | Out-File -Encoding ASCII .\token-google.secret -NoNewline  
								
#       }
#     }
#     else {
#       Write-Host "Something else happened. Status Code: $($_.Exception.Response.StatusCode)"
#     }
#   }
# }
# else {
#   Write-Host 'File token-google.secret does not exist'
# }

$retries = 0
$lastError = ''

# Terraform Init Loop
while ($retries -le 1) {
    $retries++;

    switch ($lastError) {
        'InitNeeded' {
            $Result = Invoke-TerraformInit -BackendType $BackendType
            $InitCompleted = $true
            if ($Result -ne 0) {
                Write-Error "Terraform init failed with exit code: $Result"
                exit 1
            }
        }
    }

    Write-Output "Executing: $TerraformPath validate"
    & $TerraformPath validate 2>&1 | Tee-Object -Variable ProcessOutput

    if ($LASTEXITCODE -eq 0) {
        Write-Verbose 'Terraform validate success.'
        break
    }

    Write-Debug 'Error running Terraform validate'

    # Any retriable errors can be detected here
    $InitNeededErrors = @(
        'missing or corrupted provider plugins',
        'Missing required provider',
        'module is not yet installed',
        'Module not installed',
        'Module source has changed',
        'please run "terraform init"',
        'Please run "terraform init"'
    )
    $pattern = ($InitNeededErrors | ForEach-Object { [regex]::Escape($_) }) -join '|'
    Write-Host "Process output is:"
    Write-Host $ProcessOutput
    Write-Verbose "InitNeededErrors pattern: $pattern"
    if ($ProcessOutput -match $pattern) {
        Write-Debug 'Module not installed, Terraform init needed.'
        $lastError = 'InitNeeded'
        continue
    }

    # Error is not retriable, exiting.
    Write-Information 'Terraform validation failed!'
    exit $LASTEXITCODE
}

if (!$InitCompleted) {
    Invoke-TerraformInit -BackendType $BackendType
    $InitCompleted = $true
}

###
###  Plan/Apply prep
### 

$TfArgs = @($Action)

switch ($True) {
    { ${Auto-Approve} -and $Action -ne 'plan' } { 
        $TfArgs += '-auto-approve' 
    }
    { $ShutDown } { 
        $TfArgs += '-var=shutdown=true'
    }
    { $VarFile } {
        $TfArgs += "-var-file=$VarFile"
    }
    { $TfApplyArgs } {
        $TfArgs += $TfApplyArgs
    }
}

Write-Information "Starting Terraform ${Action}..`n"

$retries = 0
$lastError = ''

while ($retries -le 1) {
    $retries++;

    # switch ($lastError) {
    #   'InitNeeded' {
    #     Invoke-TerraformInit
    #   }
    # }

    # $env:TF_VAR_GOOGLE_ACCESS_TOKEN = $(Get-Content .\token-google.secret)

    # Terraform Apply/Plan/Destroy
    # & $TerraformPath $Action $AutoApproveCmd $ShutDownCmd $args 2>&1 | Tee-Object -Variable ProcessOutput
    Write-Output "Executing: $TerraformPath $TfArgs $args"
    & $TerraformPath $TfArgs $args 2>&1 | Tee-Object -Variable ProcessOutput

    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "Terraform ${Action} success."
        break
    }

    # Any retriable errors can be detected here
    # if (($processOutput -match 'Failed to open state file') -and (Test-Path -Path 'token-google.secret')) {
    #   Write-Debug 'Init needed to refersh credentials.'

    #   $lastError = 'InitNeeded'
    #   continue
    # }

    # if ($processOutput -match 'please run "terraform init"') {
    #   $lastError = 'InitNeeded'
    #   continue
    # }

    if ($processOutput -match 'Error acquiring the state lock') {
        $pattern = 'Path:\s+(.*?)\s*│'
		
        $match = [regex]::Match($processOutput, $pattern)
        if (!$match.Success) {
            Write-Error 'Unable to parse lock path from error message'
            exit 1
        }

        $lockPath = $match.Groups[1].Value
        Write-Debug "Detected lock path: $lockPath"

        Remove-StateLock -LockPath $lockPath
    
        $lastError = 'StateLocked'
        continue
    }

    if ($processOutput -match 'provider-checksum-verification') {
        Write-Debug "Lockfile hash issues detected."
        Invoke-TerraformProviderLockFix
        Continue
    }
    # Error is not retriable, exiting.
    exit $LASTEXITCODE
}

if ($Action -ne 'plan') {
    & $TerraformPath output > tf-output.txt
    Write-Host 'Updated tf-output.txt'
}
