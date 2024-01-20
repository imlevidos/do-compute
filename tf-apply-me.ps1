<#
.VERSION 2024.01.20
#>

param(
    [switch]${Auto-Approve},
    [ValidateSet('apply', 'plan', 'destroy', 'init', 'state')][string]$Action = 'apply',
    [switch]$ShutDown,
    [string[]]$TfArgs,
    [string]$VarFile,
    [string[]]$TfInitArgs,
    [switch]$StateList,
    [string[]]$StateShow,
    [string]$TerraformPath,
    [string]$TerraformVersion
)

$InformationPreference = 'SilentlyContinue'

function Get-TerraformVersion {
    param(
        [string]$BackendType
    )

    $Version = switch ($BackendType) {
        'remote' { Get-TerraformVersionRemote; Break }
        'cloud' { Get-TerraformVersionRemote; Break }
        'none' { Get-TerraformVersionTfstate; Break }
        # 'none' {}
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

function Get-TerraformVersionTfstate {
    $StateFile = './terraform.tfstate'
    if (!(Test-Path $StateFile)) {
        $StateFile = './.terraform/terraform.tfstate'
        if (!(Test-Path $StateFile)) {
            Write-Debug 'No terraform.tfstate file found.'
            return $null
        }
    }

    $Content = Get-Content $StateFile | ConvertFrom-Json
    $Version = $Content.terraform_version
    Write-Debug "Detected Terraform version in ${StateFile}: $Version"
    return $Version
}


function Get-TerraformVersionRemote {
    $Token = Get-TfeToken

    $RepoConfigFile = './.terraform/terraform.tfstate'
    if (!(Test-Path $RepoConfigFile)) {
        Write-Debug "$RepoConfigFile not found, running terraform init"
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
        'Server'       = $Server
        'Organization' = $Organization
        'Workspace'    = $Workspace
        'Token'        = $Token
    }

    $WorkspaceData = Get-TfeWorkspace @Params
    $Result = $WorkspaceData.attributes.'terraform-version'
    Write-Verbose "$($WorkspaceData.attributes)"
    Write-Debug "Detected Terraform version from remote: $Result"
    return $Result
}

function Get-TerraformVersionText {
    $Content = Get-Content '*.tf' -ErrorAction Continue
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
    $Content = Get-TfContent -Raw
    if ($null -eq $Content) {
        Write-Debug 'Get-TerraformBackendType: no Terraform files found'
        return $null
    }
    $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*backend\s*\"([a-z]+)\"'
    if ($Null -eq $Search.Matches) {
        # Second attempt, look for `cloud` syntax
        $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*(cloud)'
    }
    if ($Null -eq $Search.Matches) {
        Write-Debug 'Detected backend: None'
        return 'none'
    }
    $Backend = $Search.Matches[0].Groups[1].Value
    Write-Debug "Detected backend: $Backend"
    return $Backend
}

function Get-TfeToken {
    param(
        [string]$Server = ''
    )
    # Try terraform.rc
    $CliConfigFileRc = "$env:APPDATA/terraform.rc"
    if (Test-Path $CliConfigFileRc) {
        if (!$Server) {
            $Server = '.*'
        }
        $Pattern = "credentials\s*`"$Server`"\s*{[\s\n]*token\s*=\s*\`"(.*)`""
        $Search = Get-Content -Raw $CliConfigFileRc | Select-String -Pattern $Pattern
        if ($Null -eq $Search.Matches) {
            Throw "Error extracting token from cli config: $CliConfigFileRc"
        }
        $Result = $Search.Matches.Groups[1].Value
        return $Result
    }
    # Try credentials.tfrc.json
    $CliConfigFileTfrc = "$env:APPDATA/terraform.d/credentials.tfrc.json"
    if (Test-Path $CliConfigFileTfrc) {
        if (!$Server) {
            $Server = 'app.terraform.io'
        }
        $Content = Get-Content -Raw $CliConfigFileTfrc | ConvertFrom-Json
        $Result = $Content.credentials.$Server.token
        if ($null -eq $Result) {
            Throw "Cannot find token for $Server in: $CliConfigFileTfrc"
        }
        return $Result
    }
    Throw "Unable to find Terraform token in $CliConfigFileRc or $CliConfigFileTfrc"
}

function Get-TfeWorkspace {
    param(
        [string]$Server,
        [string]$Organization,
        [string]$Workspace,
        [string]$Token
    )

    $Headers = @{
        'Authorization' = "Bearer $TOKEN"
        'Content-Type'  = 'application/vnd.api+json'
    }
    
    $URL = "https://$Server/api/v2/organizations/$Organization/workspaces/$Workspace"
    
    $Response = Invoke-RestMethod -Uri $URL -Headers $Headers -ErrorAction Stop
    $Result = $Response.Data

    return $Result
}

function Get-TfContent {
    <#
    .SYNOPSIS
        Get Terraform content from files, filters out comments
    .VERSION
        2024.01.20
    #>
    
    param(
        [string]$Path = './*.tf',
        [switch]$Raw
    )

    $SpecialModes = "\/\*|\*\/|\/\/|\`"|#"
    $MLCommentLevel = 0

    $Content = Get-Content $Path
    $Filtered = @()
    foreach ($line in $Content) {
        if ($MLCommentLevel -gt 0) {
            if ($line -match '\*\/') {
                $line = $line -replace '.*\*\/', ''
                $MLCommentLevel = 0
            }
            else {
                continue
            }
        }
        
        $CommentLineCheck = $line
        do {
            $Search = Select-String -InputObject $CommentLineCheck -Pattern $SpecialModes -AllMatches
            if ($Search) {
                switch ($search.Matches.Groups[0].Value) {
                    '"' {
                        $CommentLineCheck = $CommentLineCheck -replace "`".*?`"", ''
                    }
                    '#' {
                        $CommentLineCheck = $CommentLineCheck -replace '#.*$', ''
                        $line = $line -replace '#.*$', ''
                    }
                    '/*' {
                        if ($CommentLineCheck -match '\/\*.*\*\/') {
                            # Comment is closed on the same line
                            $CommentLineCheck = $CommentLineCheck -replace '\/\*.*?\*\/', ''
                            $line = $line -replace '\/\*.*?\*\/', ''
                        }
                        else {
                            $MLCommentLevel++
                            $CommentLineCheck = $CommentLineCheck -replace '\/\*.*', ''
                            $line = $line -replace '\/\*.*', ''
                        }
                    }
                    '*/' {
                        $MLCommentLevel = 0
                        $CommentLineCheck = $CommentLineCheck -replace '.*\*\/', ''
                        $line = $line -replace '.*\*\/', ''
                    }
                }
    
            }
        } while ($Search)

        if ($line -match '^\s*$') {
            continue
        }

        $Filtered += $line
    }

    if ($Raw) {
        $Filtered = $Filtered -join "`r`n"
    }

    return $Filtered
}

function Get-TerraformRemoteDetails {
    $Content = Get-Content -Raw *.tf 
    $Search = $Content | Select-String -Pattern 'terraform\s*{[\s\n]*backend\s*\"[a-z]+\"\s*{[\s\n]*hostname\s*=\s*\"(.*)\"[\s\n]*organization\s*=\s*\"(.*)\"[\s\n]*workspaces\s*{[\s\n]*(?:#.*\n)\s*name\s*=\s*\"(.*)\"'

    if ($null -eq $Search) {
        Throw 'Unable to get Terraform Remote details from code.'
    }

    $Result = @{
        'Server'       = $Search.Matches[0].Groups[1].Value
        'Organization' = $Search.Matches[0].Groups[2].Value
        'Workspace'    = $Search.Matches[0].Groups[3].Value
    }

    Write-Debug "Detected Terraform remote settings from code: $($Result | Out-String)"

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
    $TfUrl = 'https://releases.hashicorp.com/terraform/'
    $Response = Invoke-WebRequest -Uri $TfUrl -Proxy $ProxyUri -ErrorAction Stop
    $Versions = $Response.Links.innerText
    $Versions = $Versions | Where-Object { $_ -like 'terraform*' -and $_ -NotLike '*-*' }
    $SortedVersions = $Versions | Sort-Object -Descending -Property {
        $VersionComponents = ($_ -replace 'terraform_') -split '\.'
        [version]::new($VersionComponents[0], $VersionComponents[1], $VersionComponents[2])
    }
    $LatestVersion = $SortedVersions | Where-Object { $_ -like "terraform_$Version*" } | Select-Object -First 1
    Write-Verbose "Latest version for $Version is: $LatestVersion"
    if ([string]::IsNullOrEmpty($LatestVersion)) {
        Write-Warning "Available Terrarform versions: $SortedVersions"
        Throw "Unable to find version for: $Version"
    }
    $Version = $LatestVersion -replace 'terraform_', ''
    Write-Debug "Latest version is: $Version"

    return $Version
}

function Invoke-TerraformDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$OutDir
    )

    if ([string]::IsNullOrEmpty($OutDir)) {
        $OutDir = "$env:TEMP/.tf.env.ps"
    }

    $InformationPreference = 'Continue'

    $Version = Get-LatestTerraformVersion -Version $Version

    $TfPath = "$OutDir/tf-$Version.exe"

    if (Test-Path $TfPath) {
        $TfPath = Resolve-Path $TfPath | Select-Object -ExpandProperty Path
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
    # Invoke-WebRequest -Uri $TfUrl -OutFile $TfArchive -Proxy $ProxyUri -ErrorAction Stop
    $webClient = New-Object System.Net.WebClient
    if ($ProxyUri) {
        $webClient.Proxy = New-Object System.Net.WebProxy($ProxyUri)
    }
    $webClient.DownloadFile($TfUrl, $TfArchive)

    Expand-Archive -Path $TfArchive -DestinationPath $OutDir -Force -ErrorAction Stop
    Remove-Item -Path $TfArchive
    Rename-Item -Path "$OutDir/terraform.exe" -NewName $TfPath

    $TFPath = Resolve-Path $TfPath | Select-Object -ExpandProperty Path

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
    $Content = Get-TfContent -Raw
    $Search = $Content | Select-String -Pattern 'variable\s*"GOOGLE_ACCESS_TOKEN"\s*{'
    $IsGoogleTokenRequired = $Null -ne $Search.Matches
    if ($IsGoogleTokenRequired) {
        Write-Debug "GOOGLE_ACCESS_TOKEN required: $IsGoogleTokenRequired"
    }
    return $IsGoogleTokenRequired
}

function Invoke-TerraformInit {
    param(
        [Parameter(Mandatory = $true)][string]$TerraformPath,
        [Parameter(Mandatory = $true)][string]$BackendType,
        [bool]$Reconfigure,
        [string[]]$TfInitArgs
    )
    $InformationPreference = 'Continue'

    Write-Debug "Attempting: terraform init for backend type: $BackendType"
    if (Test-Path -Path './tf-init.ps1') {
        Write-Information 'Running custom tf-init.ps1'
        & .\tf-init.ps1
    }
    else {
        $TfCmd = @($TerraformPath, 'init')
        if ($TfInitArgs) {
            $TfCmd += $TfInitArgs
        }

        if ($BackendType -eq 'gcs') {
            $TfCmd += "-backend-config=`"access_token=$env:TF_VAR_GOOGLE_ACCESS_TOKEN`""
        } 
        if ($Reconfigure -and $BackendType -notin @('remote', 'cloud')) {
            $TfCmd += '-reconfigure'
        }

        Write-ExecCmd -Arguments $TfCmd
        Invoke-Expression "& $TfCmd" | Write-Host
    }

    if ($LASTEXITCODE -ne 0) {
        Throw "Terraform init failed with exit code: $LASTEXITCODE"
    }
}

function Invoke-TerraformProviderLockFix {
    $Params = 'providers lock -platform=windows_amd64 -platform=darwin_amd64 -platform=linux_amd64' -split ' '
    $TfCmd = @($TerraformPath)
    $TfCmd += $Params
    Write-Host 'Attempting providers lock fix..'
    # Write-Host "`n[ EXEC ]: $($TfCmd -join ' ')" -ForegroundColor Green
    Write-ExecCmd -Arguments $TfCmd
    Invoke-Expression "& $TfCmd" | Write-Host
}

function Invoke-TerraformValidate {
    param(
        [string]$BackendType,
        [string]$TerraformPath,
        [string[]]$TfInitArgs
    )

    $lastError = $null
    $retries = 0

    # Terraform Init Loop
    while ($retries -le 1) {
        $retries++;

        switch ($lastError) {
            'InitNeeded' {
                Invoke-TerraformInit -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
                # if ($Result -ne 0) {
                #     Throw "Terraform init failed with exit code: $Result"
                # }
            }
        }

        Write-ExecCmd -Arguments @($TerraformPath, 'validate')
        & $TerraformPath validate 2>&1 | Tee-Object -Variable ProcessOutput | Write-Host

        if ($LASTEXITCODE -eq 0) {
            Write-Verbose 'Terraform validate success.'
            Return
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
        # Write-Verbose 'Process output is:'
        # Write-Verbose $($ProcessOutput | Out-String)
        # Write-Verbose "REGEX PATTERN: $pattern"
        if ($ProcessOutput -match $pattern) {
            Write-Debug 'Module not installed, Terraform init needed.'
            $lastError = 'InitNeeded'
            Continue
        }

        Throw 'Error running Terraform validate. This error is not retriable.'
    }
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

function Write-ExecCmd {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    $Arguments = $Arguments -join ' '
    Write-Host "`nEXEC: " -NoNewline -ForegroundColor Green
    Write-Host "$Arguments`n" -ForegroundColor White
}


###
###  Start
###

$files = Get-ChildItem -Path *.tf -File -ErrorAction SilentlyContinue
if ($null -eq $files) {
    Throw 'No terraform files found.'
}

$InvokeTfDlParams = @{}
if ($env:TF_ENV_PS_DIR) {
    $InvokeTfDlParams['OutDir'] = $env:TF_ENV_PS_DIR
}

$IsGoogleTokenRequired = Get-IsGoogleTokenRequired
$BackendType = Get-TerraformBackendType

if (!$TerraformPath) {
    $Version = $TerraformVersion
    if (!$Version) {
        # Detect Terraform Version
        $Version = Get-TerraformVersion -BackendType $BackendType
        Write-Host "Detected Terraform Version: $Version"
    }

    # Download Terraform or use cached version
    $TerraformPath = Invoke-TerraformDownload -Version $Version -OutDir $env:TF_ENV_PS_DIR
    Write-Output "& `$env:TF = `"$TerraformPath`""
    $ExeDir = Split-Path $TerraformPath
    if ($env:PATH -notlike "*${ExeDir}*") {
        if ($env:PATH[-1] -ne ';') {
            $env:PATH += ';'
        }
        $env:PATH += "${ExeDir};"
    }
}
$env:TF = $TerraformPath   


if ($IsGoogleTokenRequired) {
    $env:TF_VAR_GOOGLE_ACCESS_TOKEN = "$(gcloud auth print-access-token)"
    $env:GOOGLE_ACCESS_TOKEN = $env:TF_VAR_GOOGLE_ACCESS_TOKEN  
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

if ($StateList) {
    Write-ExecCmd -Arguments @($TerraformPath, 'state list')
    & $TerraformPath state list
    exit 0
}

if ($StateShow) {
    Write-ExecCmd -Arguments @($TerraformPath, 'state show', $StateShow -replace '"', '\"')
    & $TerraformPath state show ($StateShow -replace '"', '\"')
    exit 0
}

if ($Action -in @('validate', 'plan', 'apply', 'destroy')) {
    Invoke-TerraformValidate -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
}

if ($Action -eq 'init') {
    Invoke-TerraformInit -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
}

if ($Action -eq 'init') {
    exit 0
}

###
###  Plan/Apply prep
### 

$TfArgs = @($Action) + $TfArgs

if ($Action -eq 'plan') {
    $TfArgs += '-detailed-exitcode'
}
if ($ShutDown) {
    $TfArgs += '-var=shutdown=true'
}
if (${Auto-Approve}) {
    $TfArgs += '-auto-approve'
}
if ($VarFile) {
    $TfArgs += "-var-file=$VarFile"
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
    Write-ExecCmd -Arguments @($TerraformPath, $TfArgs)
    & $TerraformPath $TfArgs 2>&1 | Tee-Object -Variable ProcessOutput

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

    if ($processOutput -match 'provider-checksum-verification|previously recorded in the dependency lock file') {
        Write-Debug 'Lockfile hash issues detected.'
        Invoke-TerraformProviderLockFix
        Continue
    }
    # Error is not retriable, exiting.
    exit $LASTEXITCODE
}

if ($Action -in @('apply', 'destroy', 'output')) {
    & $TerraformPath output > tf-output.txt
    Write-Host 'Updated tf-output.txt'
    if (Test-Path '.gitignore') {
        $gitignore = Get-Content '.gitignore'
        if ($gitignore -notlike 'tf-output.txt') {
            Add-Content '.gitignore' 'tf-output.txt'
        }
        if ($gitignore -notlike 'tfplans') {
            Add-Content '.gitignore' 'tfplans'
        }
    }
}
