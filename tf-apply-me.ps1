﻿<#
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
    [ValidateSet('apply', 'plan', 'destroy')][string]$Action = 'apply'
)

$InformationPreference = 'SilentlyContinue'
Write-Debug "Args: $args"

function Get-TerraformVersion {
    ## Method 1: versions.tf
    if (!(Test-Path versions.tf)) {
        return
    }

    $vtf = Get-Content versions.tf
    $search = $vtf | Select-String 'required_version.*?(\d+)\.(\d+)\.(\d+)'

    if (!$search) {
        Write-Debug 'Version cannot be determined from versions.tf'
        return
    }

    $groups = $search.Matches
    $null, $major, $minor, $bugfix = $groups.Groups
    $result = "$major.$minor.$bugfix"
    Write-Verbose "Detected terraform version from versions.tf: $result"

    return $result

    ## Method 2: Terraform state pull:
    Write-Debug 'Attempting to detect version from the Terraform state'
    $search = tf state pull | Select-String -Pattern '^  "terraform_version": \"(\d+)\.(\d+)\.(\d+)\"'
    $groups = $search.Matches
    $null, $major, $minor, $bugfix = $groups.Groups
    $result = "$major.$minor.$bugfix"
    Write-Debug "Detected version from state: $result"
    return $result
}

function Invoke-TerraformDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$OutDir = "$env:TEMP/.tf.env.ps"
    )

    $InformationPreference = 'Continue'

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

    $TfUrl = "https://releases.hashicorp.com/terraform/${Version}/terraform_${Version}_windows_${arch}.zip"

    $proxy = [System.Net.WebRequest]::DefaultWebProxy                                 
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials      

    $proxyUriBuilder = New-Object System.UriBuilder                                   
    $proxyUriBuilder.Scheme = $proxy.Address.Scheme                                   
    $proxyUriBuilder.Host = $proxy.Address.Host                                       
    $proxyUriBuilder.Port = $proxy.Address.Port            

    $proxyUri = $proxyUriBuilder.Uri                                                  
    Write-Information "Downloading Terraform v${Version} to: $TfPath"
    Invoke-WebRequest -Uri $TfUrl -OutFile $TfArchive -Proxy $ProxyUri
    Expand-Archive -Path $TfArchive -DestinationPath $OutDir -Force
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

function Get-TerraformBackendType {
    $Content = Get-Content -Raw *.tf
    $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*backend\s*\"([a-z]+)\"'
    if ($Null -eq $Search.Matches) {
        return $Null
    }
    $Backend = $Search.Matches.Groups[1].Value
    Write-Debug "Detected backend: $Backend"
    return $Backend
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

    Write-Debug 'Attempting: terraform init'
    if (Test-Path -Path './tf-init.ps1') {
        Write-Information 'Running custom tf-init.ps1'
        & .\tf-init.ps1
    }
    else {
        $TfCmd = @($TerraformPath, 'init')

        if ($BackendType -eq 'gcs') {
            $TfCmd += "-backend-config=`"access_token=$env:TF_VAR_GOOGLE_ACCESS_TOKEN`""
        } 
        if ($Reconfigure -and $BackendType -ne 'cloud') {
            $TfCmd += '-reconfigure'
        }

        Write-Debug "Exec: $($TfCmd -join ' ')"
        Invoke-Expression "& $TfCmd"
    }

    return $LASTEXITCODE
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

$IsTfEnvPsEffective = $TfEnvPsActive -or ($env:TF_ENV_PS_ACTIVE -eq 'true' -and !$PSBoundParameters.ContainsKey('TfEnvPsActive'))
$InvokeTfDlParams = @{}
if ($env:TF_ENV_PS_DIR) {
    $InvokeTfDlParams['OutDir'] = $env:TF_ENV_PS_DIR
}

if ($IsTfEnvPsEffective) {
    $Version = Get-TerraformVersion
    $TerraformPath = Invoke-TerraformDownload -Version $Version @InvokeTfDlParams
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
            Invoke-TerraformInit -BackendType $BackendType
            $InitCompleted = $true
            if ($LASTEXITCODE -ne 0) {
                Write-Error "Terraform init failed with exit code: $Result"
                exit 1
            }
        }
    }

    # Validate Terraform files
    Write-Debug 'Attempting: terraform validate'
    & $TerraformPath validate 2>&1 | Tee-Object -Variable ProcessOutput

    if ($LASTEXITCODE -eq 0) {
        Write-Verbose 'Terraform validate success.'
        break
    }

    Write-Debug 'Error running Terraform init'

    # Any retriable errors can be detected here
    $InitNeededErrors = @(
        'module is not yet installed',
        'Missing required provider',
        '[Pp]lease run "terraform init"',
        'missing or corrupted provider plugins',
        'Module not installed'
    )
    $pattern = ($InitNeededErrors | ForEach-Object { [regex]::Escape($_) }) -join '|'

    if ($processOutput -match $pattern) {
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
    Write-Debug "TerraformPath $TfArgs $args"
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

    # Error is not retriable, exiting.
    exit $LASTEXITCODE
}

if ($Action -ne 'plan') {
    & $TerraformPath output > tf-output.txt
    Write-Host 'Updated tf-output.txt'
}
