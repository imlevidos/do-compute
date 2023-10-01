<#
.VERSION 2023.10.01
#>

param(
  [switch]${Auto-Approve},
  [switch]$ReInit,
  [string]$TerraformPath = 'tf',
  [switch]$ShutDown,
  [switch]$AuthOnly,
  [ValidateSet('apply', 'plan', 'destroy')][string]$Action = 'apply'
)

$InformationPreference = 'Continue'

$InitCompleted = $false

if ($Action -eq 'plan') {
  $args += '-detailed-exitcode'
}

function Detect-TerraformVersion {
  ## Method 1: versions.tf
  if (!(Test-Path versions.tf)) {
    return
  }

  $vtf = Get-Content versions.tf
  $search = $vtf | Select-String 'required_version.*?(\d+)\.(\d+)\.(\d+)'

  if (!$search) {
    Write-Verbose 'Version cannot be determined'
    return
  }

  $groups = $search.Matches
  $null, $major, $minor, $bugfix = $groups.Groups
  $result = "$major.$minor.$bugfix"
  Write-Verbose "Detected terraform version: $result"

  return $result

  ## Method 2: Terraform state pull:
  $search = tf state pull | Select-String -Pattern '^  "terraform_version": \"(\d+)\.(\d+)\.(\d+)\"'
  $groups = $search.Matches
  $null, $major, $minor, $bugfix = $groups.Groups
  $result = "$major.$minor.$bugfix"

}

function Invoke-TerraformInit {
  param(
    [bool]$Reconfigure = $true
  )

  Write-Debug 'Attempting: terraform init'
  if (Test-Path -Path './tf-init.ps1') {
    Write-Information 'Running custom tf-init.ps1'
    & .\tf-init.ps1
  }
  else {
    $ReconfigureCmd = ''
    if ($Reconfigure) {
      $ReconfigureCmd = '-reconfigure'
    }
    & $TerraformPath init -backend-config="access_token=$env:TF_VAR_GOOGLE_ACCESS_TOKEN" $ReconfigureCmd
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

$env:TF_VAR_GOOGLE_ACCESS_TOKEN = "$(gcloud auth print-access-token)"
$env:GOOGLE_ACCESS_TOKEN = $env:TF_VAR_GOOGLE_ACCESS_TOKEN
if ($AuthOnly) {
  Invoke-TerraformInit
  exit 0
}

if ($ReInit) {
  Invoke-TerraformInit
  $InitCompleted = $true
}

$ShutDownCmd = ''
if ($ShutDown) {
  $ShutDownCmd = '-var=shutdown=true'
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
      Invoke-TerraformInit
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
  Invoke-TerraformInit
  $InitCompleted = $true
}

$AutoApproveCmd = ''
if (${Auto-Approve} -and $Action -ne 'plan') {
  $AutoApproveCmd = '-auto-approve'
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
  & $TerraformPath $Action $AutoApproveCmd $ShutDownCmd $args 2>&1 | Tee-Object -Variable ProcessOutput

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
