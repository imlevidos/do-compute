param(
    [switch]${Auto-Approve},
    [switch]$ReInit,
    [string]$TerraformPath = 'tf'
)

# Validate Terraform files
& $TerraformPath validate
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Terraform validation failed!'
    exit $LASTEXITCODE
}

if ($ReInit) {
    & $TerraformPath init -backend-config="access_token=$(gcloud auth print-access-token)" -reconfigure
}
# Check the validity of the token if the file exists
if (Test-Path -Path 'token-google.secret') {
    $token = Get-Content -Path 'token-google.secret'
    try {
        $response = Invoke-WebRequest -Uri "https://oauth2.googleapis.com/tokeninfo?access_token=$token" -Method Get
        Write-Host "Token is valid`n"
    }
    catch {
        if ($_.Exception.Response.StatusCode -eq 400) {
            $content = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($content)
            $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
            if ($responseBody.error -eq 'invalid_token') {
                Write-Host 'Token is likely expired, attempting to refersh token'
                $env:PYTHONWARNINGS = 'ignore'
                gcloud auth print-access-token | Out-File -Encoding ASCII .\token-google.secret -NoNewline  
								
            }
        }
        else {
            Write-Host "Something else happened. Status Code: $($_.Exception.Response.StatusCode)"
        }
    }
}
else {
    Write-Host 'File token-google.secret does not exist'
}

$AutoApproveCmd = ''
if (${Auto-Approve}) {
    $AutoApproveCmd = '-auto-approve'
}
	
Write-Host "Starting Terraform Apply..`n"

$retries = 0
$lastError = ''

while ($retries -le 1) {
    $retries++;

    switch ($lastError) {
        'InitNeeded' {
            & $TerraformPath init -reconfigure -backend-config="access_token=$(Get-Content .\token-google.secret)"
        }
    }

    # Apply Terraform
    & $TerraformPath apply $AutoApproveCmd $args 2>&1 | Tee-Object -Variable ProcessOutput

    if ($LASTEXITCODE -ne 0) {
        # Any retriable errors can be detected here
        if (($processOutput -match 'Failed to open state file') -and (Test-Path -Path 'token-google.secret')) {
            $lastError = 'InitNeeded'
            continue
        }

        # Error is not retriable, exiting.
        exit $LASTEXITCODE
    }

    # No errors, break out of the loop
    break
}


& $TerraformPath output > tf-output.txt
Write-Host 'Updated tf-output.txt'
