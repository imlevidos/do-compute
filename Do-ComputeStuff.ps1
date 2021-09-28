param(
  [Parameter()][ValidateSet('Compute','MIG')][string[]]$ResourceType = 'Compute',
  [nullable[bool]]$UseInternalIpSsh,
  [Parameter(Position=0)][string]$Answer,
  [Switch]$Install,
  [Switch]${Show-Command}
)

# $env:PATH="d:\src\do-compute;$env:path"
if ($Install -eq $true) {
  $existingPaths = `
    [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User) + `
    [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine) `
    -split ';'

  if ($existingPaths -notcontains $PSScriptRoot) {
    Write-Output 'INSTALL: Adding script location to %PATH% as user env var...'

    [Environment]::SetEnvironmentVariable("Path", "$env:Path;$PSScriptRoot", [System.EnvironmentVariableTarget]::User)
  }

  if ($env:Path -split ';' -notcontains $PSScriptRoot) {
    Write-Output 'INSTALL: Refreshing %PATH% in current shell...'
    $env:Path="$PSScriptRoot;$env:Path"
  }
  else {
    Write-Output 'INSTALL: $PSScriptRoot already in %PATH%'
  }

  exit 0
}

switch ($ResourceType) {
  "Compute" { 
    $outputCmd="gcloud compute instances list --format='csv(name,zone,MACHINE_TYPE,INTERNAL_IP,EXTERNAL_IP,status,metadata.items[created-by].scope(instanceGroupManagers),id)'"; 
    $instructions="[S]SH`t[O]UTPUT:serial-port `t[L]OG:start-up `t[T]AIL:start-up `t[U]PDATE:instance-template`t[R]ESET`t[Q]UIT"
    break 
  }
  "MIG" { 
    $outputCmd="gcloud compute instance-groups managed list --format='csv(name,LOCATION,size)'";
    $instructions="[S]ize"
    break 
  }
}

do {
  $output=$(Invoke-Expression $outputCmd)

  if ($output.Count -eq 0) {
    $Raise_Error = "No $($ResourceType.ToLower()) instances found in GCP project."
    Throw $Raise_Error
  }

  for ($i=0; $i -lt $output.Count; $i++) {
    if ($i -eq 0) {
      # Add index column to object
      $output[$i]="index,$($output[$i])"
    }
    else {
      $output[$i]="$i,$($output[$i])"
    }
  }

  $instances=ConvertFrom-Csv -InputObject $output
  $outText=($instances | Format-Table | Out-String).Replace("`r`n`r`n", "")

  if ([string]::IsNullOrEmpty($Answer)) {    
    Write-Host $outText
    Write-Host $instructions

    $Answer = Read-Host `n'Enter selection'
  }

} while ([string]::IsNullOrEmpty($Answer))


if ($ResourceType -eq 'Compute' -and $Answer -match '^\d$') {
  # Number only, default action is ssh
  $action = "s" # SSH
  [int]$item = $Answer
}
elseif ($ResourceType -eq 'Compute' -and $Answer -match '^([a-z]\d$|q|t)$') {
  $action = $Answer[0]
  [int]$item = $Answer.Substring(1)
}
elseif ($ResourceType -eq 'MIG' -and $answer -match '^(q)$') {
  $action = $Answer[0]
}
elseif ($ResourceType -eq 'MIG' -and $answer -match '^(s\d\.\d)$') {
  $action = $Answer[0]
  [int]$item = $Answer.Substring(1,1)
  [int]$param = $Answer.Substring(3,1)  
}
else {
  write-error "Unable to parse response."
  exit
}

switch ($answer) {
  'q' { exit }
  't' { $action = 'ta' } # Tail all
}

if ($item -gt 0) {
  $sel = $instances[$item-1] # Selection
  Write-Host "Your selection: $sel`n"
}

if ($UseInternalIpSsh -eq $null) {
  # -UseInternalIpSsh switch not present, use proactive detection  
  if ((gwmi win32_computersystem).partofdomain -eq $true) {
    # Domain joined workstation, use Internal IP for SSH
    $UseInternalIpSsh = $true
  }
  else {
    # Standalone workstation, use IAP
    $UseInternalIpSsh = $false
  }
}

if ($UseInternalIpSsh) {
  $UseInternalIpCmd="--internal-ip"
}

switch -wildcard ("$ResourceType`:$action") {
  "*:q" { exit; break }
  "Compute:s" { $type="hcmd"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:u" { $type="cmd"; $argListMid = "compute instance-groups managed update-instances --region=$($sel.zone -replace '..$') --minimal-action=replace $($sel.'created-by') --instances=$($sel.name)"; break }
  "Compute:r" { $type="cmd"; $argListMid = "compute instances reset --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:o" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:l" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name) | grep startup-script"; break }
  "Compute:t" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance AND resource.labels.instance_id=$($sel.id)`" --format=`"value(format('$($sel.name):{0}',json_payload.message).sub(':startup-script:',':'))`""; break }
  "Compute:ta" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance`" --format=`"value(format('{0}:{1}',resource.labels.instance_id,json_payload.message).sub(':startup-script:',':'))`""; break }  
  "MIG:s" { $type="cmd"; $argListMid = "compute instance-groups managed resize $($sel.name) --region=$($sel.location) --size=$($param)"; break }
}



$HAVE_CONEMU=$true # TBC - Add conemu detection

# Default shell
$shell = "cmd"
$shellParams = "/c"
$windowStyle = "Normal"
$SleepCmd = "& timeout /t 60"

if (${Show-Command} -eq $true) {
  $shellParams = "COMMAND:"
  $SleepCmd = ""
}
elseif ($type -eq "hcmd") {
  $windowStyle = "Minimized"
}
elseif ($type -eq "log") {
  $windowStyle = "Maximized"
  $SleepCmd = "& pause"
  if ($HAVE_CONEMU) {
    $shell = "conemu64"
    $shellParams = "-run"
  }
}

$argList = "$shellParams gcloud $argListMid $SleepCmd"

if (${Show-Command} -eq $true) {
  Write-Host "$argList`n"
}
else {
  Start-Process $shell -ArgumentList "$argList " -WindowStyle $windowStyle
}

