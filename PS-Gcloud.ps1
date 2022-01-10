param(
  [Parameter()][ValidateSet('Compute','Configurations','MIG','backend-services','SQL')][string[]]$ResourceType = 'Compute',
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
    $instructions="[S]SH`t[O]UTPUT:serial-port `t[L]OG:start-up `t[T]AIL:start-up `t[U]PDATE:instance-template`t[R]ESET`t[D]ESCRIBE`t[Q]UIT"
    $transform='Sort-Object -Property tmpregion,created-by,name'
    break 
  }
  "MIG" { 
    $outputCmd="gcloud compute instance-groups managed list --format='csv(name,LOCATION,size,autoHealingPolicies[0].healthCheck.scope(healthChecks):label='autoheal_hc')'";
    $instructions="[R#=#]ESIZE`t[D]ESCRIBE`t[U]PDATE`t[C]LEAR-AUTOHEALING`t[Q]UIT"
    break 
  }
  "backend-services" {
    $outputCmd="gcloud compute backend-services list --format='csv(name,region.scope(regions),backends[0].group.scope(instanceGroups))'";
    $instructions="[P]OOL:list`t[D]ESCRIBE`t[Q]UIT"
    break 
  }
  "Configurations" {
    $outputCmd="gcloud config configurations list --format='csv(name,is_active,ACCOUNT,PROJECT)'";
    $instructions="[A]CTIVATE`t[Q]UIT"
    break
  }
  "SQL" {
    $outputCmd="gcloud sql instances list --format='csv(name,database_version,gceZone:label='location',settings.availabilityType,settings.tier,ipAddresses[0].ipAddress,state,settings.dataDiskType,settings.dataDiskSizeGb)'";
    $instructions="[B]ACKUP`t[L]IST-BACKUPS`t[Q]UIT"
    break
  }
}

do {
  $output=$(Invoke-Expression $outputCmd)
  $outputTmp=ConvertFrom-Csv -InputObject $output

  if ($output.Count -eq 0) {
    $Raise_Error = "No $($ResourceType.ToLower()) instances found in GCP project."
    Throw $Raise_Error
  }

  for ($i=0; $i -lt $output.Count; $i++) {
    if ($i -eq 0) {
      # Append additional columns to object
      $output[$i]="$($output[$i]),tmpregion"
    }
    else {
      $region=$outputTmp[$i-1].Zone -replace ".{2}$"
      $output[$i]="$($output[$i]),$region"
    }
  }

  $instances = ConvertFrom-Csv -InputObject $output

  if($transform) {
    $instances = Invoke-Expression "`$instances | $transform"
  }

  $outText=($instances | Select-Object * -ExcludeProperty tmp* | ForEach-Object {$index=1} {$_; $index++} | Format-Table -Property @{ Label='index';Expression={$index}; },* | Out-String).Replace("`r`n`r`n", "")

  if ([string]::IsNullOrEmpty($Answer) -or $Answer -eq 'q') {    
    Write-Host $outText
    Write-Host $instructions
  }

  if ([string]::IsNullOrEmpty($Answer)) {    
    $Answer = Read-Host `n'Enter selection'
  }

} while ([string]::IsNullOrEmpty($Answer))

$Answers = Select-String -InputObject $Answer -Pattern '([a-z]{1,2})?(\d+)?=?([\da-z\-]+)?' | select -ExpandProperty Matches | select -ExpandProperty Groups | select -ExpandProperty Value
$Action = $Answers[1]
$Item = $Answers[2]
$Param = $Answers[3]

if ($ResourceType -eq 'Configurations' -and $instances.Name -contains $answer) {
  $action = 'a'
  [int]$item = $instances | Where-Object Name -eq $answer | Select-Object -ExpandProperty Index
}

if ([int]$Item -gt 0) {
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

switch -regex ("$ResourceType`:$action") {
  ".*:q$" { exit; break }
  "Compute:s?$" { $type="hcmd"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:u" { $type="cmd"; $argListMid = "compute instance-groups managed update-instances --region=$($sel.zone -replace '..$') --minimal-action=replace $($sel.'created-by') --instances=$($sel.name)"; break }
  "Compute:r" { $type="cmd"; $argListMid = "compute instances reset --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:o" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:l" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name) | grep startup-script"; break }
  "Compute:d" { $type="inline"; $argListMid = "compute instances describe --zone=$($sel.zone) $($sel.name)"; break }
  "Compute:t" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance AND resource.labels.instance_id=$($sel.id)`" --format=`"value(format('$($sel.name):{0}',json_payload.message).sub(':startup-script:',':'))`""; break }
  "Compute:ta" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance`" --format=`"value(format('{0}:{1}',resource.labels.instance_id,json_payload.message).sub(':startup-script:',':'))`""; break }  
  "MIG:r" { $type="cmd"; $argListMid = "compute instance-groups managed resize $($sel.name) --region=$($sel.location) --size=$($param)"; break }
  "MIG:u" { $type="cmd"; $argListMid = "compute instance-groups managed rolling-action replace $($sel.name) --region=$($sel.location)"; break }
  "MIG:c" { $type="cmd"; $argListMid = "compute instance-groups managed update --clear-autohealing  $($sel.name) --region=$($sel.location)"; break }
  "MIG:d" { $type="inline"; $argListMid = "compute instance-groups managed describe $($sel.name) --region=$($sel.location)"; break }
  "SQL:l" { $type="inline"; $argListMid = "sql backups list --instance=$($sel.name)"; break }
  "SQL:b" { $type="inline"; $argListMid = "sql backups create --instance=$($sel.name)"; break }
  "backend-services:p?$" { $type="inline"; $argListMid = "compute backend-services get-health $($sel.name) --region=$($sel.region) --format='table(status.healthStatus.instance.scope(instances),status.healthStatus.instance.scope(zones).segment(0):label='zone',status.healthStatus.ipAddress,status.healthStatus.healthState)' --flatten='status.healthStatus'"; break }
  "Configurations:a?$" {  $type="inline"; $argListMid = "config configurations activate $($sel.name)"; break }
  default { $Raise_Error = "No action defined for ``$ResourceType`:$action``" ; Throw $Raise_Error }
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
elseif ($type -eq "inline") {
  $shellParams = ""
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
elseif ($type -eq "inline") {
  Invoke-Expression "& $argList"
  Write-Host ''
}
else {
  Start-Process $shell -ArgumentList "$argList " -WindowStyle $windowStyle
}

