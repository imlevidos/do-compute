param(
  [Parameter()][ValidateSet('Compute','Configurations','Disks','MIG','Backend-Services','Snapshots','SQL')][string[]]$ResourceType,
  [nullable[bool]]$UseInternalIpSsh,
  [Parameter(Position=0)][string]$Answer,
  [Switch]$Install,
  [Switch]${Show-Command},
  [Switch]${ReturnAs-Object},
  [Switch]${SelfLink},[Switch]${Uri},
  [Switch]$Compute,
  [Switch]$Configurations,
  [Switch]$Disks,
  [Switch]$MIG,
  [Switch]${Backend-Services},
  [Switch]$Snapshots,
  [Switch]$SQL
)

$ResourceTypes = @( 'Compute', 'Configurations','Disks','MIG','Backend-Services','Snapshots','SQL')
$SelfLink = $SelfLink -or $Uri

# Alternative parameter validation
if ($ResourceType -eq $null) {
  foreach ($rt in $ResourceTypes) {
    $rtval = Invoke-Expression "`${$rt}"
    if ($rtval -eq $true) {
      $ResourceType=$rt
      break
    }
  }
  if ($ResourceType -eq $null) {
    $ResourceType = $ResourceTypes[0] # Default Resource Type is Compute
  }
}

function Get-EnvPathsArr {
  Param([ValidateSet('User','Machine','All')]$Scope='All')

  $Paths=@() 
  if( @('Machine','All') -icontains $Scope) {
    $Paths += `
      [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Split(';',[System.StringSplitOptions]::RemoveEmptyEntries)
  }
 
  if( @('User','All') -icontains $Scope) {
    $Paths += `
      [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User).Split(';',[System.StringSplitOptions]::RemoveEmptyEntries)
  }

  return $Paths
}


$Sel=$null

# $env:PATH="d:\src\do-compute;$env:path"
if ($Install -eq $true -and ![string]::IsNullOrEmpty($PSScriptRoot)) {
  if (Get-EnvPathsArr('All') -notcontains $PSScriptRoot) {
    Write-Output 'INSTALL: Adding script location to %PATH% as user env var...'

    [Environment]::SetEnvironmentVariable("Path", "$((Get-EnvPathsArr('User')) -join ';');$PSScriptRoot", [System.EnvironmentVariableTarget]::User)
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

$SelfLinkOpts = ''
if($SelfLink -eq $true) {
  $SelfLinkOpts = ',selfLink.scope(v1):label=self_link'
}

switch ($ResourceType) {
  "Compute" { 
    $outputCmd="gcloud compute instances list --format='csv(name,zone,MACHINE_TYPE,INTERNAL_IP,EXTERNAL_IP,status,metadata.items[created-by].scope(instanceGroupManagers),id,networkInterfaces[0].subnetwork.scope(regions).segment(0):label=tmpregion,creationTimestamp.date(%Y-%m-%d %H:%M:%S):label=CreatedTime$SelfLinkOpts)'";
    $instructions="[S]SH`tE[X#=cmd]ECUTE`t[C#=cmd]MD-INLINE`t[O]UTPUT-serial-log`t[T]AIL-STARTUP`t[U]PDATE-instance-template`t[R]ESET`t[P]OWER-OFF`t[D]ESCRIBE`t[Q]UIT"
    $transform='Sort-Object -Property tmpregion,created-by,CreatedTime'
    break 
  }
  "Disks" { 
    $outputCmd="gcloud compute disks list --format='csv(name,LOCATION:sort=1,LOCATION_SCOPE:label=lscope,SIZE_GB,TYPE,status,users[0].scope(instances),users[0].scope(projects):label=tmpUser,creationTimestamp.date(%Y-%m-%d %H:%M:%S):label=CreatedTime,selfLink:label=tmpSelfLink${SelfLinkOpts})'";
    $instructions="[D]ESCRIBE`t[S]NAPSHOT`tD[E]LETE`tDE[T]ACH`t[A#=vm]TTACH`t[Q]UIT"
    # $transform='Sort-Object -Property tmpregion,created-by,CreatedTime'
    break 
  }
  "MIG" { 
    $outputCmd="gcloud compute instance-groups managed list --format='csv(name,LOCATION,size,autoHealingPolicies[0].healthCheck.scope(healthChecks):label='autoheal_hc',creationTimestamp.date(%Y-%m-%d %H:%M:%S):label=CreatedTime$SelfLinkOpts)'";
    $instructions="[R#=#]ESIZE`t[D]ESCRIBE`t[U]PDATE`t[C]LEAR-AUTOHEALING`t[Q]UIT"
    $transform='Sort-Object -Property location,name'
    break 
  }
  "backend-services" {
    $outputCmd="gcloud compute backend-services list --format='csv(name,region.scope(regions),backends[0].group.scope(instanceGroups),creationTimestamp.date(%Y-%m-%d %H:%M:%S):label=CreatedTime$SelfLinkOpts)'";
    $instructions="[P]OOL:list`t[D]ESCRIBE`t[Q]UIT"
    break 
  }
  "Configurations" {
    $outputCmd="gcloud config configurations list --format='csv(name,is_active,ACCOUNT,PROJECT)'";
    $instructions="[A]CTIVATE`t[Q]UIT"
    break
  }
  "Snapshots" { 
    $outputCmd="gcloud compute snapshots list --format='csv(name,disk_size_gb,SRC_DISK,status,storageBytes,storageLocations,creationTimestamp.date(%Y-%m-%d %H:%M:%S):label=CreatedTime$SelfLinkOpts)'";
    $instructions="[D]ESCRIBE`t[Q]UIT"
    # $transform='Sort-Object -Property tmpregion,created-by,CreatedTime'
    break 
  }
  "SQL" {
    $outputCmd="gcloud sql instances list --format='csv(name:sort=1,database_version,gceZone:label='location',settings.availabilityType,settings.tier,ipAddresses[0].ipAddress,state,settings.dataDiskType:label=disk_type,settings.dataDiskSizeGb:label=disk_size,region:label=tmpregion,createTime.date(%Y-%m-%d %H:%M:%S)$SelfLinkOpts)'";
    $instructions="[B]ACKUP`t[L]IST-BACKUPS`t[R#=backup-id]ESTORE`t[S]TART/S[T]OP`tD[E]LETE`t[Q]UIT"
    $transform='Sort-Object -Property name'
    break
  }
}

do {
  $output = $(Invoke-Expression $outputCmd)
  if($LASTEXITCODE -ne 0) {
    $Raise_Error = "Error running gcloud command"; Throw $Raise_Error
  }

  if ($output -ne $null) {
    $instances = ConvertFrom-Csv -InputObject $output -ErrorAction SilentlyContinue
  }
  else {
    $Raise_Error = "ERROR: No $($ResourceType.ToUpper()) instances found in GCP project."; Throw $Raise_Error
  }

  if (Get-Member -InputObject $instances[0] -name "external_ip" -MemberType Properties) {
    if (($instances.external_ip | Group-Object -AsHashTable -AsString)[''].Count -eq $instances.Count) {
      $instances = $instances | Select-Object  -Property * -ExcludeProperty external_ip
    }
  }

  if($transform) {
    $instances = Invoke-Expression "`$instances | $transform"
  }

  $outText=($instances | Select-Object * -ExcludeProperty tmp* | ForEach-Object {$index=1} {$_; $index++} | Format-Table -Property @{ Label='index';Expression={$index}; },* -Wrap | Out-String).Replace("`r`n`r`n", "")

  if (${ReturnAs-Object} -eq $true) {
    return $instances
  }

  if ([string]::IsNullOrEmpty($Answer) -or $Answer -eq 'q') {    
    Write-Host $outText
    Write-Host "$instructions`n"
  }

  if ([string]::IsNullOrEmpty($Answer)) {
    $Answer = Read-Host 'Enter selection'
  }

  if($Answer -eq 'q' ) {
    exit; break
  }

} while ([string]::IsNullOrEmpty($Answer))


if($sel -eq $null) {
  # Lookup phase 0 - gcloud config configurations shortcut
  if ($ResourceType -eq 'Configurations') {
    $sel = $instances | where name -like "*$Answer*"
    $action = 'a'

    if(($sel | measure).Count -eq 0) {
      $Raise_Error = "Filter *$Answer* found no matching entries." ; Throw $Raise_Error     
    }
    elseif(($sel | measure).Count -gt 1) {
      $Raise_Error = "Filter *$Answer* matched multiple entries, pls narrow." ; Throw $Raise_Error     
    }
  }
}

if($sel -eq $null) {
  # Lookup phase 1
  $Answers = Select-String -InputObject $Answer -Pattern '^([a-z]{1})?((\d{1,3}))?(=(.+))?$' | select -ExpandProperty Matches | select -ExpandProperty Groups | select -ExpandProperty Value

 
  if ($Answers -ne $null) {
    $Action = $Answers[1]
    $Item   = $Answers[3]
    $Param  = $Answers[5]

    if([string]::IsNullOrEmpty($Item)) {
      $Raise_Error = "ERROR: No item selected." ; Throw $Raise_Error     
    }
  
    $sel = $instances[$item-1] # Selection
    Write-Host "Your selection: $sel`n"
  }
}

if($sel -eq $null) {
  # Lookup phase 2
  $Answers = Select-String -InputObject $Answer -Pattern '^([a-z]{1})?(:([\da-z\-\*]+))?(=(.+))?$' | select -ExpandProperty Matches | select -ExpandProperty Groups | select -ExpandProperty Value

  if ($Answers -ne $null) {
    $Action = $Answers[1]
    $Filter = $Answers[3]
    $Param = $Answers[5]

    $sel = $instances | where name -ilike "*$Filter*"

    if(($sel | measure).Count -eq 0) {
      $Raise_Error = "Filter *$Filter* found no matching entries." ; Throw $Raise_Error     
    }
    elseif(($sel | measure).Count -gt 1) {
      Write-Host "`nYour selections:"
      $sel.Name | % { "- $_" }
      Write-Host ""
      # Do nothing here but confirm with user at the enxt step.
    }
    else {
      Write-Host "Your selection: $sel`n"
    }
  }
}

if ($sel -eq $null) {
  $Raise_Error = "Unable to determine selection based on *$Answer*." ; Throw $Raise_Error     
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

$selCount=$sel.Count
if($selCount -gt 1 -and ${Show-Command} -eq $false) {
  $YesNo = Read-Host "WARNING: Execute on multiple targets? (yes/no)"
  Write-Host ""
  if (@('y','yes') -notcontains $YesNo) {
    exit; break
  }
}

foreach ($sel in $sel) {
  if($selCount -gt 1 -and ${Show-Command} -eq $false) {
    Write-Host "[PS-GCLOUD] Processing: $($sel.name)...`n"
  }
  switch -regex ("$ResourceType`:$action") {
    ".*:q$" { exit; break }
    "Compute:s?$" { $type="hcmd"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name)"; break }
    "Compute:u" { $type="cmd"; $argListMid = "compute instance-groups managed update-instances --region=$($sel.zone -replace '..$') --minimal-action=replace $($sel.'created-by') --instances=$($sel.name)"; break }
    "Compute:r" { $type="cmd"; $argListMid = "compute instances reset --zone=$($sel.zone) $($sel.name)"; break }
    "Compute:p" { $type="cmd"; $argListMid = "compute instances stop --zone=$($sel.zone) $($sel.name)"; break }
    "Compute:o" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name)"; break }
    "Compute:l" { $type="log"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name) --command=`"sudo journalctl -xefu google-startup-scripts.service`""; break }
    "Compute:x" { $type="log"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name) --command `"$($param)`""; break }
    "Compute:c" { $type="inline"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name) --command `"$($param)`""; break }
    "Compute:d" { $type="inline"; $argListMid = "compute instances describe --zone=$($sel.zone) $($sel.name)"; break }
    # "Compute:t" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance AND resource.labels.instance_id=$($sel.id)`" --format=`"value(format('$($sel.name):{0}',json_payload.message).sub(':startup-script:',':'))`""; break }
    "Compute:ta" { $type="log"; $argListMid = "beta logging tail `"resource.type=gce_instance`" --format=`"value(format('{0}:{1}',resource.labels.instance_id,json_payload.message).sub(':startup-script:',':'))`""; break }  
    "Disks:d" { $type="inline"; $argListMid = "compute disks describe --$($sel.lscope)=$($sel.location) $($sel.name)"; break }
    "Disks:e" { $type="inline"; $argListMid = "compute disks delete --$($sel.lscope)=$($sel.location) $($sel.name)"; break }
    "Disks:s" { $type="cmd"; $argListMid = "compute disks snapshot --$($sel.lscope)=$($sel.location) $($sel.name) --snapshot-names=ps-gcloud-$(Get-Date -Format 'yyyyMMdd-HHmmss')-$($sel.name)"; break }
    "Disks:t" { $type="inline"; $argListMid = "compute instances detach-disk `"projects/$($sel.tmpUser)`" --$($sel.lscope)=$($sel.location) `"--disk=$($sel.tmpSelfLink)`""; break }
    "Disks:a" { $type="inline"; $argListMid = "compute instances attach-disk `"$($param)`" --disk-scope=$($sel.lscope)al `"--disk=$($sel.tmpSelfLink)`""; break }
    "MIG:r" { $type="cmd"; $argListMid = "compute instance-groups managed resize $($sel.name) --region=$($sel.location) --size=$($param)"; break }
    "MIG:u" { $type="cmd"; $argListMid = "compute instance-groups managed rolling-action replace $($sel.name) --region=$($sel.location)"; break }
    "MIG:c" { $type="cmd"; $argListMid = "compute instance-groups managed update --clear-autohealing  $($sel.name) --region=$($sel.location)"; break }
    "MIG:d" { $type="inline"; $argListMid = "compute instance-groups managed describe $($sel.name) --region=$($sel.location)"; break }
    "Snapshots:d" { $type="inline"; $argListMid = "compute snapshots describe $($sel.name)"; break }
    "SQL:l" { $type="inline"; $argListMid = "sql backups list --instance=$($sel.name)"; break }
    "SQL:b" { $type="inline"; $argListMid = "sql backups create --instance=$($sel.name)"; break }
    "SQL:s" { $type="cmd"; $argListMid = "sql instances patch $($sel.name) --activation-policy=ALWAYS "; break }
    "SQL:t" { $type="cmd"; $argListMid = "sql instances patch $($sel.name) --activation-policy=NEVER "; break }
    "SQL:r" { $type="show-command"; $argListMid = "sql backups restore --restore-instance=$($sel.name)  $param"; ${Show-Command}=$true; break }
    "SQL:e" { $type="inline"; $argListMid = "sql instances delete $($sel.name) "; break }
    "backend-services:p?$" { $type="inline"; $argListMid = "compute backend-services get-health $($sel.name) --region=$($sel.region) --format='table(status.healthStatus.instance.scope(instances),status.healthStatus.instance.scope(zones).segment(0):label='zone',status.healthStatus.ipAddress,status.healthStatus.healthState)' --flatten='status.healthStatus'"; break }
    "backend-services:d$" { $type="inline"; $argListMid = "compute backend-services describe $($sel.name) --region=$($sel.region) --format=yaml"; break }
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
    Write-Host "$argList"
  }
  elseif ($type -eq "inline") {
    Invoke-Expression "& $argList"
    Write-Host ''
  }
  else {
    Start-Process $shell -ArgumentList "$argList " -WindowStyle $windowStyle
  }
}

if (${Show-Command} -eq $true) {
  Write-Host ""
}
