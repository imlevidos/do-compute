param(
  [Parameter()][ValidateSet('Compute','MIG')][string[]]$ResourceType = 'Compute',
  [Switch]$UseInternalIpSsh,
  [Parameter(Position=0)][string]$Answer
)

# $env:PATH="d:\src\do-compute;$env:path"

switch ($ResourceType) {
  "Compute" { $outputCmd="gcloud compute instances list --format='csv(name,zone,MACHINE_TYPE,INTERNAL_IP,EXTERNAL_IP,status,metadata.items[created-by].scope(instanceGroupManagers))'"; break }
  "MIG" { $outputCmd="gcloud compute instance-groups managed list --format='csv(name,LOCATION,size)'"; break }
}

do {
  $output=$(Invoke-Expression $outputCmd)

  if ($output.Count -eq 0) {
    ThrowError "No $($ResourceType.ToLower()) instances found"
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

  if ([string]::IsNullOrEmpty($Answer)) {
    $outText=($instances | Format-Table | Out-String).Replace("`r`n`r`n", "")
    Write-Host $outText
    Write-Host "S) SSH`tL) Serial port Log`tC) Start-up sCript log`tU) Update instance template`n"

    $Answer = Read-Host `n'Enter selection'
  }

} while ([string]::IsNullOrEmpty($Answer))


if ($Answer -match '^\d$') {
  # Number only, default action is ssh
  $action = "s" # SSH
  [int]$item = $Answer
}
elseif ($Answer -match '^[a-z]\d$') {
  $action = $Answer[0]
  [int]$item = $Answer.Substring(1)
}
else {
  write-error "Unable to parse response."
  exit
}

$sel = $instances[$item-1] # Selection

Write-Host "You selected: $sel`n"

if($UseInternalIpSsh) {
  $UseInternalIpCmd="--internal-ip"
}

switch ($action) {
  "s" { $type="hcmd"; $argListMid = "compute ssh $UseInternalIpCmd --zone=$($sel.zone) $($sel.name)"; break }
  "u" { $type="cmd"; $argListMid = "compute instance-groups managed update-instances --region=$($sel.zone -replace '..$') --minimal-action=replace $($sel.'created-by') --instances=$($sel.name)"; break }
  "l" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name)"; break }
  "c" { $type="log"; $argListMid = "compute instances get-serial-port-output --zone=$($sel.zone) $($sel.name) | grep startup-script"; break }
  "q" { $type="quit"; return 0; break }
}



$HAVE_CONEMU=$true # TBC - Add conemu detection

# Default shell
$shell = "cmd"
$shellParams = "/c"
$windowStyle = "Normal"

if ($type -eq "hcmd") {
  $windowStyle = "Minimized"
}
elseif ($type -eq "log") {
  $windowStyle = "Maximized"
  if ($HAVE_CONEMU) {
    $shell = "conemu64"
    $shellParams = "-run"
  }
}


$argList = "$shellParams gcloud $argListMid & pause"

Start-Process $shell -ArgumentList "$argList" -WindowStyle $windowStyle
