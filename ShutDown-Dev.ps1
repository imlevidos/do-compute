param(
  [string]$Configuration
)

Write-Output "`nINFO: Starting script, looking up GCP Project..."

function Get-GcloudConfigs() {
  $outputCmd = "gcloud config configurations list --format='csv(name,is_active,PROJECT)'"
  $output = $(Invoke-Expression $outputCmd)
  $configs = ConvertFrom-Csv -InputObject $output | where project -ne $null
  return $configs
}

if (!([string]::IsNullOrEmpty(${Configuration}))) {
  Write-Output "Looking up GCP Configurations..."

  $configs = Get-GcloudConfigs
  $oldConfig = $configs | where is_active -eq $true

  if ($configs.name -notcontains $Configuration) {
    $Raise_Error = "ERROR: Configuration $Configuration not found."; Throw $Raise_Error
  }
  elseif ($oldConfig.name -ne $Configuration) {
    $TargetConfig = $configs | where name -eq $Configuration
    Write-Output "Activating configuration $($TargetConfig.Name) to manage $($TargetConfig.project)."
    gcloud config configurations activate $TargetConfig.Name
  }
}


$projectId = Get-GcloudConfigs  | where is_active -eq $true | select -ExpandProperty Project
$projectName = gcloud projects describe $projectId --format="value(name)"

if ($projectName -like 'shd*' -or $projectName -like 'prd*') {
  $Raise_Error = "ERROR: This looks like a PROD project, please double check: ${projectName} / ${projectId}"; Throw $Raise_Error
}

Write-Output "INFO: Current GCP project: ${projectName} / ${projectId}`n"
Read-Host "Continue?"

Write-Output "Listing MIGs..."

$outputCmd = "gcloud compute instance-groups managed list --format='csv(name,LOCATION,size,autoscaled)'";
$output = $(Invoke-Expression $outputCmd)
$migs = ConvertFrom-Csv -InputObject $output

Write-Output $migs

foreach($mig in $migs | where size -gt 0 ) {
  if ($mig.autoscaled -eq 'yes') {
    gcloud compute instance-groups managed stop-autoscaling $($mig.name) --region=$($mig.location) 
  }

  gcloud compute instance-groups managed resize $($mig.name) --region=$($mig.location) --size=0
}
