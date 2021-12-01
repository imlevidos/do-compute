$project = Read-Host "Enter project name"

Write-Output "Looking up project id..."
$outputCmd="gcloud config configurations list --format='csv(name,is_active,PROJECT)'"
$output=$(Invoke-Expression $outputCmd)
$configs=ConvertFrom-Csv -InputObject $output | where project -ne $null

$oldConfig = $configs | where is_active -eq $true

$projectId = $(gcloud projects list --filter="$project" --format='value(project_id)')

if ($projectId -eq '') {
  gcloud config configurations activate lev
  $projectId=$(gcloud projects list --filter="$project" --format='value(project_id)')
}

if ($projectId -eq '') {
  Throw "Unable to look up GCP Project Id"
}
else {
  Write-Output "Project Id detected: ``$projectId``"
}

$config = $configs | where project -eq $projectId

if ($config.is_active -ne $True) {
  Write-Output "Activating configuration $($config.name) to manage $projectId."
  gcloud config configurations activate $($config.name)
}

Write-Output "Listing MIGs..."

$outputCmd="gcloud compute instance-groups managed list --format='csv(name,LOCATION,size,autoscaled)'";
$output=$(Invoke-Expression $outputCmd)
$migs=ConvertFrom-Csv -InputObject $output

Write-Output $migs

foreach($mig in $migs | where size -gt 0 ) {
  if ($mig.autoscaled -eq 'yes') {
    gcloud compute instance-groups managed stop-autoscaling $($mig.name) --region=$($mig.location) 
  }

  gcloud compute instance-groups managed resize $($mig.name) --region=$($mig.location) --size=0
}

