<#
  .SYNOPSIS
  Script to summarise a terraform plan, v2023.10.01
  Tested with Terraform v0.11 - v1.5

  .LINK
  https://github.com/levid0s/PS-Gcloud

  .PARAMETER RefreshPlan
  If specified, the terraform plan will be refreshed regardless of the age of the log file.
  If unspecified, the terraform plan will be refreshed if the log file is older than 1 hour.
  To force skipping a refresh, use -RefreshPlan:$false

  .PARAMETER SkipRefreshResources
  Run the terraform plan with the -refresh=false flag. This will skip refreshing the state of the resources.
#>

param(
  [Parameter(Position = 0)][string]$Logfile = '.\tfplans\tf-plan.log',
  [Parameter()][ValidateSet('Text', 'Object')][string[]]$OutputType = 'Text',
  [Parameter()][string]$Grep = '',
  [Switch]$RefreshPlan,
  [Switch]$SkipRefreshResources,
  [string]$TerraformPath = 'tf'
)

$LogFolder = Split-Path $LogFile -Parent
if (!(Test-Path $LogFolder)) {
  New-Item -Path $LogFolder -ItemType Directory
}

# If LogFile is older than 1 hour, refresh the plan, unless -RefreshPlan:$false is specified
if ((Test-Path $LogFile) -and !$RefreshPlan -and $PSBoundParameters.ContainsKey('RefreshPlan')) {
  $LogFileAttr = Get-ItemProperty $LogFile
  $LogTime = $LogFileAttr.LastWriteTime
  $LogAge = (Get-Date) - $LogTime
  if ($LogAge.TotalHours -gt 1) {
    $RefreshPlan = $true
  }
}

if ($RefreshPlan) {
  # Archive existing log file if already exists
  if (Test-Path $LogFile) {
    $LogFileAttr = Get-ItemProperty $LogFile

    $LogTime = $LogFileAttr.LastWriteTime
    $LogTimestamp = Get-Date $LogTime -Format 'yyyyMMdd-hhmmss'
    $LogRename = "$($LogFileAttr.BaseName)-$LogTimestamp$($LogFileAttr.Extension)"

    Move-Item -Path $Logfile -Destination "$($LogFileAttr.DirectoryName)\$LogRename"
  }
}

if ($SkipRefreshResources) {
  $SkipRefreshCmd = '-refresh=false'
}

if (!(Test-Path $LogFile)) {
  if ($RefreshPlan) { $UpdatedMsg = 'updated ' } else { $UpdatedMsg = '' }
  Write-Output "Generating $($UpdatedMsg)terraform plan..."
  &$TerraformPath plan $SkipRefreshCmd -no-color > "$LogFile"

  if ($LASTEXITCODE -ne 0) {
    $Raise_Error = 'Error executing Terraform Plan.'; Throw $Raise_Error
  }
}

$RegexPattern = '(  \# (.*) (will|must) be .*(created|destroyed|replaced|updated)| +(.*)\s\# forces replacement| ~(.*) ->.*)'

$wordColours = @{
  created     = 'Green';
  destroyed   = 'Red';
  replaced    = 'Yellow';
  replacement = 'Yellow';
  updated     = 'White'
  '#'         = 'DarkGray';
  will        = 'DarkGray';
  must        = 'DarkGray';
  be          = 'DarkGray';
  forces      = 'Yellow';
  ''          = 'White'
}

# $wordPadded = @{
#   created   = '   ';
#   destroyed = '  ';
#   replaced  = '  ';
#   updated   = '   ';
# }

$wordAction = @{
  # Dictionary to translate the past tensed words from the log into present tense
  created   = 'create';
  destroyed = 'destroy';
  replaced  = 'replace';
  updated   = 'update';
}

$Padding = ($wordAction.Values | Measure-Object -Maximum -Property Length).Maximum + 2

$PlanStart = Select-String $Logfile -Pattern 'Terraform will perform the following actions'
if (!$PlanStart) {
  $Raise_Error = 'ERROR: No changes detected in the terraform plan.'
  Throw $Raise_Error
}
$PlanStartLine = $PlanStart[0].LineNumber
$PlanEnd = Select-String $Logfile -Pattern 'Plan: (\d+) to add, (\d+) to change, (\d+) to destroy.'
$PlanEndLine = $PlanEnd[0].LineNumber
$Content = Select-String $Logfile -Pattern $RegexPattern

$Resources = @()

Write-Host ''

$Content = $Content | Where-Object { ($_.LineNumber -gt $PlanStartLine) -and ($_.LineNumber -lt $PlanEndLine) }

if ($Grep) {
  $Content = $Content | Where-Object Line -Match $Grep
}

$Content | ForEach-Object {
  $ResourceName = $_.Matches.Groups[2].Value -replace '\["', '[\"' -replace '"\]', '\"]'
  $Action = $_.Matches.Groups[4].Value

  if ($Action) {
    Write-Host "$($wordAction["$Action"].PadRight($Padding,' '))" -NoNewline -ForegroundColor $wordColours["$Action"]
  }

  if ($ResourceName) {
    $Resources += [pscustomobject]@{
      Name    = $ResourceName;
      Action  = $Action;
      FGColor = $wordColours["$Action"]
    }
    Write-Host "$ResourceName" -NoNewline
  }

  if (!$ResourceName) {
    $fgcolor = if ($_.Line | Select-String -Pattern ' # forces replacement') { $wordColours['replaced'] } else { $wordColours['#'] }
    Write-Host " $($_.Line)" -NoNewline -ForegroundColor $fgcolor
  }

  # if(!$ResourceName) {
  #   Write-Host "`t" -NoNewLine
  #   $_.Line -split ' ' | ForEach-Object {
  #     $fgcolor = $wordColours["$_"]
  #     if ($fgcolor) {
  #       Write-Host " $_" -NoNewLine -ForegroundColor $fgcolor
  #     }
  #     else {
  #       Write-Host " $_" -NoNewLine -ForegroundColor DarkGray
  #     }
  #   }
  #   #Write-Host "`t $($_.Line)" -NoNewLine -ForegroundColor DarkGray
  # }

  Write-Host ''
}

$Add = $PlanEnd.Matches.Groups[1].Value
$Change = $PlanEnd.Matches.Groups[2].Value
$Destroy = $PlanEnd.Matches.Groups[3].Value

$AddColour = If ($Add -gt 0) { 'created' } Else { '#' }
$ChangeColour = If ($Change -gt 0) { 'updated' } Else { '#' }
$DestroyColour = If ($Destroy -gt 0) { 'destroyed' } Else { '#' }

Write-Host ''
Write-Host 'Plan: ' -NoNewline
Write-Host "$Add to add" -NoNewline -ForegroundColor $wordColours[$AddColour]
Write-Host ', ' -NoNewline -ForegroundColor $wordColours['#']
Write-Host "$Change to change" -NoNewline -ForegroundColor $wordColours[$ChangeColour]
Write-Host ', ' -NoNewline -ForegroundColor $wordColours['#']
Write-Host "$Destroy to destroy" -NoNewline -ForegroundColor $wordColours[$DestroyColour]
Write-Host ".`n" -ForegroundColor $wordColours['#']

# Write-Host "Plan: $Add to add, $Change to change, $Destroy to destroy." -ForegroundColor White

if ($OutputType -eq 'Object') {
  return $Resources
}
