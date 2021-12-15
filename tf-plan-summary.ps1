param(
  [Parameter(Position=0)][string]$Logfile='.\tf-plan.log',
  [Parameter()][ValidateSet('Text','Object')][string[]]$OutputType = 'Text',
  [Parameter()][string]$Grep= '',
  [Switch]$RefreshPlan
)

if ($RefreshPlan) {
  if (Test-Path $LogFile) {
    $LogFileAttr = Get-ItemProperty $LogFile

    $TFPlansArchiveFolderName='old-tfplans'
    $TFPlansArchiveFolderPath="$($LogFileAttr.DirectoryName)\$TFPlansArchiveFolderName"

    if (!(Test-Path $TFPlansArchiveFolderPath)) {
      New-Item -Path $TFPlansArchiveFolderPath -ItemType Directory
    }

    $LogTime = $LogFileAttr.LastWriteTime
    $LogTimestamp = Get-Date $LogTime -format 'yyyyMMdd-hhmmss'
    $LogRename = "$($LogFileAttr.BaseName)-$LogTimestamp$($LogFileAttr.Extension)"

    Move-Item -Path $Logfile -Destination "$TFPlansArchiveFolderPath\$LogRename"
  }
}

if (!(Test-Path $LogFile)) {
  if ($RefreshPlan) { $UpdatedMsg = 'updated '} else { $UpdatedMsg = '' }
  Write-Output "Generating $($UpdatedMsg)terraform plan..."
  &tf plan -no-color > "$LogFile"

  if ($LASTEXITCODE -ne 0) {
    $Raise_Error = "Error executing Terraform Plan."
    Throw $Raise_Error
  }
}

$RegexPattern='(  \# (.*) (will|must) be .*(created|destroyed|replaced|updated)| +(.*)\s\# forces replacement| ~(.*) ->.*)'

$wordColours = @{
  created = 'Green';
  destroyed = 'Red';
  replaced = 'Yellow';
  replacement = 'Yellow';
  updated = 'White'
  '#' = 'DarkGray';
  will = 'DarkGray';
  must = 'DarkGray';
  be = 'DarkGray';
  forces = 'Yellow';
  '' = 'White'
}

$wordPadded = @{
  created   = '   ';
  destroyed = '  ';
  replaced  = '  ';
  updated   = '   ';
}

$wordAction = @{
  created   = 'create';
  destroyed = 'destroy';
  replaced  = 'replace';
  updated   = 'update';
}

$PlanStart=Select-String $Logfile -Pattern 'Terraform will perform the following actions'
if (!$PlanStart) {
  $Raise_Error = "ERROR: No changes detected in the terraform plan."
  Throw $Raise_Error
}
$PlanStartLine=$PlanStart[0].LineNumber
$PlanEnd=Select-String $Logfile -Pattern 'Plan: (\d+) to add, (\d+) to change, (\d+) to destroy.'
$PlanEndLine=$PlanEnd[0].LineNumber
$Content = Select-String $Logfile -Pattern $RegexPattern

$Resources = @()

Write-Host ''

$Content = $Content | Where-Object { ($_.LineNumber -gt $PlanStartLine) -and ($_.LineNumber -lt $PlanEndLine) }

if ($Grep) {
  $Content = $Content | Where-Object Line -match $Grep
}

$Content | ForEach-Object {
  $ResourceName = $_.Matches.Groups[2].Value -replace '\["', '[\"' -replace '"\]', '\"]'
  $Action = $_.Matches.Groups[4].Value

  if($Action) {
    Write-Host "$($wordAction["$Action"])" -NoNewLine -ForegroundColor $wordColours["$Action"]
    Write-Host "$($wordPadded["$Action"])" -NoNewLine -ForegroundColor DarkGray
  }

  if($ResourceName) {
    $Resources += [pscustomobject]@{
      Name = $ResourceName;
      Action = $Action;
      FGColor = $wordColours["$Action"]
    }
    Write-Host "$ResourceName" -NoNewLine
  }

  if(!$ResourceName) {
    $fgcolor = if ($_.Line | Select-String -Pattern ' # forces replacement') { $wordColours['replaced']  } else {  $wordColours['#'] }
    Write-Host " $($_.Line)" -NoNewLine -ForegroundColor $fgcolor
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

$AddColour = If ($Add -gt 0) {"created"} Else {"#"}
$ChangeColour = If ($Change -gt 0) {"updated"} Else {"#"}
$DestroyColour = If ($Destroy -gt 0) {"destroyed"} Else {"#"}

Write-Host ''
Write-Host 'Plan: ' -NoNewline
Write-Host "$Add to add" -NoNewline -ForegroundColor $wordColours[$AddColour]
Write-Host ', ' -NoNewline -ForegroundColor $wordColours["#"]
Write-Host "$Change to change" -NoNewline -ForegroundColor $wordColours[$ChangeColour]
Write-Host ', ' -NoNewline -ForegroundColor $wordColours["#"]
Write-Host "$Destroy to destroy" -NoNewline -ForegroundColor $wordColours[$DestroyColour]
Write-Host ".`n" -ForegroundColor $wordColours["#"]

# Write-Host "Plan: $Add to add, $Change to change, $Destroy to destroy." -ForegroundColor White

if ($OutputType -eq "Object") {
  return $Resources
}
