param(
  [Parameter(Position=0)][string]$Logfile
)

$RegexPattern='(  \# (.*) (will|must) be .*(created|destroyed|replaced)| +(.*)\s\# forces replacement)'

$wordColours = @{
  created = 'Green';
  destroyed = 'Red';
  replaced = 'Yellow';
  replacement = 'DarkGray';  
  '#' = 'DarkGray';
  will = 'DarkGray';
  must = 'DarkGray';
  be = 'DarkGray';
  forces = 'DarkGray';
  '' = 'White'
}

$Content = Select-String $Logfile -Pattern $RegexPattern

$Resource = @{
  name = '';
  action = '';
  fgcolor = 0;
}
$Resources = @()

$Content | ForEach-Object {
  $ResourceName = $_.Matches.Groups[2].Value
  $Action = $_.Matches.Groups[4].Value
  $Words = $_.Line -Split " "

  if($ResourceName) {
    $Resources += [pscustomobject]@{
      Name = $ResourceName;
      Action = $Action;
      FGColor = $wordColours["$Action"]
    }
    Write-Host "$ResourceName" -noNewLine
  }

  if($Action) {
    Write-Host " -> " -NoNewLine -ForegroundColor DarkGray
    Write-Host "$Action" -NoNewLine -ForegroundColor $wordColours["$Action"]
  }
  if(!$ResourceName) {
    Write-Host " $($_.Line)" -NoNewLine -ForegroundColor DarkGray
  }

  Write-Host ''
}

# return $Resources