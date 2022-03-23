## Script to remove any duplicate and inexistent paths from %PATH% (machine and user)

function Remove-MissingPaths($paths) {
  $ExistPaths = @()

  foreach ($path in $paths) {
    if (Test-Path $path -PathType Container) {
      $ExistPaths += $path
    }
  }

  Return $ExistPaths
}

function Get-EnvPathArr($Scope) {
  $Paths = @()
  if (@('Machine','All') -icontains $Scope) {
    $Paths += [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
  }
  if (@('User','All') -icontains $Scope) {
    $Paths += [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
  }

  return $Paths
}

function Update-EnvPathsIfNeeded($Scope, $paths) {
  $result = Compare-Object -ReferenceObject (Get-EnvPathArr($Scope)) -DifferenceObject $paths

  if($result -ne $null) {
    Write-Output "Updating $Scope %PATH% to $paths"
    try {
      [Environment]::SetEnvironmentVariable("Path", $paths -join ';', [System.EnvironmentVariableTarget]::$Scope)
    }
    catch {
      $Raise_Error = "ERROR updating $Scope %PATH%"; Throw $Raise_Error
    }
    
    return "SUCCESS"
  }
  return "NOUPDATE"
}


$systEnv = Get-EnvPathArr('Machine')
$userEnv = Get-EnvPathArr('User')

# Remove duplicates
$systEnv = $systEnv | Select-Object -Unique
$userEnv = $userEnv | Select-Object -Unique

# Remove missing paths
$userEnv = Remove-MissingPaths($userEnv)
$systEnv = Remove-MissingPaths($systEnv)

# Remove any user paths that is already in System
$userEnv = Compare-Object -ReferenceObject $systEnv -DifferenceObject $userEnv | Where SideIndicator -eq '=>' | Select -ExpandProperty InputObject

Update-EnvPathsIfNeeded -Scope 'User' -Paths $userEnv
Update-EnvPathsIfNeeded -Scope 'Machine' -Paths $systEnv

# Updating local ENV
$allPaths = (Get-EnvPathArr('All')) -join ';'
if ($allPaths -ne $env:PATH) {
  Write-Output 'Updating %PATH% in local shell.'
  $env:PATH = $allPaths 
}
