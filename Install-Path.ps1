## Add script location to %PATH%
param(
  [Switch]$Uninstall
)

$actionVerb = ''
$installPaths = @(
  "$PSScriptRoot",
  "$PSScriptRoot\..\sysinternals",
  "$PSScriptRoot\..\Go\bin",
  "$PSScriptRoot\..\google-cloud-sdk\google-cloud-sdk\bin",
	"$PSScriptRoot\..\istio-1.13.3\bin\"
)

$resolvedPaths = @()

foreach ($p in $installPaths) {
	$rp = $null
	try {
		$rp = $( resolve-path $p ).Path
	}
	catch {
	}
	if ($rp) {
		$resolvedPaths += $rp
	}
}

$installPaths = $resolvedPaths

function Get-EnvPathsArr {
	Param(
		[ValidateSet('User','Machine','All')]
		$Scope='All'
	)	
	
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

Write-Output ''

###
###  Install
###

if ($Uninstall -ne $true) {
	$actionVerb = 'INSTALL'
  $existingPaths = Get-EnvPathsArr
	$existingPathsUser = Get-EnvPathsArr('User')
	
	# List of paths that will be added
	$newPaths = Compare-Object -ReferenceObject $existingPaths -DifferenceObject $installPaths | `
								where SideIndicator -eq '=>' | `
								select -ExpandProperty InputObject
	
	if ($newPaths.Count -gt 0) {
		$newEnvTargetUser=($existingPathsUser + $newPaths) -join ';'
		
		Write-Host "${actionVerb}: Adding the following paths to user %PATH%:`n- $($newPaths -join "`n- ")`n"
		[Environment]::SetEnvironmentVariable("Path", "$newEnvTargetUser", [System.EnvironmentVariableTarget]::User)
		

	}
	else {
		Write-Output "${actionVerb}: Paths already present, no changes needed."
	}
}


###
###  Uninstall
###

if ($Uninstall -eq $true) {
	$actionVerb = 'UNINSTALL'
	$existingPathsUser = Get-EnvPathsArr('User')
	
	$newPaths = Compare-Object -ReferenceObject $existingPathsUser -DifferenceObject $installPaths | `
								where SideIndicator -eq '<=' | `
								select -ExpandProperty InputObject
								
	$removingPaths = Compare-Object -ReferenceObject $existingPathsUser -DifferenceObject $installPaths -ExcludeDifferent -IncludeEqual | `
										select -ExpandProperty InputObject

	if ($removingPaths.Count -gt 0) {
		$newEnvTargetUser = $newPaths -join ';'
		
		Write-Host "${actionVerb}: Removing the following paths from user %PATH%:`n- $($removingPaths -join "`n- ")`n"
		Write-Host "${actionVerb}: Updated user %PATH% values:`n- $($newPaths -join "`n- ")`n"

		[Environment]::SetEnvironmentVariable("Path", "$newEnvTargetUser", [System.EnvironmentVariableTarget]::User)
	}
	else {
		Write-Output "${actionVerb}: No paths present, no changes needed."				
	}
}

###
###  Refresh Shell
###

$pathsRegistry = $(Get-EnvPathsArr) -join ';'

if($pathsRegistry -ne $env:Path) {
	Write-Output "${actionVerb}: Refreshing %PATH% in current shell..."		
	$env:Path = $(Get-EnvPathsArr) -join ';'
}

Write-Output ''
