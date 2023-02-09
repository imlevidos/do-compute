## Add script location to %PATH%
param(
	[Switch]$Uninstall,
	[Switch]$RefreshOnly	
)

$actionVerb = ''
$installPaths = @(
	# "$PSScriptRoot",
	# "$PSScriptRoot\sysinternals",
	# "$PSScriptRoot\Hashicorp",
	# "$PSScriptRoot\google-cloud-sdk\bin",
	# "$PSScriptRoot\Notepad++",
	# "$PSScriptRoot\PuTTY",
	# "$PSScriptRoot\GitBashPortable",
	# "$PSScriptRoot\GitBashPortable\bin",
	# "$PSScriptRoot\GitBashPortable\mingw64\bin",
	# "$PSScriptRoot\GitBashPortable\usr\bin",
	# "$PSScriptRoot\ffmpeg\bin"
)


function Get-EnvPathsArr {
	Param(
		[ValidateSet('User', 'Machine', 'All')]
		$Scope = 'All'
	)	
	
	$Paths = @()
	
	if ( @('Machine', 'All') -icontains $Scope) {
		$Paths += `
			[Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::Machine).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
	}
	
	if ( @('User', 'All') -icontains $Scope) {
		$Paths += `
			[Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User).Split(';', [System.StringSplitOptions]::RemoveEmptyEntries)
	}
	
	return $Paths
}

Write-Output ''

###
###  Install
###

if (!$Uninstall -and !$RefreshOnly) {
	$actionVerb = 'INSTALL'
	$existingPaths = Get-EnvPathsArr
	$existingPathsUser = Get-EnvPathsArr('User')
	
	# List of paths that will be added
	$newPaths = Compare-Object -ReferenceObject $existingPaths -DifferenceObject $installPaths | `
		where SideIndicator -eq '=>' | `
		select -ExpandProperty InputObject
	
	if ($newPaths.Count -gt 0) {
		$newEnvTargetUser = ($existingPathsUser + $newPaths) -join ';'
		
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

if ($Uninstall -and !$RefereshOnly) {
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

if ($RefereshOnly) {
	$actionVerb = 'REFRESH-ONLY'
}

$pathsRegistry = $(Get-EnvPathsArr) -join ';'

if ($pathsRegistry -ne $env:Path) {
	Write-Output "${actionVerb}: Refreshing %PATH% in current shell..."		
	$env:Path = $(Get-EnvPathsArr) -join ';'
}
else {
	Write-Output "${actionVerb}: %PATH% already up to date."
}

Write-Output ''
