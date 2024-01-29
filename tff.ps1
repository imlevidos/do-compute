<#
.VERSION 2024.01.29
#>

[CmdletBinding()]
param(
    [ValidateSet('apply', 'plan', 'destroy', 'init', 'state', 'import', 'login', 'version', 'output', 'validate', 'taint', 'fmt')][string]$Action = 'apply',
    [string[]]$TfArgs,
    [switch]${Auto-Approve},
    [switch]$ShutDown,
    [string]$VarFile,
    [string[]]$TfInitArgs,
    [switch]$StateShow,
    [switch]$StatePull,
    [switch]$StateList,
    [string]$TerraformPath,
    [string]$TerraformVersion
)

<#

.PARAM Force
    Don't exit if there are no Terrform files
#>

$script:InformationPreference = 'SilentlyContinue'

if ($PSBoundParameters.ContainsKey('Debug')) {
    $Script:DebugPreference = 'Continue'
}

Write-Verbose 'Verbose ON'
Write-Debug 'Debug ON'
Write-Information 'Information ON'

function Get-GoogleTokenTTL {
    param(
        [string]$Token
    )

    try {
        $TokenInfo = Invoke-RestMethod -Uri "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=$Token" -ErrorAction Stop
        $ExpiresIn = $TokenInfo.expires_in
        Write-Verbose "Google Token Info: $TokenInfo"
    }
    catch {
        Write-Verbose "Google Token Info REST call failed: $($_.Exception.Message)"
        $ExpiresIn = -5939
    }
    return $ExpiresIn
}

function Get-GitlabToken {
    # Attempt 1: env var
    if ($env:GITLAB_TOKEN) {
        return $env:GITLAB_TOKEN
    }

    if (Test-Path -Path './.gitlab-token') {
        $Token = Get-Content -Path './token-gitlab.secret'
        return $Token
    }
}

function Get-GitlabProjectVars {
    [CmdletBinding()]
    param(
        [string]$Token,
        [string]$Environment = 'auto',
        [bool]$SetEnv = $true
    )

    # Detect Token
    if ([string]::IsNullOrEmpty($Token)) {
        $Token = Get-GitlabToken
    }
    if ([string]::IsNullOrEmpty($Token)) {
        Throw 'Unable to find Gitlab token. Please set GITLAB_TOKEN env.'
    }

    # Detect Environment
    if ($Environment -eq 'auto') {
        $Environment = ''
        $Location = Get-Location
        if ($Location -match '[\\/]environments[\\/]([a-z0-9]+)$') {
            Write-Debug "Detected environment: $($Matches[1])"
            $Environment = $Matches[1]
        }
    }

    # Get Gitlab remote details

    $remote = git remote get-url origin
    
    $HostAndPathPattern = '(?:.*@)?((?:https?\:\/\/)?[a-z0-9\.]+(?:\:\d{1,5})?)[:\/]([a-zA-Z0-9\/\-]+)?(?:\.git)'
    if (!($remote -match $HostAndPathPattern)) {
        Throw "Unable to find Gitlab host and path in remote: $remote"
    }
    if ($Matches.Count -ne 3) {
        Write-Debug "Matches: $($Matches | Out-String)"
        Throw "Unable to find Gitlab host and path in remote: $remote"
    }
    
    $GitlabAddr = $Matches[1]
    Write-Verbose "Detected Gitlab address: $GitlabAddr"
    if ($GitlabAddr -notlike '*://*') {
        $GitlabAddr = "https://$GitlabAddr"
    }
    $ProjectPath = $Matches[2] -replace '/', '%2F'

    Write-Verbose "Detected Gitlab address: $GitlabAddr"
    Write-Verbose "Detected Gitlab project path: $ProjectPath"

    $Headers = @{
        'PRIVATE-TOKEN' = $Token
    }

    $Uri = "$GitlabAddr/api/v4/projects/$ProjectPath"
    try {
        $Project = Invoke-RestMethod -Uri $Uri -Headers $Headers -ErrorAction Stop
    }
    catch {
        Write-Warning "URL: $Uri"
        Throw "Error getting project details: $($_.Exception.Message)"
    }

    $ProjectId = $Project.id
    $ParentId = $Project.namespace.id
    $GrandParentId = $Project.namespace.parent_id
    
    $GitlabVariables = @()
    $GitlabVariables += Invoke-RestMethod -Uri "$GitlabAddr/api/v4/projects/$ProjectId/variables" -Headers $Headers -ErrorAction Stop

    if ($ParentId) {
        try {
            $CallUri = "$GitlabAddr/api/v4/groups/$ParentId/variables"
            $GitlabVariables += Invoke-RestMethod -Uri $CallUri -Headers $Headers
        }
        catch {
            Write-Warning "Cannot query Gitlab parent: $CallUri"
        }
    }
    if ($GrandParentId) {
        try {
            $CallUri = "$GitlabAddr/api/v4/groups/$GrandParentId/variables"
            $GitlabVariables += Invoke-RestMethod -Uri $CallUri -Headers $Headers
        }
        catch {
            Write-Warning "Cannot query Gitlab grandparent: $CallUri"
        }
    }

    $varLookupList = [System.Collections.Specialized.OrderedDictionary]::new()
    $varLookupList['TF_CLOUD_HOSTNAME'] = 'Hostname'
    $varLookupList['TF_CLOUD_ORGANIZATION'] = 'Organization'
    $varLookupList['TF_WORKSPACE'] = 'Workspace'

    $result = @{}

    $Message = ''
    foreach ($varLookup in $varLookupList.GetEnumerator()) {
        foreach ($GitlabVar in $GitlabVariables | Where-Object { $_.Key -eq $varLookup.Key }) {

            if ($Environment -and $GitlabVar.environment_scope -notin @('*', $Environment)) {
                Write-Verbose "Skipping Gitlab var because the envs don't match: $($GitlabVar.Key)/$($GitlabVar.environment_scope)"
                Continue
            }
            
            $Value = $GitlabVar.Value
            Write-Debug "Found Gitlab var: $($varLookup.key) = $Value"
            $result[$varLookupList[$varLookup.key]] = $Value
            if ($SetEnv) {
                Invoke-Expression "`$env:$($varLookup.key)=`"$Value`""
                $Message += "$($varLookup.key): $Value  "
            }
        }
    }

    if ($result) {
        Write-ExecCmd -Header 'TFENV' -Arguments $Message
    }

    return $result
}

function Get-TerraformVersion {
    <#
    .SYNOPSIS
        Try to detect the Terraform Version
    #>
    param(
        [string]$BackendType,
        $TFERemoteDetails = @()
    )

    $Version = switch ($BackendType) {
        'remote' { Get-TerraformVersionRemote -TFERemoteDetails $TFERemoteDetails; Break }
        'cloud' { Get-TerraformVersionRemote -TFERemoteDetails $TFERemoteDetails; Break }
        'none' { Get-TerraformVersionTfstate; Break }
        # 'none' {}
        Default { Get-TerraformVersionText }
    }
    
    if ($null -eq $Version) {
        $Version = '1'
    }

    return $Version
    # ## Method 1: versions.tf
    # if (!(Test-Path versions.tf)) {
    #     return
    # }

    # $vtf = Get-Content versions.tf
    # $search = $vtf | Select-String 'required_version.*?(\d+)\.(\d+)\.(\d+)'

    # if (!$search) {
    #     Write-Debug 'Version cannot be determined from versions.tf'
    #     return
    # }

    # $groups = $search.Matches
    # $null, $major, $minor, $bugfix = $groups.Groups
    # $result = "$major.$minor.$bugfix"
    # Write-Verbose "Detected terraform version from versions.tf: $result"

    # return $result

    # ## Method 2: Terraform state pull:
    # Write-Debug 'Attempting to detect version from the Terraform state'
    # $search = tf state pull | Select-String -Pattern '^  "terraform_version": \"(\d+)\.(\d+)\.(\d+)\"'
    # $groups = $search.Matches
    # $null, $major, $minor, $bugfix = $groups.Groups
    # $result = "$major.$minor.$bugfix"
    # Write-Debug "Detected version from state: $result"
    # return $result
}

function Get-TerraformVersionTfstate {
    $StateFile = './terraform.tfstate'
    if (!(Test-Path $StateFile)) {
        $StateFile = './.terraform/terraform.tfstate'
        if (!(Test-Path $StateFile)) {
            Write-Debug 'No terraform.tfstate file found.'
            return $null
        }
    }

    $Content = Get-Content $StateFile | ConvertFrom-Json
    $Version = $Content.terraform_version
    Write-Debug "Detected Terraform version in ${StateFile}: $Version"
    return $Version
}

function Get-TerraformInitDetails {
    $InitFile = './.terraform/terraform.tfstate'
    $InitDetails = Get-Content -Path $InitFile | ConvertFrom-Json

    $Result = @{
        'backend_type' = $InitDetails.backend.type
        'hostname'     = $InitDetails.backend.config.hostname
        'organization' = $InitDetails.backend.config.organization
        'workspaces'   = $InitDetails.backend.config.workspaces
        'token'        = $InitDetails.backend.config.token
    }
    Return $Result
}

function Get-TerraformVersionRemote {
    param(
        $TFERemoteDetails = @()
    )

    # $GitlabToken = Get-GitlabToken

    <#>
    $RepoConfigFile = './.terraform/terraform.tfstate'
    if (!(Test-Path $RepoConfigFile)) {
        Write-Debug "$RepoConfigFile not found, running terraform init"
        $OldDebugPreference, $DebugPreference = $DebugPreference, 'Continue'
        & terraform init | Write-Debug
        $DebugPreference = $OldDebugPreference
    }

    if (!(Test-Path $RepoConfigFile)) {
        Write-Verbose 'Terraform Init possibly failed, trying to get remote details from code.'
        $Result = Get-TerraformRemoteDetailsFromCode
        $Hostname = $Result.Hostname
        $Organization = $Result.Organization
        $Workspace = $Result.Workspace
    }
    else {
        $Config = Get-Content $RepoConfigFile | ConvertFrom-Json
        $Hostname = $Config.backend.config.hostname
        if (!$Hostname) {
            $Hostname = 'app.terraform.io'
        }
        $Organization = $Config.backend.config.organization
        $Workspace = $null
        if ($Config.backend.config.workspaces) {
            $Workspace = $Config.backend.config.workspaces[0].name
        }
    }
    


    if (!$Organization -or !$Workspace) {
        # Check if we're on an environment specific path
        $Location = Get-Location
        $GetGlpvParams = @{}
        if ($Location -match '[\\/]environments[\\/]([a-z0-9]+)$') {
            Write-Debug "Detected environment: $($Matches[1])"
            $GetGlpvParams['Environment'] = $Matches[1]
        }
        $GitlabVars = Get-GitlabProjectVars -Token $GitlabToken @GetGlpvParams
        $GitlabVars.GetEnumerator() | ForEach-Object {
            Set-Variable -Name $_.Key -Value $_.Value -Force
        }
    }

    Write-Verbose "Hostname: $Hostname`tOrganization: $Organization`tWorkspace: $Workspace"

    $global:TFERemoteDetails = @{
        'hostname'       = $Hostname
        'organization' = $Organization
        'workspace'    = $Workspace
    }
    # Mute the editor warning
    $TFERemoteDetails | Out-Null
    #>

    $Hostname = $TFERemoteDetails.hostname
    $Organization = $TFERemoteDetails.organization
    $Workspace = $TFERemoteDetails.workspace
    if (!$Hostname) {
        $Hostname = 'app.terraform.io'
    }
    if (!$Organization -or !$Workspace) {
        
        Throw 'TFERemoteDetails missing.'
    }
    Write-Debug "Get-TerraformVersionRemote: Hostname: $Hostname, Organization: $Organization, Workspace: $Workspace"

    $TfeToken = Get-TfeToken

    $Params = @{
        'Hostname'     = $Hostname
        'Organization' = $Organization
        'Workspace'    = $Workspace
        'Token'        = $TfeToken
    }

    try {
        $WorkspaceData = Get-TfeWorkspace @Params
    }
    catch {
        Throw "Error getting workspace details: $($_.Exception.Message)"
    }
    $TerraformVersion = $WorkspaceData.attributes.'terraform-version'
    Write-Verbose "TFE Workspace Attributes: $($WorkspaceData.attributes)"
    Write-Debug "Detected Terraform version from remote: $TerraformVersion"
    return $TerraformVersion
}

function Get-TerraformVersionText {
    $Content = Get-Content '*.tf' -ErrorAction Continue
    if ($null -eq $Content) {
        return $null
    }

    $Pattern = 'required_version\s*=\s*\"[~>=\s]*(\d+)(\.\d+)?(\.\d+)?\"'
    $Search = $Content | Select-String -Pattern $Pattern
    $SearchMatches = $Search.Matches

    Write-Verbose "Matches: $SearchMatches"

    If ($null -eq $SearchMatches) {
        Return $null
    }

    $Major = $SearchMatches[0].Groups[1]
    $Minor = $SearchMatches[0].Groups[2]
    $Bugfix = $SearchMatches[0].Groups[3]

    $Result = "${Major}${Minor}${Bugfix}"

    Write-Debug "Detected Terraform version from text: $Result"
    return $Result
}

function Get-TerraformBackendType {
    [CmdletBinding()]
    param()

    if ($script:BackendType) {
        return $script:BackendType
    }

    try {
        $Content = Get-TfContent -Raw -ErrorAction Stop
    }
    catch {
        Throw 'Unable to detect Terraform backend, no *.tf files found.'
    }

    Write-Verbose "Looking for terraform { backend `"...`" } syntax.."
    $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*backend\s*\"([a-z]+)\"'
    if ($Null -eq $Search.Matches) {
        Write-Verbose 'Second attempt, looking for terraform { cloud { } } syntax..'
        # Second attempt, look for `cloud` syntax
        $Search = $Content | Select-String -Pattern 'terraform\s+{[\s\n]*(cloud)'
    }
    if ($Null -eq $Search.Matches) {
        Write-Debug 'Detected backend: None'
        return 'none'
    }
    $script:BackendType = $Search.Matches[0].Groups[1].Value
    Write-Debug "Detected backend: $script:BackendType"

    return $script:BackendType
}

function Get-TfeToken {
    param(
        [string]$Hostname = ''
    )
    # Try terraform.rc
    $CliConfigFileRc = "$env:APPDATA/terraform.rc"
    if (Test-Path $CliConfigFileRc) {
        if (!$Hostname) {
            $Hostname = '.*'
        }
        $Pattern = "credentials\s*`"$Hostname`"\s*{[\s\n]*token\s*=\s*\`"(.*)`""
        $Search = Get-Content -Raw $CliConfigFileRc | Select-String -Pattern $Pattern
        if ($Null -eq $Search.Matches) {
            Throw "Error extracting token from cli config: $CliConfigFileRc"
        }
        $Result = $Search.Matches.Groups[1].Value
        return $Result
    }
    # Try credentials.tfrc.json
    $CliConfigFileTfrc = "$env:APPDATA/terraform.d/credentials.tfrc.json"
    if (Test-Path $CliConfigFileTfrc) {
        if (!$Hostname) {
            $Hostname = 'app.terraform.io'
        }
        $Content = Get-Content -Raw $CliConfigFileTfrc | ConvertFrom-Json
        $Result = $Content.credentials.$Hostname.token
        if ($null -eq $Result) {
            Throw "Cannot find token for $Hostname in: $CliConfigFileTfrc"
        }
        return $Result
    }
    Throw "Unable to find Terraform token in $CliConfigFileRc or $CliConfigFileTfrc"
}

function Get-TfeWorkspace {
    param(
        [Parameter(Mandatory = $true)][string]$Hostname,
        [Parameter(Mandatory = $true)][string]$Organization,
        [Parameter(Mandatory = $true)][string]$Workspace,
        [Parameter(Mandatory = $true)][string]$Token
    )

    $Headers = @{
        'Authorization' = "Bearer $TOKEN"
        'Content-Type'  = 'application/vnd.api+json'
    }
    
    $URL = "https://$Hostname/api/v2/organizations/$Organization/workspaces/$Workspace"
    
    $Response = Invoke-RestMethod -Uri $URL -Headers $Headers -ErrorAction Stop
    $Result = $Response.Data

    return $Result
}

function Get-TfContent {
    <#
    .SYNOPSIS
        Get Terraform content from files, filters out comments
    .VERSION
        2024.01.20
    #>
    
    [CmdletBinding()]
    param(
        [string]$Path = './*.tf',
        [switch]$Raw
    )

    $SpecialModes = "\/\*|\*\/|\/\/|\`"|#"
    $MLCommentLevel = 0

    $Content = Get-Content $Path
    $Filtered = @()
    foreach ($line in $Content) {
        if ($MLCommentLevel -gt 0) {
            if ($line -match '\*\/') {
                $line = $line -replace '.*\*\/', ''
                $MLCommentLevel = 0
            }
            else {
                continue
            }
        }
        
        $CommentLineCheck = $line
        do {
            $Search = Select-String -InputObject $CommentLineCheck -Pattern $SpecialModes -AllMatches
            if ($Search) {
                switch ($search.Matches.Groups[0].Value) {
                    '"' {
                        $CommentLineCheck = $CommentLineCheck -replace "`".*?`"", ''
                    }
                    '#' {
                        $CommentLineCheck = $CommentLineCheck -replace '#.*$', ''
                        $line = $line -replace '#.*$', ''
                    }
                    '/*' {
                        if ($CommentLineCheck -match '\/\*.*\*\/') {
                            # Comment is closed on the same line
                            $CommentLineCheck = $CommentLineCheck -replace '\/\*.*?\*\/', ''
                            $line = $line -replace '\/\*.*?\*\/', ''
                        }
                        else {
                            $MLCommentLevel++
                            $CommentLineCheck = $CommentLineCheck -replace '\/\*.*', ''
                            $line = $line -replace '\/\*.*', ''
                        }
                    }
                    '*/' {
                        $MLCommentLevel = 0
                        $CommentLineCheck = $CommentLineCheck -replace '.*\*\/', ''
                        $line = $line -replace '.*\*\/', ''
                    }
                }
    
            }
        } while ($Search)

        if ($line -match '^\s*$') {
            continue
        }

        $Filtered += $line
    }

    if ($Raw) {
        $Filtered = $Filtered -join "`r`n"
    }

    return $Filtered
}

function Get-TerraformBackendDetailsFromCode {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('none', 'cloud', 'remote', 'gcs')][string]$BackendType
    )

    if ($BackendType -eq 'none') {
        return @{}
    }
    
    $Content = Get-TfContent -Raw -ErrorAction SilentlyContinue
    $Content = $Content -replace "`r|`n", ' '

    $TFERemoteDetails = @{
        'server'       = $null
        'organization' = $null
        'workspace'    = $null
    }

    if ($BackendType -eq 'cloud') {
        $Content -match 'terraform\s*{\s*cloud\s*{\s*.*?}\s*' | Out-Null
        if ($Matches.Count -eq 0) {
            Throw 'Unable to get Terraform Cloud details from code.'
        }
        $Content = $Matches[0]

        $Content -match 'organization\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['organization'] = $Matches[1]
            Write-Verbose "Detected Terraform Cloud organization from code: $($Matches[1])"
        }

        $Content -match 'workspaces\s*{\s*name\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['workspace'] = $Matches[1]
            Write-Verbose "Detected Terraform Cloud workspace from code: $($Matches[1])"
        }

        $Content -match 'hostname\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['hostname'] = $Matches[1]
            Write-Verbose "Detected Terraform Cloud hostname from code: $($Matches[1])"
        }
    }

    if ($BackendType -eq 'remote') {
        $Content -match 'terraform\s*{\s*backend\s*"remote"\s*{\s*.*?}\s*' | Out-Null
        if ($Matches.Count -eq 0) {
            Throw 'Unable to get Terraform Remote details from code.'
        }
        $Content = $Matches[0]

        $Content -match 'organization\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['organization'] = $Matches[1]
            Write-Verbose "Detected Terraform Remote organization from code: $($Matches[1])"
        }

        $Content -match 'workspaces\s*{\s*name\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['workspace'] = $Matches[1]
            Write-Verbose "Detected Terraform Remote workspace from code: $($Matches[1])"
        }

        $Content -match 'hostname\s*=\s*"(.*?)"' | Out-Null
        if ($Matches -and $Matches.Count -eq 2) {
            $TFERemoteDetails['hostname'] = $Matches[1]
            Write-Verbose "Detected Terraform Remote hostname from code: $($Matches[1])"
        }
    }

    return $TFERemoteDetails
}


function Get-TerraformRemoteDetailsFromCodeRemote {
    $Content = Get-Content -Raw '*.tf' 
    $Search = $Content | Select-String -Pattern 'terraform\s*{[\s\n]*backend\s*\"[a-z]+\"\s*{[\s\n]*hostname\s*=\s*\"(.*)\"[\s\n]*organization\s*=\s*\"(.*)\"[\s\n]*workspaces\s*{[\s\n]*(?:#.*\n)\s*name\s*=\s*\"(.*)\"'

    if ($null -eq $Search) {
        Throw 'Unable to get Terraform Remote details from code.'
    }

    $Result = @{
        'Server'       = $Search.Matches[0].Groups[1].Value
        'Organization' = $Search.Matches[0].Groups[2].Value
        'Workspace'    = $Search.Matches[0].Groups[3].Value
    }

    Write-Debug "Detected Terraform remote settings from code: $($Result | Out-String)"

    return $Result
}

function Get-LatestTerraformVersion {
    <#
        Query Terraform website for the latest version matching $Version
    #>
    param(
        $Version
    )

    $dotCount = ($Version | Select-String -Pattern '\.' -AllMatches).Matches.Count
    Write-Verbose "Version: $Version`tDotCount: $dotCount"
    if ($dotCount -ge 2) {
        return $Version
    }

    Write-Debug "Got partial version, looking up the latest version for: $Version"
    $proxy = [System.Net.WebRequest]::DefaultWebProxy
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    
    $proxyUriBuilder = New-Object System.UriBuilder
    $proxyUriBuilder.Scheme = $proxy.Address.Scheme
    $proxyUriBuilder.Host = $proxy.Address.Host
    $proxyUriBuilder.Port = $proxy.Address.Port
    $proxyUri = $proxyUriBuilder.Uri                                                  
    $TfUrl = 'https://releases.hashicorp.com/terraform/'
    $Response = Invoke-WebRequest -Uri $TfUrl -Proxy $ProxyUri -ErrorAction Stop
    $Versions = $Response.Links.innerText
    $Versions = $Versions | Where-Object { $_ -like 'terraform*' -and $_ -NotLike '*-*' }
    $SortedVersions = $Versions | Sort-Object -Descending -Property {
        $VersionComponents = ($_ -replace 'terraform_') -split '\.'
        [version]::new($VersionComponents[0], $VersionComponents[1], $VersionComponents[2])
    }
    $LatestVersion = $SortedVersions | Where-Object { $_ -like "terraform_$Version*" } | Select-Object -First 1
    Write-Verbose "Latest version for $Version is: $LatestVersion"
    if ([string]::IsNullOrEmpty($LatestVersion)) {
        Write-Warning "Available Terrarform versions: $SortedVersions"
        Throw "Unable to find version for: $Version"
    }
    $Version = $LatestVersion -replace 'terraform_', ''
    Write-Debug "Latest version is: $Version"

    return $Version
}

function Invoke-TerraformDownload {
    param(
        [Parameter(Mandatory = $true)][string]$Version,
        [string]$OutDir
    )

    if ([string]::IsNullOrEmpty($OutDir)) {
        $OutDir = "$env:TEMP/.tf.env.ps"
    }

    $InformationPreference = 'Continue'

    $Version = Get-LatestTerraformVersion -Version $Version

    $TfPath = "$OutDir/tf-$Version.exe"

    if (Test-Path $TfPath) {
        $TfPath = Resolve-Path $TfPath | Select-Object -ExpandProperty Path
        Write-Debug "Terraform version already cached: $TfPath"
        
        return $TfPath
    }

    $TfArchive = $TfPath -replace '\.exe$', '.zip'
    if (!(Test-Path -Path $OutDir -PathType Container)) {
        New-Item -ItemType Directory -Path $OutDir | Out-Null
    }

    $arch = switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'x86' { '386' }
        default { Throw "CPU Architecture cannot be determined: $env:PROCESSOR_ARCHITECTURE" }
    }

    $proxy = [System.Net.WebRequest]::DefaultWebProxy
    $proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    
    $proxyUriBuilder = New-Object System.UriBuilder
    $proxyUriBuilder.Scheme = $proxy.Address.Scheme
    $proxyUriBuilder.Host = $proxy.Address.Host
    $proxyUriBuilder.Port = $proxy.Address.Port
    $proxyUri = $proxyUriBuilder.Uri                                                  

    $TfUrl = "https://releases.hashicorp.com/terraform/${Version}/terraform_${Version}_windows_${arch}.zip"
    
    Write-Information "Downloading Terraform v${Version} to: $TfPath"
    # Invoke-WebRequest -Uri $TfUrl -OutFile $TfArchive -Proxy $ProxyUri -ErrorAction Stop
    $webClient = New-Object System.Net.WebClient
    if ($ProxyUri) {
        $webClient.Proxy = New-Object System.Net.WebProxy($ProxyUri)
    }
    $webClient.DownloadFile($TfUrl, $TfArchive)

    Expand-Archive -Path $TfArchive -DestinationPath $OutDir -Force -ErrorAction Stop
    Remove-Item -Path $TfArchive
    Rename-Item -Path "$OutDir/terraform.exe" -NewName $TfPath

    $TFPath = Resolve-Path $TfPath | Select-Object -ExpandProperty Path

    # Test
    $Test = & $TfPath version
    if ($LASTEXITCODE -ne 0) {
        Throw "Terraform download unsuccessful: $TfPath`nExit code: $LASTEXITCODE"
    }
    if ([string]::IsNullOrEmpty($Test)) {
        Throw "Terraform version didn't generate any output. Try running manually? $TfPath"
    }
    if ($Test[0] -notlike "*$Version") {
        Throw "Unexpected terraform version: $TfPath`n$Test"
    }

    Write-Information "Terraform download successful: $TfPath"
    return $TfPath
}

function Get-IsGoogleTokenRequired {
    $Content = Get-TfContent -Raw -ErrorAction SilentlyContinue
    $Search = $Content | Select-String -Pattern 'variable\s*"GOOGLE_ACCESS_TOKEN"\s*{'
    $IsGoogleTokenRequired = $Null -ne $Search.Matches
    if ($IsGoogleTokenRequired) {
        Write-Debug "GOOGLE_ACCESS_TOKEN required: $IsGoogleTokenRequired"
    }
    return $IsGoogleTokenRequired
}

function Invoke-TerraformInit {
    param(
        [Parameter(Mandatory = $true)][string]$TerraformPath,
        [Parameter(Mandatory = $true)][string]$BackendType,
        [bool]$Reconfigure,
        [string[]]$TfInitArgs
    )

    $lastError = $null
    $retries = 0

    while ($retries -le 1) {
        $retries++;

        switch ($lastError) {
            'BackendConfigEnvNeeded' {
                Get-GitlabProjectVars -Token $GitlabToken
            }
        }

    
        if ($Script:InitCompleted) {
            Write-Verbose 'Terraform init already completed.'
            return
        }

        Write-Debug "Attempting: terraform init for backend type: $BackendType"
        if (Test-Path -Path './tf-init.ps1') {
            Write-ExecCmd 'tf-init.ps1'
            & .\tf-init.ps1
        }
        else {
            $TfCmd = @($TerraformPath, 'init')
            if ($TfInitArgs) {
                $TfCmd += $TfInitArgs
            }

            if ($BackendType -eq 'gcs') {
                $TfCmd += "-backend-config=`"access_token=$env:TF_VAR_GOOGLE_ACCESS_TOKEN`""
            } 
            if ($Reconfigure -and $BackendType -notin @('remote', 'cloud')) {
                $TfCmd += '-reconfigure'
            }

            Write-ExecCmd -Arguments $TfCmd -NewLineBefore
            Invoke-Expression "& $TfCmd" 2>&1 | Tee-Object -Variable ProcessOutput | Write-Host
        }

        if ($LASTEXITCODE -eq 0) {
            $Script:InitCompleted = $true
            Write-Verbose 'Terraform init completed successfully.'
            Return
        }

        $BackendConfigEnvNeededPattern = 'or as an environment variable: TF_CLOUD_ORGANIZATION'

        if ($ProcessOutput -match $BackendConfigEnvNeededPattern) {
            Write-Debug 'Backend config env vars needed, attempting to find them'
            $lastError = 'BackendConfigEnvNeeded'
            Continue
        }

    
        Throw "Terraform init failed with exit code: $LASTEXITCODE"
    }
}

function Invoke-TerraformProviderLockFix {
    $Params = 'providers lock -platform=windows_amd64 -platform=darwin_amd64 -platform=linux_amd64' -split ' '
    $TfCmd = @($TerraformPath)
    $TfCmd += $Params
    Write-Host 'Attempting providers lock fix..'
    # Write-Host "`n[ EXEC ]: $($TfCmd -join ' ')" -ForegroundColor Green
    Write-ExecCmd -Arguments $TfCmd
    Invoke-Expression "& $TfCmd" | Write-Host
}

function Invoke-TerraformValidate {
    param(
        [string]$BackendType,
        [string]$TerraformPath,
        [string[]]$TfInitArgs
    )

    $lastError = $null
    $retries = 0

    # Terraform Init Loop
    while ($retries -le 1) {
        $retries++;

        switch ($lastError) {
            'InitNeeded' {
                Invoke-TerraformInit -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
                # if ($Result -ne 0) {
                #     Throw "Terraform init failed with exit code: $Result"
                # }
            }
        }

        Write-ExecCmd -Arguments @($TerraformPath, 'validate')
        & $TerraformPath validate 2>&1 | Tee-Object -Variable ProcessOutput | Write-Host

        if ($LASTEXITCODE -eq 0) {
            Write-Verbose 'Terraform validate success.'
            Return
        }

        Write-Debug 'Error running Terraform validate'

        # Any retriable errors can be detected here
        $InitNeededErrors = @(
            'missing or corrupted provider plugins',
            'Missing required provider',
            'module is not yet installed',
            'Module not installed',
            'Module source has changed',
            'please run "terraform init"',
            'Please run "terraform init"'
        )
        $pattern = ($InitNeededErrors | ForEach-Object { [regex]::Escape($_) }) -join '|'
        # Write-Verbose 'Process output is:'
        # Write-Verbose $($ProcessOutput | Out-String)
        # Write-Verbose "REGEX PATTERN: $pattern"
        if ($ProcessOutput -match $pattern) {
            Write-Debug 'Module not installed, Terraform init needed.'
            $lastError = 'InitNeeded'
            Continue
        }

        Throw 'Error running Terraform validate. This error is not retriable.'
    }
}

function Invoke-TerraformOutput {
    param(
        [Parameter(Mandatory = $true)][string]$TerraformPath,
        [Parameter(Mandatory = $false)][string[]]$TfArgs,
        [switch]$Save,
        [switch]$Obj
    )
    
    if ($TfArgs) {
        Write-ExecCmd -Arguments @($TerraformPath, 'output', $TfArgs -join ' ')
        & $TerraformPath output $TfArgs
        Return
    }
    
    $Messages = @()
    Write-ExecCmd -Arguments @($TerraformPath, 'output')

    if ($Save) {
        & $TerraformPath output > tf-output.txt
        $Messages += { Write-ExecCmd -Header 'SAVED' -Arguments '-> tf-output.txt' } # -HeaderColor DarkGray -ArgumentsColor DarkGray
        if (Test-Path '.gitignore') {
            $gitignore = Get-Content '.gitignore'
            if (!($gitignore -like 'tf-output.txt')) {
                Add-Content '.gitignore' 'tf-output.txt'
                Write-Verbose 'Patched: tf-output.txt >> .gitignore'
            }
            if (!($gitignore -like 'tfplans')) {
                Add-Content '.gitignore' 'tfplans'
                Write-Verbose 'Patched: tfplans >> .gitignore'
            }
        }
    }

    if ($Obj) {
        $TfOutputJson = & $TerraformPath output -json
        $TfOutputObj = $TfOutputJson | ConvertFrom-Json -ErrorAction Stop
        $global:TfOutput = [System.Collections.Specialized.OrderedDictionary]::new()
        $TfOutputObj.PSObject.Properties | Sort-Object -Property Name | ForEach-Object { 
            $TfOutput[$_.Name] = $_.Value.value 
        }
        $global:TfOutputJson = $TfOutput | ConvertTo-Json -Depth 100
    
        $Messages += { Write-ExecCmd -Header 'SAVED' -Arguments '-> $TfOutput $TfOutputJson' }
        if (Get-Command yq) {
            $global:TfOutputJson | yq e -PC -
        }
        else {
            $TfOutput | Format-Table             
        }
    }

    if ($Messages) {
        Write-Host
        $Messages | ForEach-Object { & $_ }
    }
}

function Remove-StateLock {
    param(
        # Mandatory
        [Parameter(Mandatory = $true)][string]$LockPath
    )

    Write-Information "Detected lock path: $lockPath"
    $response = Read-Host -Prompt 'Delete? (y/n)'
    if ($response -ne 'y') {
        exit 1
    }

    & gcloud storage rm $LockPath
}

function Invoke-TfStateShow {
    param(
        [Parameter(Mandatory = $true)][string]$TerraformPath
    )

    $global:TfStateList = & $TerraformPath state list
    $Selection = $TfStateList | Out-GridView -Title 'Select resources to show' -PassThru
    $global:TfStateShowData = @()

    foreach ($item in $Selection) {
        $item = $item -replace '"', '\"'
        Write-ExecCmd -Arguments @($TerraformPath, 'state show', $item)
        & $TerraformPath state show $item | Tee-Object -Variable TfStateShow
        $global:TfStateShowData += $TfStateShow
    }
    Write-ExecCmd -Header 'SAVED' -Arguments '-> $TfStateList'
    if ($global:TfStateShowData) {
        Write-ExecCmd -Header 'SAVED' -Arguments '-> $TfStateShowData'
    }
}

function Write-ExecCmd {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [string]$Header = 'EXEC',
        [switch]$SaveToHistory,
        [switch]$SepateLine,
        [switch]$NewLineBefore,
        [switch]$NewLineAfter,
        [string]$HeaderColor = 'Green',
        [string]$ArgumentsColor = 'White'
    )

    if (!$PSBoundParameters.ContainsKey('SaveToHistory')) {
        # Switch wasn't used, determining defaults
        if ($Header -eq 'EXEC') {
            $SaveToHistory = $true
        }
    }

    if (!($PSBoundParameters.ContainsKey('SepateLine') -or $PSBoundParameters.ContainsKey('NewLineBefore') -or $PSBoundParameters.ContainsKey('NewLineAfter'))) {
        # Switch wasn't used, determining defaults
        if ($Header -eq 'EXEC') {
            $SepateLine = $true
        }
    }

    $Header = $Header.PadRight(5, ' ') + ': '
    $Arguments = $Arguments -join ' '

    if ($SepateLine -or $NewLineBefore) {
        Write-Host
    }

    Write-Host $Header -NoNewline -ForegroundColor $HeaderColor
    Write-Host "$Arguments" -ForegroundColor $ArgumentsColor

    if ($SepateLine -or $NewLineAfter) {
        Write-Host
    }

    if ($SaveToHistory) {
        try {
            [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($Arguments)
        }
        catch {
        }
        if ($script:ScriptCommand) {
            try {
                [Microsoft.PowerShell.PSConsoleReadLine]::AddToHistory($script:ScriptCommand)
            }
            catch {
            }
        }
    }
}

$isDotSourced = $MyInvocation.InvocationName -eq '.' -or $MyInvocation.Line -eq ''
if ($isDotSourced) {
    Write-Output 'INFO: Dot-sourcing functions complete.'
    Return
}
$script:InitCompleted = $false
$script:ScriptCommand = $MyInvocation.Line

###   [ START ]
###

$InvokeTfDlParams = @{}
if ($env:TF_ENV_PS_DIR) {
    $InvokeTfDlParams['OutDir'] = $env:TF_ENV_PS_DIR
}


$NeedsBackendInfo = $true
if ($NeedsBackendInfo) {
    $BackendType = Get-TerraformBackendType
    if (!$script:BackendDetails) {
        if ($BackendType -in @('cloud', 'remote')) {
            $script:BackendDetails = Get-TerraformBackendDetailsFromCode -BackendType $BackendType
        
            if (!$BackendDetails.hostname -or !$BackendDetails.organization -or !$BackendDetails.workspace) {
                $script:BackendDetails = Get-GitlabProjectVars
            }
        }

    }
}


#Region Detect Terraform Version and Download it

if (!$TerraformPath) {
    if (!$TerraformVersion) {
        # Detect Terraform Version
        $BackendType = Get-TerraformBackendType
        $FunctionParam = @()
        if ($script:BackendDetails) {
            $FunctionParam = @{'TFERemoteDetails' = $script:BackendDetails }
        }
        $TerraformVersion = Get-TerraformVersion -BackendType $BackendType @FunctionParam
        Write-ExecCmd -Header 'INFO' -Arguments "Detected Terraform Version: $TerraformVersion"
    }

    # Download Terraform or use cached version
    $TerraformPath = Invoke-TerraformDownload -Version $TerraformVersion -OutDir $env:TF_ENV_PS_DIR
    $ExeDir = Split-Path $TerraformPath
    if ($env:PATH -notlike "*${ExeDir}*") {
        if ($env:PATH[ - 1] -ne ';') {
            $env:PATH += ';'
        }
        $env:PATH += "${ExeDir}; "
    }
    $TerraformPath = Split-Path $TerraformPath -Leaf
    Write-ExecCmd -Header 'ALIAS' -Arguments "$TerraformPath - > tfv"
    Set-Alias -Name tfv -Value $TerraformPath -Scope Global
}

Get-Command $TerraformPath -ErrorAction Stop | Out-Null
$env:TF = $TerraformPath

#EndRegion

if ($Action -eq 'version') {
    Write-ExecCmd -Arguments @($TerraformPath, 'version') -SepateLine:$false
    & $TerraformPath version
    exit 0
}

#Region GOOGLE_ACCESS_TOKEN

$IsGoogleTokenRequired = Get-IsGoogleTokenRequired

if ($IsGoogleTokenRequired) {
    $TokenTTL = 0

    if ($env:GOOGLE_ACCESS_TOKEN) {
        $TokenTTL = Get-GoogleTokenTTL -Token $env:GOOGLE_ACCESS_TOKEN
        Write-Debug "Google Token valid for $([math]::Round($TokenTTL / 60))m $([math]::Round($TokenTTL % 60))s"
    }

    if ($TokenTTL -lt 20 * 60) {
        $env:TF_VAR_GOOGLE_ACCESS_TOKEN = "$(gcloud auth print-access-token)"
        $env:GOOGLE_ACCESS_TOKEN = $env:TF_VAR_GOOGLE_ACCESS_TOKEN
        Write-ExecCmd -Header 'FETCH' -Arguments 'GOOGLE_ACCESS_TOKEN'
        Invoke-TerraformInit -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
    }
}

#EndRegion

# Check the validity of the token if the file exists.
# No longer needed because we're doing auth at each run, but useful code to keep around.
# if (Test-Path -Path 'token-google.secret') {
#   $token = Get-Content -Path 'token-google.secret'
#   try {
#     $response = Invoke-WebRequest -Uri "https://oauth2.googleapis.com/tokeninfo?access_token=$token" -Method Get
#     Write-Host "Token is valid`n"
#   }
#   catch {
#     if ($_.Exception.Response.StatusCode -eq 400) {
#       $content = $_.Exception.Response.GetResponseStream()
#       $reader = New-Object System.IO.StreamReader($content)
#       $responseBody = $reader.ReadToEnd() | ConvertFrom-Json
#       if ($responseBody.error -eq 'invalid_token') {
#         Write-Host 'Token is likely expired, attempting to refersh token'
#         $env:PYTHONWARNINGS = 'ignore'
#         gcloud auth print-access-token | Out-File -Encoding ASCII .\token-google.secret -NoNewline  
								
#       }
#     }
#     else {
#       Write-Host "Something else happened. Status Code: $($_.Exception.Response.StatusCode)"
#     }
#   }
# }
# else {
#   Write-Host 'File token-google.secret does not exist'
# }

#Region Backend

#EndRegion


#Region [ TfStateList / TfStateShow ]

if ($StateList) {
    Write-ExecCmd -Arguments @($TerraformPath, 'state list')
    & $TerraformPath state list | Tee-Object -Variable TfStateList
    $global:TfStateList = $TfStateList
    Write-ExecCmd -Header 'SAVED' -Arguments '-> $TfStateList'
    exit 0
}

if ($StateShow) {
    Invoke-TfStateShow -TerraformPath $TerraformPath

    # Write-ExecCmd -Arguments @($TerraformPath, 'state list')
    # $TfStateList = & $TerraformPath state list
    # $Selection = $TfStateList | Out-GridView -Title 'Select resources to show' -PassThru
    
    # foreach ($item in $Selection) {
    #     & $TerraformPath state show ($item -replace '"', '\"') | Tee-Object -Variable TfStateList
    #     $env:StateList += $TfStateList
    # }
    exit 0
}

if ($StatePull) {
    Write-ExecCmd -Arguments @($TerraformPath, 'state pull') -SepateLine:$false

    $DownloadDir = "$env:USERPROFILE\Downloads"
    $TempFile = Get-Location | Split-Path -Leaf
    $Suffix = Get-Date -Format 'yyyyMMdd-HHmmss'
    $TempState = "$DownloadDir\$TempFile-$Suffix.tfstate.json"
    $TempStateYaml = "$DownloadDir\$TempFile-$Suffix.tfstate.yaml"
    & $TerraformPath state pull | Set-Content $TempState
    if (Get-Command yq -ErrorAction SilentlyContinue) {
        Write-ExecCmd -Arguments @('yq', '-P', $TempState, '>', $TempStateYaml) -SepateLine:$false -SaveToHistory:$false
        $Content = @()
        $Content += '__metadata:'
        $Content += "  generated: $(Get-Date -Format 'yyyy/MM/dd-HH:mm:ss')"
        foreach ($k in $TFERemoteDetails.keys) {
            $Content += "  ${k}: $($TFERemoteDetails[$k])"
        }
        $Content += "  localPath: $(Get-Location)"
        Set-Content -Path $TempStateYaml -Value $Content
        yq -Poy $TempState | Add-Content $TempStateYaml
        Start-Sleep -Milliseconds 200
        $TempState = $TempStateYaml
    }

    if (Get-Command code -ErrorAction SilentlyContinue) {
        code -n $TempState
    }
    elseif (Get-Command notepad++ -ErrorAction SilentlyContinue) {
        notepad++ $TempState
    }
    else {
        notepad $TempState
    }
    Start-Sleep -Milliseconds 500
    # Remove-Item $TempState

    exit 0
}
# Accept the shorthand syntax: tff init "-upgrade"

#EndRegion

#Region [ login / validate / init / output ]

if ($Action -eq 'login') {
    Write-ExecCmd -Arguments @($TerraformPath, 'login')
    & $TerraformPath login
    exit 0
}

if ($Action -in @('taint', 'login', 'fmt')) {
    $TfArgs = @($Action) + $TfArgs
    Write-ExecCmd -Arguments @($TerraformPath, ($TfArgs -join ' '))
    & $TerraformPath $TfArgs
    exit 0
}

if ($Action -in @('validate', 'plan', 'apply', 'destroy')) {
    Invoke-TerraformValidate -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
    if ($Action -eq 'validate') {
        exit 0
    }
}

if ($Action -eq 'init') {
    # Accept the shorthand syntax: tff init "-upgrade"
    if (!($TfInitArgs) -and $TfArgs) {
        $TfInitArgs = $TfArgs
    }

    Invoke-TerraformInit -TerraformPath $TerraformPath -BackendType $BackendType -TfInitArgs $TfInitArgs
    exit 0
}

if ($Action -eq 'output' -and $TfArgs) {
    Invoke-TerraformOutput -TerraformPath $TerraformPath -TfArgs $TfArgs
    exit 0
}

#EndRegion

#Region [ plan/apply prep ]

$TfArgs = @($Action) + $TfArgs

if ($ShutDown) {
    $TfArgs += '-var=shutdown=true'
}
if (${Auto-Approve}) {
    $TfArgs += '-auto-approve'
}
if ($VarFile) {
    $TfArgs += "-var-file=$VarFile"
}

#EndRegion

#Region [ apply / plan / destroy ]

Write-Information "Starting Terraform ${Action}..`n"

$retries = 0
$lastError = ''

while ($retries -le 1 -and $action -ne 'output') {
    $retries++;

    # switch ($lastError) {
    #   'InitNeeded' {
    #     Invoke-TerraformInit
    #   }
    # }

    # $env:TF_VAR_GOOGLE_ACCESS_TOKEN = $(Get-Content .\token-google.secret)

    # Terraform Apply/Plan/Destroy
    Write-ExecCmd -Arguments @($TerraformPath, $TfArgs) -NewLineAfter
    & $TerraformPath $TfArgs 2>&1 | Tee-Object -Variable ProcessOutput

    $script:TfRunUrl = $ProcessOutput -match '^https://.*/runs/run-'

    if ($LASTEXITCODE -eq 0) {
        Write-Verbose "Terraform ${Action} success."
        break
    }

    # Any retriable errors can be detected here
    # if (($processOutput -match 'Failed to open state file') -and (Test-Path -Path 'token-google.secret')) {
    #   Write-Debug 'Init needed to refersh credentials.'

    #   $lastError = 'InitNeeded'
    #   continue
    # }

    # if ($processOutput -match 'please run "terraform init"') {
    #   $lastError = 'InitNeeded'
    #   continue
    # }

    if ($processOutput -match 'Error acquiring the state lock') {
        $pattern = 'Path:\s+(.*?)\s*│'
		
        $match = [regex]::Match($processOutput, $pattern)
        if (!$match.Success) {
            Write-Error 'Unable to parse lock path from error message'
            exit 1
        }

        $lockPath = $match.Groups[1].Value
        if ([string]::IsNullOrEmpty($lockPath)) {
            Write-Error 'Unable to parse lock path from error message'
            exit 1
        }
        
        Write-Warning "Detected lock path: $lockPath, attempting to remove.."

        Remove-StateLock -LockPath $lockPath
    
        $lastError = 'StateLocked'
        continue
    }

    if ($processOutput -match 'provider-checksum-verification|previously recorded in the dependency lock file') {
        Write-Warning 'Lockfile hash issues detected.'
        Invoke-TerraformProviderLockFix
        Continue
    }

    if ($processOutput -match "run 'gcloud auth application-default login'") {
        Throw 'Google Authentication not configured when using a remote backend.'
        Write-Warning 'Need a fresh GOOGLE_AUTH_TOKEN.'
        Write-ExecCmd -Arguments @('gcloud auth application-default login --no-launch-browser')
        & gcloud auth application-default login --no-launch-browser | Tee-Object -Variable ProcessOutput

        Continue
    }

    # Error is not retriable, exiting.
    exit $LASTEXITCODE
}

#EndRegion

if ($Action -in @('apply', 'destroy', 'output')) {
    Invoke-TerraformOutput -TerraformPath $TerraformPath -Save -Obj
}

if ($script:TfRunUrl) {
    Write-ExecCmd -Header 'RUNID' -Arguments "-> $script:TfRunUrl"
    $global:TfRunUrl = $script:TfRunUrl
}
