<#
.SYNOPSIS
  Headless Intune policy search compatible with PowerShell Constrained Language Mode.
.DESCRIPTION
  Searches Settings Catalog, legacy device configuration, compliance, and
  Administrative Templates policies through Microsoft Graph. Reuses a valid
  Graph session and does not disconnect unless -DisconnectOnExit is specified.

This version includes the corrections from every error encountered so far:

Reuses an active, validated Microsoft Graph session
Leaves the Graph session connected by default
Safely processes @odata.nextLink
Uses -OutputType PSObject to normalize Graph responses
Handles ordered dictionaries without converting them to PSCustomObject
Contains no [pscustomobject]@{} conversions
Contains no explicit instance method calls
Contains no static .NET method calls
Prevents empty Write-Progress -Status values
Validates Settings Catalog policy IDs before constructing URLs
Validates ADMX policy IDs before constructing URLs
Validates ADMX definition value IDs before constructing URLs
Skips malformed Graph records instead of generating URLs containing //definitionValues
Preserves Settings Catalog, legacy policy, compliance policy, and ADMX searches
Supports CSV export and pipeline output
  
#>
[CmdletBinding()]
param(
  [Parameter(Position=0)][string]$SearchString,
  [string]$TenantId,
  [ValidateSet('Global','USGov')][string]$Environment = 'Global',
  [ValidateSet('All','SettingsCatalog','Legacy','Compliance','ADMX')]
  [string[]]$PolicyType = @('All'),
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$DisconnectOnExit
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Status {
  param([string]$Message)
  Write-Host ('[' + (Get-Date -Format 'HH:mm:ss') + '] ' + $Message)
}

function Get-PropertyValue {
  param($InputObject,[string]$Name)
  if ($null -eq $InputObject) { return $null }
  foreach ($property in $InputObject.PSObject.Properties) {
    if ($property.Name -eq $Name) { return $property.Value }
  }
  $keys = $null
  foreach ($property in $InputObject.PSObject.Properties) {
    if ($property.Name -eq 'Keys') { $keys = $property.Value; break }
  }
  foreach ($key in @($keys)) {
    if ([string]$key -eq $Name) { return $InputObject[$key] }
  }
  return $null
}

function ConvertTo-DisplayText {
  param($Value)
  if ($null -eq $Value) { return '' }
  if ($Value -is [string]) { return $Value }
  try { return ($Value | ConvertTo-Json -Depth 25 -Compress) }
  catch { return (($Value | Out-String) -replace '^\s+|\s+$','') }
}

function Test-TextMatch {
  param($Value,[string]$Needle)
  if ($null -eq $Value) { return $false }
  return ([string]$Value -like ('*' + $Needle + '*'))
}

function Test-PolicyType {
  param([string]$Name)
  return (($PolicyType -contains 'All') -or ($PolicyType -contains $Name))
}

function New-Result {
  param([string]$Type,[string]$Platform,[string]$PolicyName,[string]$PolicyId,[string]$SettingFound,$SettingValue)
  # Select-Object creates the record without the CLM-prohibited [pscustomobject]@{} conversion.
  $record = '' | Select-Object Type,Platform,PolicyName,PolicyGuid,SettingFound,SettingValue
  $record.Type = $Type
  $record.Platform = $Platform
  $record.PolicyName = $PolicyName
  $record.PolicyGuid = $PolicyId
  $record.SettingFound = $SettingFound
  $record.SettingValue = ConvertTo-DisplayText $SettingValue
  return $record
}

function Get-GraphCollection {
  param([string]$Uri)
  $items = @()
  $next = $Uri
  while ($next) {
    # OutputType PSObject asks the trusted Graph module to materialize properties.
    $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject
    $value = Get-PropertyValue $response 'value'
    if ($null -ne $value) { $items += @($value) }
    else { $items += $response }
    $next = Get-PropertyValue $response '@odata.nextLink'
  }
  return @($items)
}

function Get-ContextValue {
  param([string]$Name)
  $context = Get-MgContext -ErrorAction SilentlyContinue
  if ($null -eq $context) { return $null }
  return Get-PropertyValue $context $Name
}

function Test-ActiveGraphSession {
  $account = Get-ContextValue 'Account'
  if (-not $account) { return $false }
  $currentEnvironment = Get-ContextValue 'Environment'
  if ($currentEnvironment -and ([string]$currentEnvironment -ne $Environment)) { return $false }
  if ($TenantId) {
    $currentTenant = Get-ContextValue 'TenantId'
    if ([string]$currentTenant -ne $TenantId) { return $false }
  }
  try {
    Invoke-MgGraphRequest -Method GET -Uri '/v1.0/me?$select=id' -OutputType PSObject | Out-Null
    return $true
  }
  catch { return $false }
}

function Connect-IntuneGraph {
  if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
    throw 'Microsoft.Graph.Authentication is not installed or is blocked by application control.'
  }
  Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
  if (Test-ActiveGraphSession) {
    Write-Status ('Reusing active Microsoft Graph session for ' + [string](Get-ContextValue 'Account'))
    return
  }
  $connect = @{ Scopes=@('DeviceManagementConfiguration.Read.All'); Environment=$Environment; NoWelcome=$true; ErrorAction='Stop' }
  if ($TenantId) { $connect['TenantId'] = $TenantId }
  Write-Status 'No active usable Graph session found. Authenticating...'
  Connect-MgGraph @connect | Out-Null
  if (-not (Test-ActiveGraphSession)) { throw 'Graph authentication completed, but session validation failed.' }
  Write-Status ('Connected as ' + [string](Get-ContextValue 'Account'))
}

function Get-Platform {
  param($Object)
  $source = Get-PropertyValue $Object 'Platform'
  if (-not $source) { $source = Get-PropertyValue $Object 'Platforms' }
  if (-not $source) { $source = Get-PropertyValue $Object '@odata.type' }
  if (-not $source) { $source = Get-PropertyValue $Object 'supportedOn' }
  if ($source -match 'android') { return 'Android' }
  if ($source -match 'ios|ipad') { return 'iOS/iPadOS' }
  if ($source -match 'windows') { return 'Windows' }
  if ($source -match 'linux') { return 'Linux' }
  if ($source -match 'mac') { return 'macOS' }
  return ''
}

function Search-FlatPolicy {
  param($Policy,[string]$Needle,[string]$Type)
  $results = @()
  $ignored = @('createdDateTime','description','displayName','name','version','supportsScopeTags','@odata.type','roleScopeTagIds','lastModifiedDateTime','id')
  $name = Get-PropertyValue $Policy 'displayName'
  if (-not $name) { $name = Get-PropertyValue $Policy 'name' }
  $id = Get-PropertyValue $Policy 'id'
  if (-not $id) { return @() }
  foreach ($property in $Policy.PSObject.Properties) {
    if ($ignored -contains $property.Name) { continue }
    $text = ConvertTo-DisplayText $property.Value
    if ((Test-TextMatch $property.Name $Needle) -or (Test-TextMatch $text $Needle)) {
      $results += New-Result $Type (Get-Platform $Policy) ([string]$name) ([string]$id) $property.Name $text
    }
  }
  return @($results)
}

function Search-SettingNode {
  param($Node,[string]$Needle,$Policy)
  $results = @()
  if ($null -eq $Node) { return @() }
  $definitionId = Get-PropertyValue $Node 'settingDefinitionId'
  $values = @()
  $simple = Get-PropertyValue $Node 'simpleSettingValue'
  if ($simple) { $values += Get-PropertyValue $simple 'value' }
  $choice = Get-PropertyValue $Node 'choiceSettingValue'
  if ($choice) { $values += Get-PropertyValue $choice 'value' }
  foreach ($entry in @(Get-PropertyValue $Node 'simpleSettingCollectionValue')) { if ($entry) { $values += Get-PropertyValue $entry 'value' } }
  foreach ($entry in @(Get-PropertyValue $Node 'choiceSettingCollectionValue')) { if ($entry) { $values += Get-PropertyValue $entry 'value' } }
  $groups = Get-PropertyValue $Node 'groupSettingCollectionValue'
  $displayValue = (@($values | ForEach-Object { ConvertTo-DisplayText $_ }) -join ' | ')
  if ((Test-TextMatch $definitionId $Needle) -or (Test-TextMatch $displayValue $Needle)) {
    $policyName = Get-PropertyValue $Policy 'name'
    $policyId = Get-PropertyValue $Policy 'id'
    if ($policyId) { $results += New-Result 'Settings Catalog' (Get-Platform $Policy) ([string]$policyName) ([string]$policyId) ([string]$definitionId) $displayValue }
  }
  if ($choice) {
    foreach ($child in @(Get-PropertyValue $choice 'children')) { if ($child) { $results += Search-SettingNode $child $Needle $Policy } }
  }
  foreach ($group in @($groups)) {
    foreach ($child in @(Get-PropertyValue $group 'children')) { if ($child) { $results += Search-SettingNode $child $Needle $Policy } }
  }
  return @($results)
}

function Search-SettingsCatalog {
  param([string]$Needle)
  Write-Status 'Searching Settings Catalog policies...'
  $results = @(); $policies = @(Get-GraphCollection '/beta/deviceManagement/configurationPolicies'); $index = 0; $count = $policies.Count
  foreach ($policy in $policies) {
    $index++; $name = Get-PropertyValue $policy 'name'; $id = Get-PropertyValue $policy 'id'
    if (-not $id) { Write-Warning 'Skipping a Settings Catalog item without a policy ID.'; continue }
    $status = [string]$name; if (-not $status) { $status = 'Policy ' + [string]$id }
    Write-Progress -Activity 'Settings Catalog' -Status $status -PercentComplete (($index / $count) * 100)
    foreach ($setting in @(Get-GraphCollection ('/beta/deviceManagement/configurationPolicies/' + [string]$id + '/settings'))) {
      $instance = Get-PropertyValue $setting 'settingInstance'
      if ($instance) { $results += Search-SettingNode $instance $Needle $policy }
    }
  }
  Write-Progress -Activity 'Settings Catalog' -Completed
  return @($results)
}

function Search-Legacy {
  param([string]$Needle)
  Write-Status 'Searching legacy device configuration policies...'
  $results = @(); foreach ($policy in @(Get-GraphCollection '/beta/deviceManagement/deviceConfigurations')) { $results += Search-FlatPolicy $policy $Needle 'Configuration Template' }
  return @($results)
}

function Search-Compliance {
  param([string]$Needle)
  Write-Status 'Searching compliance policies...'
  $results = @(); foreach ($policy in @(Get-GraphCollection '/beta/deviceManagement/deviceCompliancePolicies')) { $results += Search-FlatPolicy $policy $Needle 'Compliance' }
  return @($results)
}

function Search-ADMX {
  param([string]$Needle)
  Write-Status 'Searching Administrative Templates policies...'
  $results = @(); $policies = @(Get-GraphCollection '/beta/deviceManagement/groupPolicyConfigurations?$select=id,displayName'); $index = 0; $count = $policies.Count
  foreach ($policy in $policies) {
    $index++; $policyName = Get-PropertyValue $policy 'displayName'; $policyId = Get-PropertyValue $policy 'id'
    if (-not $policyId) { Write-Warning 'Skipping an Administrative Templates item without a policy ID.'; continue }
    $status = [string]$policyName; if (-not $status) { $status = 'Policy ' + [string]$policyId }
    Write-Progress -Activity 'Administrative Templates' -Status $status -PercentComplete (($index / $count) * 100)
    $definitionValues = @(Get-GraphCollection ('/beta/deviceManagement/groupPolicyConfigurations/' + [string]$policyId + '/definitionValues'))
    foreach ($definitionValue in $definitionValues) {
      $valueId = Get-PropertyValue $definitionValue 'id'
      if (-not $valueId) { Write-Warning ('Skipping an ADMX definition without an ID in policy ' + [string]$policyId); continue }
      $definition = Invoke-MgGraphRequest -Method GET -Uri ('/beta/deviceManagement/groupPolicyConfigurations/' + [string]$policyId + '/definitionValues/' + [string]$valueId + '/definition') -OutputType PSObject
      $definitionName = Get-PropertyValue $definition 'displayName'; $supportedOn = Get-PropertyValue $definition 'supportedOn'; $enabled = Get-PropertyValue $definitionValue 'enabled'
      $configuredValue = if ($enabled) { 'Enabled' } else { 'Disabled' }
      if ($enabled) {
        $presentations = @(Get-GraphCollection ('/beta/deviceManagement/groupPolicyConfigurations/' + [string]$policyId + '/definitionValues/' + [string]$valueId + '/presentationValues'))
        $presentationText = ConvertTo-DisplayText $presentations
        if ($presentationText) { $configuredValue += ' | ' + $presentationText }
      }
      if ((Test-TextMatch $definitionName $Needle) -or (Test-TextMatch $configuredValue $Needle)) {
        $platform = ''; if ($supportedOn -match 'android') { $platform='Android' } elseif ($supportedOn -match 'ios|ipad') { $platform='iOS/iPadOS' } elseif ($supportedOn -match 'windows') { $platform='Windows' } elseif ($supportedOn -match 'linux') { $platform='Linux' } elseif ($supportedOn -match 'mac') { $platform='macOS' }
        $results += New-Result 'ADMX Template' $platform ([string]$policyName) ([string]$policyId) ([string]$definitionName) $configuredValue
      }
    }
  }
  Write-Progress -Activity 'Administrative Templates' -Completed
  return @($results)
}

try {
  if (-not $SearchString) { $SearchString = Read-Host 'Enter the setting name or value to search for' }
  if (-not $SearchString) { throw 'SearchString cannot be empty.' }
  Connect-IntuneGraph
  $results = @()
  if (Test-PolicyType 'SettingsCatalog') { $results += Search-SettingsCatalog $SearchString }
  if (Test-PolicyType 'Legacy') { $results += Search-Legacy $SearchString }
  if (Test-PolicyType 'Compliance') { $results += Search-Compliance $SearchString }
  if (Test-PolicyType 'ADMX') { $results += Search-ADMX $SearchString }
  $results = @($results | Sort-Object Type,Platform,PolicyName,SettingFound,SettingValue -Unique)
  Write-Status ('Search complete. Matches: ' + [string]$results.Count)
  if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    $results | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Status ('Results saved to ' + $OutputPath)
  }
  if ($PassThru) { $results } else { $results | Format-Table Type,Platform,PolicyName,PolicyGuid,SettingFound,SettingValue -AutoSize -Wrap }
}
catch { Write-Error $_; exit 1 }
finally {
  if ($DisconnectOnExit) { try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null; Write-Status 'Disconnected from Microsoft Graph.' } catch {} }
}
