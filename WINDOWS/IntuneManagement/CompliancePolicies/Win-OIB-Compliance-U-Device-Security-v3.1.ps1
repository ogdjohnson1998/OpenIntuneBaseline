# Script to create GPO from Intune Device Security Compliance Policy JSON

#Requires -Modules GroupPolicy

param (
    [string]$JsonContentIn
)

# Helper function to clean the JSON content
function Clean-JsonContent {
    param ([string]$RawContent)
    $cleaned = $RawContent
    if ($cleaned.StartsWith("ÿþ")) {
        $cleaned = $cleaned.Substring(2)
    }
    $cleaned = $cleaned.Replace([char]0, "")
    return $cleaned
}

# Initialize
$setGPRegistryValueCommandsExecuted = 0
$interpretedSettingsFromJson = 0

# Clean and Parse JSON
$cleanedJson = Clean-JsonContent -RawContent $JsonContentIn
try {
    $policyObject = $cleanedJson | ConvertFrom-Json -ErrorAction Stop
} catch {
    Write-Error "Failed to parse JSON content. Error: $($_.Exception.Message)"
    Write-Error "Cleaned JSON content (first 500 chars): $($cleanedJson.Substring(0, [System.Math]::Min($cleanedJson.Length, 500)))"
    exit 1
}

# Extract GPO Name and Description
$gpoName = $policyObject.displayName
$gpoDescription = $policyObject.description
if ([string]::IsNullOrEmpty($gpoDescription)) {
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Device Security - Automated Script)"
}

Write-Host "Preparing to create GPO: '$gpoName'"
Write-Host "Description: '$gpoDescription'"

# Create New GPO
try {
    Import-Module GroupPolicy -ErrorAction Stop
    $existingGpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if ($existingGpo) {
        Write-Warning "GPO named '$gpoName' already exists. Script will not create a new one or modify the existing one. Exiting."
        exit 1
    } else {
        $gpo = New-Gpo -Name $gpoName -Comment $gpoDescription -ErrorAction Stop
        Write-Host "Successfully created GPO: '$($gpo.DisplayName)' (ID: $($gpo.Id))"
    }
} catch {
    Write-Error "Failed to create GPO '$gpoName'. Error: $($_.Exception.Message)"
    exit 1
}

# --- Registry Settings Mapping for Device Security ---

# 1. activeFirewallRequired: true
# Enables Windows Defender Firewall for the Domain Profile.
# GPO: Computer Configuration > Admin Templates > Network > Network Connections > Windows Defender Firewall > Domain Profile > Windows Defender Firewall: Protect all network connections
# Registry: HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall (DWORD)
if ($policyObject.PSObject.Properties.Match('activeFirewallRequired').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.activeFirewallRequired -eq $true) {
        $regKeyFirewall = "SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
        $regValueName = "EnableFirewall"
        $regValue = 1
        $regType = "DWord"
        try {
            Write-Host "Applying Firewall setting: Enable Windows Defender Firewall for Domain Profile (EnableFirewall = 1)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyFirewall -ValueName $regValueName -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for enabling Firewall: $($_.Exception.Message)"
        }
    } else {
        Write-Host "JSON setting 'activeFirewallRequired: false'. No GPO setting applied for Windows Firewall."
    }
}

# 2. antivirusRequired: true AND antiSpywareRequired: true
# The JSON indicates defenderEnabled: false. This means the policy requires *an* AV/AS solution, not necessarily Defender.
# However, GPOs are best at configuring specific solutions. As a best-effort, we will enable Windows Defender's components.
if (($policyObject.PSObject.Properties.Match('antivirusRequired').Count -gt 0 -and $policyObject.antivirusRequired -eq $true) -or `
    ($policyObject.PSObject.Properties.Match('antiSpywareRequired').Count -gt 0 -and $policyObject.antiSpywareRequired -eq $true)) {
    
    if($policyObject.PSObject.Properties.Match('antivirusRequired').Count -gt 0 -and $policyObject.antivirusRequired -eq $true){ $interpretedSettingsFromJson++ }
    if($policyObject.PSObject.Properties.Match('antiSpywareRequired').Count -gt 0 -and $policyObject.antiSpywareRequired -eq $true -and -not ($policyObject.PSObject.Properties.Match('antivirusRequired').Count -gt 0 -and $policyObject.antivirusRequired -eq $true) ){ $interpretedSettingsFromJson++ } # Count only if not already counted by antivirusRequired

    Write-Warning "JSON requires generic Antivirus/Antispyware. Enforcing this by enabling Windows Defender components as a baseline."

    # Enable Defender Antivirus (DisableAntiSpyware = 0)
    # GPO: Computer Configuration > Admin Templates > Windows Components > Microsoft Defender Antivirus > Turn off Microsoft Defender Antivirus
    $regKeyDefender = "SOFTWARE\Policies\Microsoft\Windows Defender"
    try {
        Write-Host "Applying Defender AV setting: Enable Defender Antivirus (DisableAntiSpyware = 0)"
        Set-GPRegistryValue -Name $gpoName -Key $regKeyDefender -ValueName "DisableAntiSpyware" -Type DWord -Value 0 -ErrorAction Stop
        $setGPRegistryValueCommandsExecuted++
    } catch {
        Write-Warning "Failed to set registry value for DisableAntiSpyware (Enable Defender): $($_.Exception.Message)"
    }

    # Enable Defender Real-Time Protection (DisableRealtimeMonitoring = 0)
    # GPO: Computer Configuration > ... > Microsoft Defender Antivirus > Real-time Protection > Turn off real-time protection
    $regKeyDefenderRTP = "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    try {
        Write-Host "Applying Defender RTP setting: Enable Real-Time Monitoring (DisableRealtimeMonitoring = 0)"
        Set-GPRegistryValue -Name $gpoName -Key $regKeyDefenderRTP -ValueName "DisableRealtimeMonitoring" -Type DWord -Value 0 -ErrorAction Stop
        $setGPRegistryValueCommandsExecuted++
    } catch {
        Write-Warning "Failed to set registry value for DisableRealtimeMonitoring (Enable Defender RTP): $($_.Exception.Message)"
    }
} else {
     if($policyObject.PSObject.Properties.Match('antivirusRequired').Count -gt 0) {
        Write-Host "JSON setting 'antivirusRequired: $($policyObject.antivirusRequired)'."
    }
    if($policyObject.PSObject.Properties.Match('antiSpywareRequired').Count -gt 0) {
        Write-Host "JSON setting 'antiSpywareRequired: $($policyObject.antiSpywareRequired)'."
    }
    Write-Host "No GPO settings applied for Antivirus/Antispyware as they are not explicitly required or Defender is not specified as the solution."
}


# 3. tpmRequired: true
# TPM is a hardware/firmware prerequisite. GPO cannot enable it but can require it for other features.
if ($policyObject.PSObject.Properties.Match('tpmRequired').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.tpmRequired -eq $true) {
        Write-Warning "JSON setting 'tpmRequired: true' noted. TPM is a hardware/firmware prerequisite and must be enabled and configured in BIOS/UEFI. GPO cannot enforce this directly. It is essential for features like BitLocker."
    } else {
        Write-Host "JSON setting 'tpmRequired: false' noted."
    }
}

# --- Note on other Device Security settings from JSON ---
Write-Host "---"
Write-Host "Other Device Security related settings from JSON and their status for GPO mapping:"

$otherSettings = @{
    "passwordRequired" = $policyObject.passwordRequired;
    "passwordBlockSimple" = $policyObject.passwordBlockSimple;
    "passwordRequiredToUnlockFromIdle" = $policyObject.passwordRequiredToUnlockFromIdle;
    "passwordMinimumLength" = $policyObject.passwordMinimumLength;
    "osMinimumVersion" = $policyObject.osMinimumVersion;
    "osMaximumVersion" = $policyObject.osMaximumVersion;
    "bitLockerEnabled" = $policyObject.bitLockerEnabled;
    "secureBootEnabled" = $policyObject.secureBootEnabled;
    "codeIntegrityEnabled" = $policyObject.codeIntegrityEnabled;
    "storageRequireEncryption" = $policyObject.storageRequireEncryption;
    "defenderEnabled" = $policyObject.defenderEnabled # Note: This is false, AV/AS above handled via Defender enable.
}

foreach ($settingName in $otherSettings.Keys) {
    if ($policyObject.PSObject.Properties.Match($settingName).Count -gt 0) {
        $interpretedSettingsFromJson++ # Count all present settings as "interpreted"
        $settingValue = $otherSettings[$settingName]
        $warningMessage = "- $settingName: $settingValue. "
        if ($settingValue -eq $true) {
            $warningMessage += "This setting is 'true' but not directly mapped to a simple Set-GPRegistryValue in this script due to complexity (e.g., password policies, full BitLocker setup) or being a prerequisite."
            Write-Warning $warningMessage
        } elseif ($settingValue -eq $false -or $settingValue -eq $null) {
            $warningMessage += "This setting is 'false' or 'null', so no GPO enforcement is applied."
            Write-Host $warningMessage
        } else {
             Write-Host "- $settingName: $settingValue. This setting's value is noted; no specific GPO enforcement logic for this value in the script."
        }
    }
}
Write-Host "Password policies are complex and typically managed via specific GPO templates (Account Policies), not simple registry keys under 'Policies'."
Write-Host "OS Version checks are for compliance reporting and cannot be enforced via GPO registry settings."
Write-Host "---"

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Compliance Policy (Intune Device Security)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Regarding 'settingCount':"
Write-Host "The input JSON is an Intune Compliance Policy, which does not have a 'settingCount' field."
Write-Host "The script interprets specific, known properties from the compliance policy JSON."
Write-Host ""
Write-Host "Number of distinct settings/conditions interpreted from JSON for GPO translation: $interpretedSettingsFromJson"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation:"
Write-Host "The count of 'interpreted settings' and 'executed commands' may differ because:"
Write-Host "  1. Some Intune compliance checks (e.g., 'antivirusRequired') are translated into multiple registry values to enable a baseline (Windows Defender)."
Write-Host "  2. Settings that are prerequisites (e.g., TPM) or too complex for single Set-GPRegistryValue commands (e.g. full password policies) are noted with warnings but not directly translated into registry changes."
Write-Host "  3. Settings that are 'false' or 'null' in the JSON are generally not enforced by this script, only noted."
Write-Host "This script focuses on translating 'true' or active Device Security compliance states into enforcing GPO settings where feasible with Set-GPRegistryValue."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - Compliance - U - Device Security - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
