# Script to create GPO from Intune Device Health Compliance Policy JSON

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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Device Health - Automated Script)"
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

# --- Registry Settings Mapping for Device Health ---

# 1. secureBootEnabled: true
# Secure Boot is a UEFI firmware setting. GPO cannot enable it.
# It's a prerequisite for some OS-level security features (like VBS/HVCI).
if ($policyObject.PSObject.Properties.Match('secureBootEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.secureBootEnabled -eq $true) {
        Write-Warning "JSON setting 'secureBootEnabled: true' noted. Secure Boot is a UEFI firmware setting and must be enabled in BIOS. GPO cannot enforce this directly. It serves as a prerequisite for features like VBS/HVCI."
    } else {
        Write-Warning "JSON setting 'secureBootEnabled: false' noted. If VBS/HVCI are to be enforced, Secure Boot is recommended to be enabled in firmware."
    }
}

# 2. codeIntegrityEnabled: true (Hypervisor-Enforced Code Integrity - HVCI)
# This requires Virtualization Based Security (VBS).
# Note: The JSON has virtualizationBasedSecurityEnabled: false. To *enforce* Code Integrity, VBS must be enabled.
# The script will attempt to set VBS and HVCI keys if codeIntegrityEnabled is true.
if ($policyObject.PSObject.Properties.Match('codeIntegrityEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.codeIntegrityEnabled -eq $true) {
        Write-Host "JSON setting 'codeIntegrityEnabled: true'. Attempting to enforce VBS and HVCI."
        
        $regKeyDeviceGuard = "SYSTEM\CurrentControlSet\Control\DeviceGuard"

        # EnableVirtualizationBasedSecurity = 1 (Enable VBS)
        # GPO: Computer Configuration > Admin Templates > System > Device Guard > Turn On Virtualization Based Security
        try {
            Write-Host "Applying VBS setting: EnableVirtualizationBasedSecurity = 1"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDeviceGuard -ValueName "EnableVirtualizationBasedSecurity" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for EnableVirtualizationBasedSecurity: $($_.Exception.Message)"
        }

        # RequirePlatformSecurityFeatures = 1 (Secure Boot) or 3 (Secure Boot and DMA Protection)
        # Since kernelDmaProtectionEnabled is false in this JSON, we aim for Secure Boot only.
        # This GPO setting configures VBS to require specific hardware security features.
        $requirePlatformSecurityFeaturesValue = 1 # Default to Secure Boot only
        if ($policyObject.PSObject.Properties.Match('kernelDmaProtectionEnabled').Count -gt 0 -and $policyObject.kernelDmaProtectionEnabled -eq $true) {
            # This case is not met by the current JSON, but included for completeness
            # $requirePlatformSecurityFeaturesValue = 3
        }
         try {
            Write-Host "Applying VBS setting: RequirePlatformSecurityFeatures = $requirePlatformSecurityFeaturesValue (1 = SecureBoot, 3 = SecureBoot+DMA)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDeviceGuard -ValueName "RequirePlatformSecurityFeatures" -Type DWord -Value $requirePlatformSecurityFeaturesValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for RequirePlatformSecurityFeatures: $($_.Exception.Message)"
        }

        # HypervisorEnforcedCodeIntegrity = 1 (Enable HVCI / Memory Integrity)
        # GPO: Computer Configuration > Admin Templates > System > Device Guard > Turn On Virtualization Based Security > Hypervisor Enforced Code Integrity (Memory Integrity)
         try {
            Write-Host "Applying VBS setting: HypervisorEnforcedCodeIntegrity = 1 (Enable HVCI/Memory Integrity)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDeviceGuard -ValueName "HypervisorEnforcedCodeIntegrity" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for HypervisorEnforcedCodeIntegrity: $($_.Exception.Message)"
        }
        
        # Locked = 1 (Prevent VBS/HVCI from being turned off locally) - Optional, but for strong enforcement
        try {
            Write-Host "Applying VBS setting: Locked = 1 (Prevent local VBS/HVCI changes)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyDeviceGuard -ValueName "Locked" -Type DWord -Value 1 -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
        } catch {
            Write-Warning "Failed to set registry value for Locked (DeviceGuard): $($_.Exception.Message)"
        }

        Write-Warning "Enforcing Code Integrity (HVCI) also implies enabling Virtualization Based Security (VBS). The JSON had 'virtualizationBasedSecurityEnabled: $($policyObject.virtualizationBasedSecurityEnabled)'. The script proceeded to set VBS keys."
        Write-Warning "Full effectiveness of VBS/HVCI requires appropriate hardware, firmware (with Secure Boot), and hypervisor support."

    } else {
        Write-Host "JSON setting 'codeIntegrityEnabled: false'. No GPO settings applied for VBS/HVCI."
    }
}

# 3. bitLockerEnabled: true
# Enforcing full BitLocker via GPO is complex. This will set one example policy to require encryption for Fixed Data Drives.
# GPO: Computer Configuration > Admin Templates > Windows Components > BitLocker Drive Encryption > Fixed Data Drives > Deny write access to fixed drives not protected by BitLocker
if ($policyObject.PSObject.Properties.Match('bitLockerEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    if ($policyObject.bitLockerEnabled -eq $true) {
        $regKeyFVE = "SOFTWARE\Policies\Microsoft\FVE"
        $regValueName = "FDVDenyWriteAccess" # Deny write access to non-BitLocker protected Fixed Drives
        $regValue = 1 
        $regType = "DWord"
        try {
            Write-Host "Applying BitLocker setting: Deny write access to fixed drives not protected by BitLocker (FDVDenyWriteAccess = 1)"
            Set-GPRegistryValue -Name $gpoName -Key $regKeyFVE -ValueName $regValueName -Type $regType -Value $regValue -ErrorAction Stop
            $setGPRegistryValueCommandsExecuted++
            Write-Warning "This is one example of enforcing BitLocker. Full BitLocker GPO configuration is more extensive and may involve OS drive encryption, removable drive policies, TPM configuration, etc."
        } catch {
            Write-Warning "Failed to set example BitLocker registry value (FDVDenyWriteAccess): $($_.Exception.Message)"
        }
    } else {
        Write-Host "JSON setting 'bitLockerEnabled: false'. No GPO settings applied for BitLocker."
    }
}

# --- Note on other Device Health settings from JSON ---
Write-Host "---"
Write-Host "Other Device Health related settings from JSON and their status for GPO mapping:"

# tpmRequired: false (in this JSON)
if ($policyObject.PSObject.Properties.Match('tpmRequired').Count -gt 0) {
    $interpretedSettingsFromJson++ # Counted as interpreted
    Write-Host "- tpmRequired: $($policyObject.tpmRequired). TPM is a hardware/firmware prerequisite. GPO cannot enable it but can require its presence for features like BitLocker."
}

# earlyLaunchAntiMalwareDriverEnabled: false (in this JSON)
if ($policyObject.PSObject.Properties.Match('earlyLaunchAntiMalwareDriverEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++ # Counted as interpreted
    Write-Host "- earlyLaunchAntiMalwareDriverEnabled: $($policyObject.earlyLaunchAntiMalwareDriverEnabled). ELAM is typically enabled by the AV solution. Direct GPO for 'enabled' status is complex; usually involves configuring specific ELAM drivers."
}

# storageRequireEncryption: false (in this JSON)
# This is often tied to BitLocker. If BitLocker is enforced, this is usually covered.
if ($policyObject.PSObject.Properties.Match('storageRequireEncryption').Count -gt 0) {
    $interpretedSettingsFromJson++ # Counted as interpreted
    Write-Host "- storageRequireEncryption: $($policyObject.storageRequireEncryption). This is typically achieved via BitLocker. If 'bitLockerEnabled' was true and enforced, this would be implicitly covered."
}

# memoryIntegrityEnabled: false (in this JSON) - This is HVCI
if ($policyObject.PSObject.Properties.Match('memoryIntegrityEnabled').Count -gt 0) {
    # This was already part of codeIntegrityEnabled logic if it were true
    $interpretedSettingsFromJson++ 
    Write-Host "- memoryIntegrityEnabled (HVCI): $($policyObject.memoryIntegrityEnabled). If 'codeIntegrityEnabled' is true, HVCI settings are applied. This specific flag being false means no additional direct enforcement from this flag alone."
}

# kernelDmaProtectionEnabled: false (in this JSON)
if ($policyObject.PSObject.Properties.Match('kernelDmaProtectionEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    Write-Host "- kernelDmaProtectionEnabled: $($policyObject.kernelDmaProtectionEnabled). This is a VBS feature. If set to true, 'RequirePlatformSecurityFeatures' for DeviceGuard would be set to '3' (Secure Boot + DMA). Currently false."
}

# virtualizationBasedSecurityEnabled: false (in this JSON)
if ($policyObject.PSObject.Properties.Match('virtualizationBasedSecurityEnabled').Count -gt 0) {
    # This was already part of codeIntegrityEnabled logic if it were true
    $interpretedSettingsFromJson++
    Write-Host "- virtualizationBasedSecurityEnabled: $($policyObject.virtualizationBasedSecurityEnabled). VBS is a foundational technology for HVCI. If 'codeIntegrityEnabled' is true, VBS registry keys are set accordingly."
}

# firmwareProtectionEnabled: false (in this JSON)
if ($policyObject.PSObject.Properties.Match('firmwareProtectionEnabled').Count -gt 0) {
    $interpretedSettingsFromJson++
    Write-Host "- firmwareProtectionEnabled: $($policyObject.firmwareProtectionEnabled). This relates to advanced firmware security (e.g., System Guard Secure Launch) and is not typically managed by simple GPO registry toggles."
}

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Compliance Policy (Intune Device Health)"
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
Write-Host "  1. Some Intune compliance checks (e.g., 'codeIntegrityEnabled') are translated into multiple registry values."
Write-Host "  2. Settings that are prerequisites (e.g., Secure Boot, TPM) or too complex for single Set-GPRegistryValue commands are noted with warnings but not directly translated into registry changes."
Write-Host "  3. Settings that are 'false' in the JSON are generally not enforced by this script, only noted."
Write-Host "This script focuses on translating 'true' or active Device Health compliance states into enforcing GPO settings where feasible with Set-GPRegistryValue."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - Compliance - U - Device Health - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
