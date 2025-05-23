# Script to create GPO from Intune Password Compliance Policy JSON

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
$interpretedSettingsFromJson = 0 # Counts all password-related settings found in JSON

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
    $gpoDescription = "GPO created from Intune policy '$gpoName' (Password Settings - Automated Script)"
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

# --- Registry Settings Mapping for Password Policies ---
Write-Host "--- Processing Password Settings ---"

# Centralized list of password-related properties from the JSON
$passwordProperties = @(
    "passwordRequired", "passwordBlockSimple", "passwordRequiredToUnlockFromIdle", 
    "passwordMinimumLength", "passwordExpirationDays", "passwordPreviousPasswordBlockCount", 
    "passwordMinimumCharacterSetCount", "passwordRequiredType", "passwordMinutesOfInactivityBeforeLock"
)

# Check and process each password property
foreach ($propName in $passwordProperties) {
    if ($policyObject.PSObject.Properties.Match($propName).Count -gt 0) {
        $interpretedSettingsFromJson++
        $propValue = $policyObject.$propName
        Write-Host "Interpreting JSON setting: $propName = $propValue"

        switch ($propName) {
            "passwordMinutesOfInactivityBeforeLock" {
                if ($propValue -ne $null -and $propValue -gt 0) {
                    $timeoutSeconds = $propValue * 60
                    $regKeyDesktop = "Software\Policies\Microsoft\Windows\Control Panel\Desktop" # HKCU context
                    
                    try {
                        Write-Host "Applying Screen Saver Timeout: $timeoutSeconds seconds (HKCU)"
                        Set-GPRegistryValue -Name $gpoName -Key $regKeyDesktop -ValueName "ScreenSaveTimeOut" -Type String -Value $timeoutSeconds.ToString() -ErrorAction Stop
                        $setGPRegistryValueCommandsExecuted++

                        Write-Host "Applying Screen Saver Secure Lock (HKCU)"
                        Set-GPRegistryValue -Name $gpoName -Key $regKeyDesktop -ValueName "ScreenSaverIsSecure" -Type String -Value "1" -ErrorAction Stop
                        $setGPRegistryValueCommandsExecuted++
                        Write-Warning "Note: This sets screen saver timeout and lock under User Configuration. The JSON 'passwordRequiredToUnlockFromIdle' was '$($policyObject.passwordRequiredToUnlockFromIdle)'."
                    } catch {
                        Write-Warning "Failed to set screen saver timeout/lock registry values: $($_.Exception.Message)"
                    }
                } elseif ($propValue -eq 0) {
                     Write-Warning "JSON setting '$propName' is $propValue. This typically means 'disabled' or 'not configured'. No GPO setting applied for screen saver timeout."
                } else { # Covers $null or other non-positive values
                    Write-Warning "JSON setting '$propName' is '$propValue' (null or not configured). No GPO setting applied for screen saver timeout."
                }
            }
            "passwordRequired" {
                 Write-Warning "JSON setting '$propName: $propValue'. Standard GPOs enforce this via password length/complexity, not a direct toggle key modifiable by Set-GPRegistryValue under 'Policies' GPO sections. This setting is typically managed by domain or local security policy (SAM)."
            }
            "passwordBlockSimple" {
                 Write-Warning "JSON setting '$propName: $propValue'. 'Simple' passwords (like 'password' or dictionary words) are usually blocked by enabling complexity. Standard GPO password complexity is not directly managed via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
            }
            "passwordMinimumLength" {
                if ($propValue -ne $null -and $propValue -gt 0) {
                    Write-Warning "JSON setting '$propName: $propValue'. Standard GPO minimum password length is not directly managed via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
                } else {
                     Write-Warning "JSON setting '$propName' is '$propValue' (null or not configured). No specific warning for non-enforcement here."
                }
            }
            "passwordRequiredType" {
                 if ($propValue -ne $null) {
                    Write-Warning "JSON setting '$propName: $propValue'. Standard GPOs define complexity (e.g. requiring uppercase, lowercase, numbers, symbols) rather than a specific type like 'numeric' or 'alphanumeric' via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
                 } else {
                     Write-Warning "JSON setting '$propName' is '$propValue' (null or not configured)."
                 }
            }
            "passwordExpirationDays" { # MaxPasswordAge
                 Write-Warning "JSON setting '$propName: $propValue'. Standard GPO password expiration is not directly managed via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
            }
            "passwordPreviousPasswordBlockCount" { # PasswordHistorySize
                 Write-Warning "JSON setting '$propName: $propValue'. Standard GPO password history is not directly managed via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
            }
            "passwordMinimumCharacterSetCount" {
                 Write-Warning "JSON setting '$propName: $propValue'. This relates to password complexity (number of character types like upper, lower, digit, symbol). Standard GPO complexity is not directly managed via 'Policies' registry keys for Set-GPRegistryValue. This setting is typically managed by domain or local security policy (SAM)."
            }
            "passwordRequiredToUnlockFromIdle" {
                # This is linked to passwordMinutesOfInactivityBeforeLock. If that one is set, ScreenSaverIsSecure is set to 1.
                # If passwordMinutesOfInactivityBeforeLock is NOT set, but this IS true, it's a bit ambiguous for GPO.
                if ($propValue -eq $true -and ($policyObject.passwordMinutesOfInactivityBeforeLock -eq $null -or $policyObject.passwordMinutesOfInactivityBeforeLock -le 0)) {
                     Write-Warning "JSON setting '$propName: $propValue' without 'passwordMinutesOfInactivityBeforeLock' being active. To enforce password on resume from idle via GPO, typically screen saver timeout is also configured. No direct 'Policies' key set for this alone."
                } else {
                    Write-Host "JSON setting '$propName: $propValue'. This is handled in conjunction with 'passwordMinutesOfInactivityBeforeLock'."
                }
            }
            default {
                Write-Warning "Password setting '$propName' with value '$propValue' is present in JSON but has no defined mapping to Set-GPRegistryValue in this script or is covered by other warnings."
            }
        }
    } else {
        Write-Host "Password-related JSON setting '$propName' not found in the policyObject."
    }
}

Write-Host "---"
Write-Host "Note on Password Policy Enforcement:"
Write-Host "Most core password policy settings (length, complexity, history, expiration) are traditionally managed via specific Group Policy extensions (Account Policies -> Password Policy) that modify security databases (SAM for local, NTDS.DIT for domain) rather than registry keys under 'Software\Policies'."
Write-Host "The `Set-GPRegistryValue` cmdlet is primarily for Administrative Template settings that write to these 'Policies' keys. Therefore, this script cannot directly enforce many of the listed password compliance settings into a GPO in a way that clients would process them as standard password policies."
Write-Host "The warnings issued above for each setting reflect this limitation."
Write-Host "Screen saver settings, which can require a password on resume, are an exception and have been mapped if configured in the JSON."
Write-Host "---"

# --- Summary ---
Write-Host "--------------------------------------------------------------------"
Write-Host "GPO Configuration Summary for '$gpoName'"
Write-Host "--------------------------------------------------------------------"
Write-Host "Source JSON: Compliance Policy (Intune Password Settings)"
Write-Host "GPO Name: $gpoName"
Write-Host ""
Write-Host "Regarding 'settingCount':"
Write-Host "The input JSON is an Intune Compliance Policy, which does not have a 'settingCount' field."
Write-Host "The script interprets specific, known properties from the compliance policy JSON."
Write-Host ""
Write-Host "Number of distinct password-related settings interpreted from JSON: $interpretedSettingsFromJson"
Write-Host "Total Set-GPRegistryValue commands successfully executed: $setGPRegistryValueCommandsExecuted"
Write-Host ""
Write-Host "Discrepancy Explanation:"
Write-Host "The count of 'interpreted settings' and 'executed commands' differs significantly because:"
Write-Host "  1. Most standard password policy settings (length, complexity, history, etc.) cannot be enforced using `Set-GPRegistryValue` against client-side processed 'Policies' registry keys. They are typically managed through other GPO mechanisms that modify the SAM or AD security databases."
Write-Host "  2. The script issues `Write-Warning` for each of these unmappable password settings, explaining the limitation."
Write-Host "  3. Only settings like screen saver lock/timeout (if configured in the JSON) are mapped to `Set-GPRegistryValue` under User Configuration."
Write-Host "This script primarily serves to document these limitations when attempting to map Intune password compliance to GPO registry values via Set-GPRegistryValue."
Write-Host "--------------------------------------------------------------------"
Write-Host "Script finished."
# Example of how to run:
# $jsonFilePath = "path\to\Win - OIB - Compliance - U - Password - v3.1.json"
# $fileContent = Get-Content -Path $jsonFilePath -Raw
# .\ThisScriptFileName.ps1 -JsonContentIn $fileContent
