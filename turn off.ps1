# Step 1: Temporarily set execution policy to Unrestricted for this session
Set-ExecutionPolicy Unrestricted -Scope Process -Force

# Step 2: Define the registry key paths
$regKeyDefender = "HKLM:\Software\Microsoft\Windows Defender"
$regKeyRealTimeProtection = "HKLM:\Software\Microsoft\Windows Defender\Real-Time Protection"
$groupPolicyDefender = "HKLM:\Software\Policies\Microsoft\Windows Defender"
$tamperProtectionKey = "HKLM:\Software\Microsoft\Windows Defender\Features"

# Step 3: Function to set registry key permissions for full access
function Set-RegistryKeyPermission {
    param (
        [string]$keyPath
    )
    try {
        # Get current ACL
        $acl = Get-Acl -Path $keyPath
        # Create access rule to give full control to Administrators
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule("Administrators", "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        # Apply ACL to the key
        Set-Acl -Path $keyPath -AclObject $acl
        Write-Host "Ownership and permissions set for ${keyPath}."
    } catch {
        Write-Host "Error setting permissions for ${keyPath}: $_"
    }
}

# Step 4: Function to permanently disable Defender
function Disable-Defender {
    try {
        # Disable AntiSpyware
        New-ItemProperty -Path $regKeyDefender -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force
        Write-Host "Windows Defender AntiSpyware has been disabled."

        # Disable Real-time Protection
        New-ItemProperty -Path $regKeyRealTimeProtection -Name "DisableRealtimeMonitoring" -Value 1 -PropertyType DWord -Force
        Write-Host "Real-time protection has been disabled."

        # Set Group Policy to permanently disable Defender
        New-ItemProperty -Path $groupPolicyDefender -Name "DisableAntiSpyware" -Value 1 -PropertyType DWord -Force
        Write-Host "Group Policy has been set to permanently disable Defender."

        # Optional: Disable Defender via Group Policy (Pro/Enterprise versions only)
        New-ItemProperty -Path $groupPolicyDefender -Name "DisableAntiVirus" -Value 1 -PropertyType DWord -Force
        Write-Host "Group Policy setting has been applied to disable Defender permanently."

        # Disable Tamper Protection
        New-ItemProperty -Path $tamperProtectionKey -Name "TamperProtection" -Value 0 -PropertyType DWord -Force
        Write-Host "Tamper Protection has been disabled."

    } catch {
        Write-Host "Error disabling Defender or Real-time protection: $_"
    }
}

# Step 5: Take ownership of the registry keys to make changes
Set-RegistryKeyPermission -keyPath $regKeyDefender
Set-RegistryKeyPermission -keyPath $regKeyRealTimeProtection
Set-RegistryKeyPermission -keyPath $groupPolicyDefender
Set-RegistryKeyPermission -keyPath $tamperProtectionKey

# Step 6: Permanently disable Defender and its protections
Disable-Defender

# Final confirmation
Write-Host "Attempted to permanently disable Windows Defender and Real-time protection."
