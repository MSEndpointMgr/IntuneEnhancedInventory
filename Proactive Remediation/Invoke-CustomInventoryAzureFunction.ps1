<#
.SYNOPSIS
Collect custom device inventory and upload to Log Analytics for further processing.

.DESCRIPTION
This script will collect device hardware and / or app inventory and upload this to a Log Analytics Workspace. This allows you to easily search in device hardware and installed apps inventory.
The script is meant to be runned on a daily schedule either via Proactive Remediations (RECOMMENDED) in Intune or manually added as local schedule task on your Windows Computer.

.EXAMPLE
Invoke-CustomInventoryWithAzureFunction.ps1 (Required to run as System or Administrator)

.PARAMETER 
Note the following variables 
$RandomiseCollectionInt - if this is true the randomizer to spread load over X minutes is enabled 
$RandomizeMinutes - the number of minutes to randomize load over. Max 50 minutes to avoid PR timeouts 

.NOTES
FileName:    Invoke-CustomInventory.ps1
Author:      Jan Ketil Skanke
Contributors: Sandy Zeng / Maurice Daly
Contact:     @JankeSkanke
Created:     2021-01-02
Updated:     2023-10-08 by @JankeSkanke

Version history:
0.9.0 - (2021 - 01 - 02) Script created
1.0.0 - (2021 - 01 - 02) Script polished cleaned up.
1.0.1 - (2021 - 04 - 05) Added NetworkAdapter array and fixed typo
2.0 - (2021 - 08 - 29) Moved secrets out of code - now running via Azure Function
2.0.1 (2021-09-01) Removed all location information for privacy reasons 
2.1 - (2021-09-08) Added section to cater for BIOS release version information, for HP, Dell and Lenovo and general bugfixes
2.1.1 - (2021-21-10) Added MACAddress to the inventory for each NIC. 
3.0.0 - (2022-22-02) Azure Function updated - Requires version 1.1 of Azure Function LogCollectorAPI for more dynamic log collecting
3.0.1 - (2022-15-09) Updated to support CloudPC (Different method to find AzureAD DeviceID for verification) and fixed output error from script (Thanks to @gwblok)
3.5.0 - (2022-14-10) Azure Function updated - Requires version 1.2 Updated output logic to be more dynamic. Fixed a bug in the randomizer function and disabled inventory collection during provisioning day.
3.5.1 - (2023-05-30) Added battery information to inventory. 
3.6.0 - (2023-24-02) Added SecureBoot check
3.6.1 - (2023-13-03) Added TPM Version information
4.0.0 - (2023-02-06) Azure Function updated to use AADDeviceTrust from https://github.com/MSEndpointMgr/AADDeviceTrust, requires updating the function app to version 2.0 to support this. 
4.0.1 - (2023-10-08) Adding support for Windows RE Version information
#>

#region initialize
# Script Version 
$ScriptVersion = "4.0.1"

# Define your azure function URL: 
# Example 'https://<appname>.azurewebsites.net/api/<functioname>'

$AzureFunctionURL = ""

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Control if you want to collect App or Device Inventory or both (True = Collect)
$CollectAppInventory = $true
$CollectDeviceInventory = $true
# $CollectCustomInventory = $true *SAMPLE*

#Set Log Analytics Log Name
$AppLogName = "AppInventory"
$DeviceLogName = "DeviceInventory"
# $CustomLogName = "CustomInventory" *SAMPLE*
$Date=(Get-Date)
# Enable or disable randomized running time to avoid azure function to be overloaded in larger environments 
# Set to true only if needed 
$RandomiseCollectionInt = $false 
# Time to randomize over, max 50 minutes to avoid PR timeout. 
$RandomizeMinutes = 30

#endregion initialize

#region functions
# Function to get Azure AD DeviceID
function Get-AzureADDeviceID {
    <#
    .SYNOPSIS
        Get the Azure AD device ID from the local device.
    
    .DESCRIPTION
        Get the Azure AD device ID from the local device.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
		1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find AzureAD DeviceID)
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoKey -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
            
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }    
                }
            }
			if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
				# Handle return value
				return $AzureADDeviceID
			}
		}
	}
} #endfunction 
function Get-AzureADJoinDate {
    <#
    .SYNOPSIS
        Get the Azure AD Join Date from the local device.
    
    .DESCRIPTION
        Get the Azure AD Join Date from the local device.
    
    .NOTES
        Author:      Jan Ketil Skanke (and Nickolaj Andersen)
        Contact:     @JankeSkanke
        Created:     2021-05-26
        Updated:     2021-05-26
    
        Version history:
        1.0.0 - (2021-05-26) Function created
		1.0.1 - (2022-15.09) Updated to support CloudPC (Different method to find AzureAD DeviceID)
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoKey -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
            
            if ($AzureADJoinInfoKey -ne $null) {
                # Match key data against GUID regex
                if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                }
                else {
                    $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoKey }    
                }
            }
		if ($AzureADJoinCertificate -ne $null) {
				# Determine the device identifier from the subject name
				$AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
				# Handle return value
				return $AzureADJoinDate
			}
		}
	}
} #endfunction 
#Function to get AzureAD TenantID
function Get-AzureADTenantID {
	# Cloud Join information registry path
	$AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
	# Retrieve the child key name that is the tenant id for AzureAD
	$AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
	return $AzureADTenantID
}                          
# Function to get all Installed Application
function Get-InstalledApplications() {
	param (
		[string]$UserSid
	)
	
	New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
	$regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
	$regpath += "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
	if (-not ([IntPtr]::Size -eq 4)) {
		$regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
		$regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
	}
	$propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
	$Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName
	Remove-PSDrive -Name "HKU" | Out-Null
	Return $Apps
}
# Function to get AAD Cert Thumbprint
function Get-AzureADRegistrationCertificateThumbprint {
    <#
    .SYNOPSIS
        Get the thumbprint of the certificate used for Azure AD device registration.
    
    .DESCRIPTION
        Get the thumbprint of the certificate used for Azure AD device registration.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contributor: @JankeSkanke
        Contact:     @NickolajA
        Created:     2021-06-03
        Updated:     2022-26-10
    
        Version history:
        1.0.0 - (2021-06-03) Function created
        1.1.0 - (2022-26-10) Added support for finding thumbprint for Cloud PCs @JankeSkanke
    #>
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoKey = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
         # Retrieve the machine certificate based on thumbprint from registry key or Certificate (CloudPC)        
        if ($AzureADJoinInfoKey -ne $null) {
            # Match key data against GUID regex for CloudPC Support 
            if ([guid]::TryParse($AzureADJoinInfoKey, $([ref][guid]::Empty))) {
                #This is for CloudPC
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -like "CN=$($AzureADJoinInfoKey)" }
                $AzureADJoinInfoThumbprint = $AzureADJoinCertificate.Thumbprint
            }
            else {
                # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid (non-CloudPC)
                $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
            }
        }
        # Handle return value
        return $AzureADJoinInfoThumbprint
    }
}
function New-RSACertificateSignature {
	<#
	.SYNOPSIS
		Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
	
	.DESCRIPTION
		Creates a new signature based on content passed as parameter input using the private key of a certificate determined by it's thumbprint, to sign the computed hash of the content.
		The certificate used must be available in the LocalMachine\My certificate store, and must also contain a private key.

	.PARAMETER Content
		Specify the content string to be signed.

	.PARAMETER Thumbprint
		Specify the thumbprint of the certificate.
	
	.NOTES
		Author:      Nickolaj Andersen / Thomas Kurth
		Contact:     @NickolajA
		Created:     2021-06-03
		Updated:     2021-06-03
	
		Version history:
		1.0.0 - (2021-06-03) Function created

		Credits to Thomas Kurth for sharing his original C# code.
	#>
	param(
		[parameter(Mandatory = $true, HelpMessage = "Specify the content string to be signed.")]
		[ValidateNotNullOrEmpty()]
		[string]$Content,

		[parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
		[ValidateNotNullOrEmpty()]
		[string]$Thumbprint
	)
	Process {
		# Determine the certificate based on thumbprint input
		$Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $CertificateThumbprint }
		if ($Certificate -ne $null) {
			if ($Certificate.HasPrivateKey -eq $true) {
				# Read the RSA private key
				$RSAPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
				
				if ($RSAPrivateKey -ne $null) {
					if ($RSAPrivateKey -is [System.Security.Cryptography.RSACng]) {
						# Construct a new SHA256Managed object to be used when computing the hash
						$SHA256Managed = New-Object -TypeName "System.Security.Cryptography.SHA256Managed"

						# Construct new UTF8 unicode encoding object
						$UnicodeEncoding = [System.Text.UnicodeEncoding]::UTF8

						# Convert content to byte array
						[byte[]]$EncodedContentData = $UnicodeEncoding.GetBytes($Content)

						# Compute the hash
						[byte[]]$ComputedHash = $SHA256Managed.ComputeHash($EncodedContentData)

						# Create signed signature with computed hash
						[byte[]]$SignatureSigned = $RSAPrivateKey.SignHash($ComputedHash, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)

						# Convert signature to Base64 string
						$SignatureString = [System.Convert]::ToBase64String($SignatureSigned)
						
						# Handle return value
						return $SignatureString
					}
				}
			}
		}
	}
}
function Get-PublicKeyBytesEncodedString {
	<#
	.SYNOPSIS
		Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
	
	.DESCRIPTION
		Returns the public key byte array encoded as a Base64 string, of the certificate where the thumbprint passed as parameter input is a match.
		The certificate used must be available in the LocalMachine\My certificate store.

	.PARAMETER Thumbprint
		Specify the thumbprint of the certificate.
	
	.NOTES
		Author:      Nickolaj Andersen / Thomas Kurth
		Contact:     @NickolajA
		Created:     2021-06-07
		Updated:     2021-06-07
	
		Version history:
		1.0.0 - (2021-06-07) Function created

		Credits to Thomas Kurth for sharing his original C# code.
	#>
	param(
		[parameter(Mandatory = $true, HelpMessage = "Specify the thumbprint of the certificate.")]
		[ValidateNotNullOrEmpty()]
		[string]$Thumbprint
	)
	Process {
		# Determine the certificate based on thumbprint input
		$Certificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $Thumbprint }
		if ($Certificate -ne $null) {
			# Get the public key bytes
			[byte[]]$PublicKeyBytes = $Certificate.GetPublicKey()

			# Handle return value
			return [System.Convert]::ToBase64String($PublicKeyBytes)
		}
	}
}
function Get-ComputerSystemType {
	<#
	.SYNOPSIS
		Get the computer system type, either VM or NonVM.
	
	.DESCRIPTION
		Get the computer system type, either VM or NonVM.
	
	.NOTES
		Author:      Nickolaj Andersen
		Contact:     @NickolajA
		Created:     2021-06-07
		Updated:     2022-01-01
	
		Version history:
		1.0.0 - (2021-06-07) Function created
		1.0.1 - (2022-01-01) Updated virtual machine array with 'Google Compute Engine'
	#>
	Process {
		# Check if computer system type is virtual
		$ComputerSystemModel = Get-WmiObject -Class "Win32_ComputerSystem" | Select-Object -ExpandProperty "Model"
		if ($ComputerSystemModel -in @("Virtual Machine", "VMware Virtual Platform", "VirtualBox", "HVM domU", "KVM", "VMWare7,1", "Google Compute Engine")) {
			$ComputerSystemType = "VM"
		}
		else {
			$ComputerSystemType = "NonVM"
		}

		# Handle return value
		return $ComputerSystemType
	}
}
function Get-WindowsREInfo {
    $reagentcOutput = reagentc /info | findstr "\\?\GLOBALROOT\device"
    $winRELocation = $reagentcOutput.replace("Windows RE location: ", "").Trim()
    $imagePath = "$winRELocation\winre.wim"
    $imageIndex = 1
    Get-WindowsImage -imagepath $imagePath -index $imageIndex
}

#endregion functions

#region script
#region common
# ***** DO NOT EDIT IN THIS REGION *****
# Check if device is in "provisioning day" and skip inventory until next day if true
$JoinDate = Get-AzureADJoinDate
$DelayDate = $JoinDate.AddDays(1)
$CompareDate = ($Date - $DelayDate)
if ($CompareDate.TotalDays -ge 0){
	# Randomize over X minutes to spread load on Azure Function if enabled
	if ($RandomiseCollectionInt -eq $true){
		Write-Output "Randomzing execution time"
		$RandomizerSeconds = $RandomizeMinutes * 60
		$ExecuteInSeconds = (Get-Random -Maximum $RandomizerSeconds -Minimum 1)
		Start-Sleep -Seconds $ExecuteInSeconds
	}
}
else {
	Write-Output "Device recently added, inventory not to be runned before $Delaydate"
    Exit 0  
}

#Get Common data for App and Device Inventory: 
#Get Intune DeviceID and ManagedDeviceName
if (@(Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse | Where-Object { $_.PSChildName -eq 'MS DM Server' })) {
	$MSDMServerInfo = Get-ChildItem HKLM:SOFTWARE\Microsoft\Enrollments\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -eq 'MS DM Server'  }
	$ManagedDeviceInfo = Get-ItemProperty -LiteralPath "Registry::$($MSDMServerInfo)" -ErrorAction SilentlyContinue
	}
$ManagedDeviceName = $ManagedDeviceInfo.EntDeviceName
$ManagedDeviceID = $ManagedDeviceInfo.EntDMID
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

 # Retrieve variables required to build request header
 $ComputerSystemType = Get-ComputerSystemType
 $AzureADDeviceID = Get-AzureADDeviceID
 $CertificateThumbprint = Get-AzureADRegistrationCertificateThumbprint
 $Signature = New-RSACertificateSignature -Content $AzureADDeviceID -Thumbprint $CertificateThumbprint
 $PublicKeyBytesEncoded = Get-PublicKeyBytesEncodedString -Thumbprint $CertificateThumbprint

#Get Computer Info
$ComputerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
$ComputerName = $ComputerInfo.Name
$ComputerManufacturer = $ComputerInfo.Manufacturer

if ($ComputerManufacturer -match "HP|Hewlett-Packard") {
	$ComputerManufacturer = "HP"
}
#endregion common

#region DEVICEINVENTORY
if ($CollectDeviceInventory) {
	
	# Get Windows Update Service Settings
	$DefaultAUService = (New-Object -ComObject "Microsoft.Update.ServiceManager").Services | Where-Object { $_.isDefaultAUService -eq $True } | Select-Object Name
	$AUMeteredNetwork = (Get-ItemProperty -Path HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings\).AllowAutoWindowsUpdateDownloadOverMeteredNetwork 
	if ($AUMeteredNetwork -eq "0") {
		$AUMetered = "false"
	} else { $AUMetered = "true" }
	
	
	# Get Computer Inventory Information 
	$ComputerOSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
	$ComputerBiosInfo = Get-CimInstance -ClassName Win32_Bios
	$ComputerModel = $ComputerInfo.Model
	$ComputerLastBoot = $ComputerOSInfo.LastBootUpTime
	$ComputerUptime = [int](New-TimeSpan -Start $ComputerLastBoot -End $Date).Days
	$ComputerInstallDate = $ComputerOSInfo.InstallDate
	$DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
	if ([string]::IsNullOrEmpty($DisplayVersion)) {
		$ComputerWindowsVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId).ReleaseId
	} else {
		$ComputerWindowsVersion = $DisplayVersion
	}
	$ComputerOSName = $ComputerOSInfo.Caption
	$ComputerSystemSkuNumber = $ComputerInfo.SystemSKUNumber
	$ComputerSerialNr = $ComputerBiosInfo.SerialNumber
	$ComputerBiosUUID = Get-CimInstance Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID
	$ComputerBiosVersion = $ComputerBiosInfo.SMBIOSBIOSVersion
	$ComputerBiosDate = $ComputerBiosInfo.ReleaseDate
	$ComputerFirmwareType = $env:firmware_type
	$PCSystemType = $ComputerInfo.PCSystemType
		switch ($PCSystemType){
			0 {$ComputerPCSystemType = "Unspecified"}
			1 {$ComputerPCSystemType = "Desktop"}
			2 {$ComputerPCSystemType = "Laptop"}
			3 {$ComputerPCSystemType = "Workstation"}
			4 {$ComputerPCSystemType = "EnterpriseServer"}
			5 {$ComputerPCSystemType = "SOHOServer"}
			6 {$ComputerPCSystemType = "AppliancePC"}
			7 {$ComputerPCSystemType = "PerformanceServer"}
			8 {$ComputerPCSystemType = "Maximum"}
			default {$ComputerPCSystemType = "Unspecified"}
		}
	$PCSystemTypeEx = $ComputerInfo.PCSystemTypeEx
		switch ($PCSystemTypeEx){
			0 {$ComputerPCSystemTypeEx = "Unspecified"}
			1 {$ComputerPCSystemTypeEx = "Desktop"}
			2 {$ComputerPCSystemTypeEx = "Laptop"}
			3 {$ComputerPCSystemTypeEx = "Workstation"}
			4 {$ComputerPCSystemTypeEx = "EnterpriseServer"}
			5 {$ComputerPCSystemTypeEx = "SOHOServer"}
			6 {$ComputerPCSystemTypeEx = "AppliancePC"}
			7 {$ComputerPCSystemTypeEx = "PerformanceServer"}
			8 {$ComputerPCSystemTypeEx = "Slate"}
			9 {$ComputerPCSystemTypeEx = "Maximum"}
			default {$ComputerPCSystemTypeEx = "Unspecified"}
		}
		
	$ComputerPhysicalMemory = [Math]::Round(($ComputerInfo.TotalPhysicalMemory / 1GB))
	$ComputerOSBuild = $ComputerOSInfo.BuildNumber
	$ComputerOSRevision = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	$ComputerCPU = Get-CimInstance win32_processor | Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors
	$ComputerProcessorManufacturer = $ComputerCPU.Manufacturer | Get-Unique
	$ComputerProcessorName = $ComputerCPU.Name | Get-Unique
	$ComputerNumberOfCores = $ComputerCPU.NumberOfCores | Get-Unique
	$ComputerNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors | Get-Unique
	$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
	
	try {
		$TPMValues = Get-Tpm -ErrorAction SilentlyContinue | Select-Object -Property TPMReady, TPMPresent, TPMEnabled, TPMActivated, ManagedAuthLevel
	} catch {
		$TPMValues = $null
	}
	
	try {
		$ComputerTPMThumbprint = (Get-TpmEndorsementKeyInfo).AdditionalCertificates.Thumbprint
	} catch {
		$ComputerTPMThumbprint = $null
	}
	
	try {
		$BitLockerInfo = Get-BitLockerVolume -MountPoint $env:SystemDrive | Select-Object -Property *
	} catch {
		$BitLockerInfo = $null
	}
	
	# TPM Information
	$ComputerTPMVersion = Get-WmiObject -Class "Win32_Tpm" -Namespace "ROOT\CIMV2\Security\MicrosoftTpm" | Select-Object -ExpandProperty SpecVersion
	$ComputerTPMReady = $TPMValues.TPMReady
	$ComputerTPMPresent = $TPMValues.TPMPresent
	$ComputerTPMEnabled = $TPMValues.TPMEnabled
	$ComputerTPMActivated = $TPMValues.TPMActivated
	
	# BitLocker Information	
	$ComputerBitlockerCipher = $BitLockerInfo.EncryptionMethod
	$ComputerBitlockerStatus = $BitLockerInfo.VolumeStatus
	$ComputerBitlockerProtection = $BitLockerInfo.ProtectionStatus
	$ComputerDefaultAUService = $DefaultAUService.Name
	$ComputerAUMetered = $AUMetered

	# SecureBoot Information
	try {
		$ComputerSecureBootStatus = Confirm-SecureBootUEFI
	} catch {
		$ComputerSecureBootStatus = $null
	}

	# Get BIOS information
	# Determine manufacturer specific information
	switch -Wildcard ($ComputerManufacturer) {
		"*Microsoft*" {
			$ComputerManufacturer = "Microsoft"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = Get-WmiObject -Namespace root\wmi -Class MS_SystemInformation | Select-Object -ExpandProperty SystemSKU
		}
		"*HP*" {
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).BaseBoardProduct.Trim()
			
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
			
			# Detect new versus old BIOS formats
			switch -wildcard ($($CurrentBIOSProperties.SMBIOSBIOSVersion)) {
				"*ver*" {
					if ($CurrentBIOSProperties.SMBIOSBIOSVersion -match '.F.\d+$') {
						$ComputerBiosVersion = ($CurrentBIOSProperties.SMBIOSBIOSVersion -split "Ver.")[1].Trim()
					} else {
						$ComputerBiosVersion = [System.Version]::Parse(($CurrentBIOSProperties.SMBIOSBIOSVersion).TrimStart($CurrentBIOSProperties.SMBIOSBIOSVersion.Split(".")[0]).TrimStart(".").Trim().Split(" ")[0])
					}
				}
				default {
					$ComputerBiosVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
				}
			}
		}
		"*Dell*" {
			$ComputerManufacturer = "Dell"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).Trim()
			$ComputerSystemSKU = (Get-CIMInstance -ClassName MS_SystemInformation -NameSpace root\WMI).SystemSku.Trim()
			
			# Obtain current BIOS release
			$ComputerBiosVersion = (Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SMBIOSBIOSVersion).Trim()
			
		}
		"*Lenovo*" {
			$ComputerManufacturer = "Lenovo"
			$ComputerModel = (Get-WmiObject -Class Win32_ComputerSystemProduct | Select-Object -ExpandProperty Version).Trim()
			$ComputerSystemSKU = ((Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty Model).SubString(0, 4)).Trim()
			
			# Obtain current BIOS release
			$CurrentBIOSProperties = (Get-WmiObject -Class Win32_BIOS | Select-Object -Property *)
			
			# Obtain current BIOS release
			#$ComputerBiosVersion = ((Get-WmiObject -Class Win32_BIOS | Select-Object -Property *).SMBIOSBIOSVersion).SubString(0, 8)
			$ComputerBiosVersion = "$($CurrentBIOSProperties.SystemBiosMajorVersion).$($CurrentBIOSProperties.SystemBiosMinorVersion)"
		}
	}
	
	#Get network adapters
	$NetWorkArray = @()
	
	$CurrentNetAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
	$CurrentNetAdapetersIPInfo = Get-NetIPConfiguration
	
	foreach ($CurrentNetAdapter in $CurrentNetAdapters) {
		$IPConfiguration = $null
		$IPConfiguration = $CurrentNetAdapetersIPInfo | where-object { $_.InterfaceAlias -eq $CurrentNetAdapter.InterfaceAlias }
		if ($IPConfiguration -ne $null){
			$ComputerNetInterfaceDescription = $CurrentNetAdapter.InterfaceDescription
			$ComputerNetProfileName = $IPConfiguration.NetProfile.Name
			$ComputerNetIPv4Adress = $IPConfiguration.IPv4Address.IPAddress
			$ComputerNetInterfaceAlias = $CurrentNetAdapter.InterfaceAlias
			$ComputerNetIPv4DefaultGateway = $IPConfiguration.IPv4DefaultGateway.NextHop
			$ComputerNetMacAddress = $CurrentNetAdapter.MacAddress
			
			$tempnetwork = New-Object -TypeName PSObject
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceDescription" -Value "$ComputerNetInterfaceDescription" -Force
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetProfileName" -Value "$ComputerNetProfileName" -Force
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4Adress" -Value "$ComputerNetIPv4Adress" -Force
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetInterfaceAlias" -Value "$ComputerNetInterfaceAlias" -Force
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "NetIPv4DefaultGateway" -Value "$ComputerNetIPv4DefaultGateway" -Force
			$tempnetwork | Add-Member -MemberType NoteProperty -Name "MacAddress" -Value "$ComputerNetMacAddress" -Force
			$NetWorkArray += $tempnetwork
		}
	}

	[System.Collections.ArrayList]$NetWorkArrayList = $NetWorkArray
	
	# Get Disk Health
	$DiskArray = @()
	$Disks = Get-PhysicalDisk | Where-Object { $_.BusType -match "NVMe|SATA|SAS|ATAPI|RAID" }
	
	# Loop through each disk
	foreach ($Disk in ($Disks | Sort-Object DeviceID)) {
		# Obtain disk health information from current disk
		$DiskHealth = Get-PhysicalDisk -UniqueId $($Disk.UniqueId) | Get-StorageReliabilityCounter | Select-Object -Property Wear, ReadErrorsTotal, ReadErrorsUncorrected, WriteErrorsTotal, WriteErrorsUncorrected, Temperature, TemperatureMax
		
		# Obtain media type
		$DriveDetails = Get-PhysicalDisk -UniqueId $($Disk.UniqueId) | Select-Object MediaType, HealthStatus
		$DriveMediaType = $DriveDetails.MediaType
		$DriveHealthState = $DriveDetails.HealthStatus
		$DiskTempDelta = [int]$($DiskHealth.Temperature) - [int]$($DiskHealth.TemperatureMax)
		
		# Create custom PSObject
		$DiskHealthState = new-object -TypeName PSObject
		
		# Create disk entry
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk Number" -Value $Disk.DeviceID
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "FriendlyName" -Value $($Disk.FriendlyName)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "HealthStatus" -Value $DriveHealthState
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "MediaType" -Value $DriveMediaType
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk Wear" -Value $([int]($DiskHealth.Wear))
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) Read Errors" -Value $([int]($DiskHealth.ReadErrorsTotal))
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) Temperature Delta" -Value $DiskTempDelta
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) ReadErrorsUncorrected" -Value $($Disk.ReadErrorsUncorrected)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) ReadErrorsTotal" -Value $($Disk.ReadErrorsTotal)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) WriteErrorsUncorrected" -Value $($Disk.WriteErrorsUncorrected)
		$DiskHealthState | Add-Member -MemberType NoteProperty -Name "Disk $($Disk.DeviceID) WriteErrorsTotal" -Value $($Disk.WriteErrorsTotal)
		
		$DiskArray += $DiskHealthState
		[System.Collections.ArrayList]$DiskHealthArrayList = $DiskArray
	}
	
	# Get Battery information
	$BatteryArray = @()
	$BatteryPresent = [boolean](Get-CimInstance -Namespace "root\wmi" -ClassName "BatteryStatus" -ErrorAction SilentlyContinue)
		
	if ($BatteryPresent) {
		$BatteryInstances = Get-CimInstance -Namespace "root\wmi" -Class "BatteryStatus" | Select-Object -ExpandProperty "InstanceName"
		foreach ($BatteryInstance in $BatteryInstances) {
			
            $BatteryUniqueID = Get-WmiObject -ClassName "BatteryStaticData" -Namespace "root\wmi" | Where-Object { $PSItem.InstanceName -eq $BatteryInstance} | Select-Object -ExpandProperty UniqueID 
            $BatteryLocation = Get-CimInstance -ClassName "Win32_Battery" -Namespace "root\cimv2" | Where-Object {$_.DeviceID -eq $BatteryUniqueID}   | Select-Object -ExpandProperty "Name"
            $MSBatteryInfo = Get-WmiObject -Class "MSBatteryClass" -Namespace "root\wmi" | Where-Object { $PSItem.InstanceName -eq $BatteryInstance } | Select-Object "FullChargedCapacity", "DesignedCapacity", "SerialNumber", "CycleCount", "ManufactureName", "DeviceName"
			$Win32BatteryInfo = Get-CimInstance -ClassName Win32_Battery -Namespace "root\cimv2" | Where-Object {$_.DeviceID -eq $BatteryUniqueID}
            $Win32PortableBatteryInfo = Get-CimInstance -ClassName Win32_PortableBattery -Namespace "root\cimv2" | Where-Object {$_.Location -eq $BatteryLocation}
            $BatteryDesignedCapacity = [int]($MSBatteryInfo.DesignedCapacity | Where-Object { $PSItem -gt 0 })[0]
			$BatteryFullChargedCapacity = [int]($MSBatteryInfo.FullChargedCapacity | Where-Object { $PSItem -gt 0 })[0]
			$BatteryCycleCount = [int]($MSBatteryInfo.CycleCount | Where-Object { $PSItem -gt 0 })[0]
			$BatterySerialNumber = ($MSBatteryInfo.SerialNumber | Where-Object { $PSItem -ne $null })
			$BatteryCurrentMaxCapacity = [math]::Round((($BatteryFullChargedCapacity / $BatteryDesignedCapacity) * 100))
			$BatteryManufacturer = ($MSBatteryInfo.ManufactureName | Where-Object { $PSItem -ne $null })
			$BatteryDeviceName = ($MSBatteryInfo.DeviceName | Where-Object { $PSItem -ne $null })
            $BatteryName = $Win32PortableBatteryInfo.Name
            $BatteryChemistry = $Win32BatteryInfo.Chemistry
            $BatteryStatus = $Win32BatteryInfo.BatteryStatus
            $BatteryErrorCleared = $Win32BatteryInfo.ErrorCleared
            $BatteryErrorDescription = $Win32BatteryInfo.ErrorDescription           
            $BatteryLastErrorCode = $Win32BatteryInfo.LastErrorCode
			
			$tmpbattery = New-Object -TypeName PSObject
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryUniqueID" -Value $BatteryUniqueID -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryDesignedCapacity" -Value $BatteryDesignedCapacity -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryFullChargedCapacity" -Value $BatteryFullChargedCapacity -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryCycleCount" -Value $BatteryCycleCount -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatterySerialNumber" -Value $BatterySerialNumber -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryCurrentMaxCapacity" -Value $BatteryCurrentMaxCapacity -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryManufacturer" -Value $BatteryManufacturer -Force
			$tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryDeviceName" -Value $BatteryDeviceName -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryName" -Value $BatteryName -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryChemistry" -Value $BatteryChemistry -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryStatus" -Value $BatteryStatus -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryErrorCleared" -Value $BatteryErrorCleared -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryErrorDescription" -Value $BatteryErrorDescription -Force
            $tmpbattery | Add-Member -MemberType NoteProperty -Name "BatteryLastErrorCode" -Value $BatteryLastErrorCode -Force
			$BatteryArray += $tmpbattery
		}
		[System.Collections.ArrayList]$BatteryArrayList = $BatteryArray
	}
	
	# Get WinReInformation 
	$WinREInformation = Get-WindowsREInfo
	$WinReVersion = $WinREInformation.Version
	$WinReLanguage = $WinREInformation.Languages

	# Create JSON to Upload to Log Analytics
	$Inventory = New-Object System.Object
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerModel" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemType" -Value "$ComputerPCSystemType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "PCSystemTypeEx" -Value "$ComputerPCSystemTypeEx" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ComputerUpTime" -Value "$ComputerUptime" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "LastBoot" -Value "$ComputerLastBoot" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "InstallDate" -Value "$ComputerInstallDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value "$ComputerWindowsVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DefaultAUService" -Value "$ComputerDefaultAUService" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "AUMetered" -Value "$ComputerAUMetered" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SystemSkuNumber" -Value "$ComputerSystemSkuNumber" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SerialNumber" -Value "$ComputerSerialNr" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SMBIOSUUID" -Value "$ComputerBiosUUID" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosVersion" -Value "$ComputerBiosVersion" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BiosDate" -Value "$ComputerBiosDate" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SystemSKU" -Value "$ComputerSystemSKU" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "FirmwareType" -Value "$ComputerFirmwareType" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "Memory" -Value "$ComputerPhysicalMemory" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSBuild" -Value "$ComputerOSBuild" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSRevision" -Value "$ComputerOSRevision" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "OSName" -Value "$ComputerOSName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUManufacturer" -Value "$ComputerProcessorManufacturer" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUName" -Value "$ComputerProcessorName" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPUCores" -Value "$ComputerNumberOfCores" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "CPULogical" -Value "$ComputerNumberOfLogicalProcessors" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMReady" -Value "$ComputerTPMReady" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMPresent" -Value "$ComputerTPMPresent" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMEnabled" -Value "$ComputerTPMEnabled" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMActived" -Value "$ComputerTPMActivated" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMThumbprint" -Value "$ComputerTPMThumbprint" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "TPMVersion" -Value "$ComputerTPMVersion" -Force	
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerCipher" -Value "$ComputerBitlockerCipher" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerVolumeStatus" -Value "$ComputerBitlockerStatus" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BitlockerProtectionStatus" -Value "$ComputerBitlockerProtection" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "SecureBootEnabled" -Value "$ComputerSecureBootStatus" -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "NetworkAdapters" -Value $NetWorkArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "DiskHealth" -Value $DiskHealthArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BatteryPresent" -Value $BatteryPresent -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "BatteryStatus" -Value $BatteryArrayList -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WinREVersion" -Value $WinReVersion -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "WinRELanguage" -Value $WinReLanguage -Force
	$Inventory | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value $ScriptVersion -Force
		
	$DeviceInventory = $Inventory
	
}
#endregion DEVICEINVENTORY

#region APPINVENTORY
if ($CollectAppInventory) {
	#$AppLog = "AppInventory"
	
	#Get SID of current interactive users
	$CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName
	if (-not ([string]::IsNullOrEmpty($CurrentLoggedOnUser))) {
		$AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
		$strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
		$UserSid = $strSID.Value
	} else {
		$UserSid = $null
	}
	
	#Get Apps for system and current user
	$MyApps = Get-InstalledApplications -UserSid $UserSid
	$UniqueApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -eq 1 }).Group
	$DuplicatedApps = ($MyApps | Group-Object Displayname | Where-Object { $_.Count -gt 1 }).Group
	$NewestDuplicateApp = ($DuplicatedApps | Group-Object DisplayName) | ForEach-Object { $_.Group | Sort-Object [version]DisplayVersion -Descending | Select-Object -First 1 }
	$CleanAppList = $UniqueApps + $NewestDuplicateApp | Sort-Object DisplayName
	
	$AppArray = @()
	foreach ($App in $CleanAppList) {
		$tempapp = New-Object -TypeName PSObject
		$tempapp | Add-Member -MemberType NoteProperty -Name "ComputerName" -Value "$ComputerName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceName" -Value "$ManagedDeviceName" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "ManagedDeviceID" -Value "$ManagedDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppName" -Value $App.DisplayName -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppVersion" -Value $App.DisplayVersion -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppInstallDate" -Value $App.InstallDate -Force -ErrorAction SilentlyContinue
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppPublisher" -Value $App.Publisher -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallString" -Value $App.UninstallString -Force
		$tempapp | Add-Member -MemberType NoteProperty -Name "AppUninstallRegPath" -Value $app.PSPath.Split("::")[-1]
		$tempapp | Add-Member -MemberType NoteProperty -Name "ScriptVersion" -Value $ScriptVersion -Force
		$AppArray += $tempapp
	}
	
	$AppInventory = $AppArray
}
#endregion APPINVENTORY

#region CUSTOMINVENTORY *SAMPLE*
<# Here you can add in code for other logs to extend with *SAMPLE
if ($CollectCustomInventory){
	Check SAMPLE-CustomLogInventory.ps1 in Github Repo
}
#>
#endregion CUSTOMINVENTORY

#region compose
# Start composing logdata
# If additional logs is collected, remember to add to main payload 
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

# Adding every log payload into PSObject for main payload - Additional logs can be added 
$LogPayLoad = New-Object -TypeName PSObject 
if ($CollectAppInventory) {
	$LogPayLoad | Add-Member -NotePropertyMembers @{$AppLogName = $AppInventory}
}
if ($CollectDeviceInventory) {
	$LogPayLoad | Add-Member -NotePropertyMembers @{$DeviceLogName = $DeviceInventory}
}
<# *SAMPLE*
if ($CollectCustomInventory){
	$LogPayLoad | Add-Member -NotePropertyMember @{$CustomLogName = $CustomInventory}
}
#>

# Construct main payload to send to LogCollectorAPI
$MainPayLoad = [PSCustomObject]@{
	DeviceName = $ComputerName
	AzureADTenantID = $AzureADTenantID
	AzureADDeviceID = $AzureADDeviceID
	Signature = $Signature
	Thumbprint = $CertificateThumbprint
	PublicKey = $PublicKeyBytesEncoded
	LogPayloads = $LogPayLoad
}
$MainPayLoadJson = $MainPayLoad| ConvertTo-Json -Depth 9	

#endregion compose

#region ingestion 
# NO NEED TO EDIT BELOW THIS LINE 
# New in version 3.5.0 - Now it requires functionapp version 1.2 
# Set default exit code to 0 
$ExitCode = 0

# Attempt to send data to API
try {
	$ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson
    foreach ($response in $ResponseInventory){
        if ($response.response -match "200"){
        $OutputMessage = $OutPutMessage + "OK: $($response.logname) $($response.response) "
        }
        else{
        $OutputMessage = $OutPutMessage + "FAIL: $($response.logname) $($response.response) "
        $ExitCode = 1
        }
    }
} 
catch {
	$ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
	$ResponseMessage = $_.Exception.Message
    $OutputMessage = $OutPutMessage + "Inventory:FAIL " + $ResponseInventory + $ResponseMessage
    $ExitCode = 1
}
# Exit script with correct output and code

Write-Output $OutputMessage
Exit $ExitCode																							
#endregion ingestion 

#endregion script

