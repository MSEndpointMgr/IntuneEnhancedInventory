<#
.SYNOPSIS
Sample to explain how to call the collector API with your own logdata. The azure function now supports dynamically "any" log data as long as the API call is formatted correctly. 

.DESCRIPTION
Sample to explain how to call the collector API with your own logdata. The azure function now supports dynamically "any" log data as long as the API call is formatted correctly. 

.EXAMPLE
Invoke-CustomLogAzureFunction.ps1 

.NOTES
FileName:    Invoke-CustomLogAzureFunction.ps1 
Author:      Jan Ketil Skanke
Contact:     @JankeSkanke
Created:     2022-22-02
Updated:     2022-22-02

Version history:
1.0.0 - (2022-22-02) Azure Function updated - Requires version 1.1 of Azure Function LogCollectorAPI - 
#>

#region initialize
# Define your azure function URL: 
# Example 'https://<appname>.azurewebsites.net/api/<functioname>'

$AzureFunctionURL = ""

# Enable TLS 1.2 support 
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#Control if you want to collect App or Device Inventory or both (True = Collect)

#Set your Log Analytics Log Name
$CustomLog1Name = "MyLog1"
$CustomLog2Name = "MyLog2"
$Date=(Get-Date)
#endregion initialize

#region functions (All functions in here are requried for sample to work)
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
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
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
    #>
	Process {
		# Define Cloud Domain Join information registry path
		$AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
		# Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
		$AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
		if ($AzureADJoinInfoThumbprint -ne $null) {
			# Retrieve the machine certificate based on thumbprint from registry key
			$AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
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
#endregion functions

#region script
#Get Common data for validation in Azure Function: 
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID

#region CustomLogData1

#Gather some data 

$MyLog1Data1 = "TestData"
$MyLog1Data2 = "TestData"
$MyLog1Data3 = "TestData"
$MyLog1Data4 = "TestData"

# Create Object to Upload to Log Analytics
$Inventory = New-Object System.Object
$Inventory | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
$Inventory | Add-Member -MemberType NoteProperty -Name "MyLog1Data1" -Value "$MyLog1Data1" -Force
$Inventory | Add-Member -MemberType NoteProperty -Name "MyLog1Data2" -Value "$MyLog1Data2" -Force
$Inventory | Add-Member -MemberType NoteProperty -Name "MyLog1Data3" -Value "$MyLog1Data3" -Force
$Inventory | Add-Member -MemberType NoteProperty -Name "MyLog1Data4" -Value "$MyLog1Data4" -Force
$MyLog1DataInventory = $Inventory
	
#endregion CustomLogData1

#region CustomLogData2
	
# Data Arrays are also supported 

$MyArray = "Query an array of data"


$MyArray = @()
foreach ($Item in $MyArray) {
	$tempData = New-Object -TypeName PSObject
	$tempData | Add-Member -MemberType NoteProperty -Name "AzureADDeviceID" -Value "$AzureADDeviceID" -Force
	$tempData | Add-Member -MemberType NoteProperty -Name "MyLog2Data1" -Value $Item.MyLog2Data1 -Force
	$tempData | Add-Member -MemberType NoteProperty -Name "MyLog2Data2" -Value $Item.MyLog2Data2 -Force
	$tempData | Add-Member -MemberType NoteProperty -Name "MyLog2Data3" -Value $Item.MyLog2Data3 -Force 
	$tempData | Add-Member -MemberType NoteProperty -Name "MyLog2Data4" -Value $Item.MyLog2Data4 -Force
	$DataArray += $tempData
}

$MyLog2DataInventory = $DataArray

#endregion CustomLogData2

#Randomize over 50 minutes to spread load on Azure Function - disabled on date of enrollment (Disabled in sample - Enable only in larger environments)
$JoinDate = Get-AzureADJoinDate
$DelayDate = $JoinDate.AddDays(1)
$CompareDate = ($DelayDate - $JoinDate)
if ($CompareDate.Days -ge 1){
	Write-Output "Randomzing execution time"
	#$ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
	#Start-Sleep -Seconds $ExecuteInSeconds
}
#Start sending logs
$date = Get-Date -Format "dd-MM HH:mm"
$OutputMessage = "InventoryDate:$date "

$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

# Add arrays of logs into payload array 
$LogPayLoad = New-Object -TypeName PSObject 
$LogPayLoad | Add-Member -NotePropertyMembers @{$CustomLog1Name= $MyLog1DataInventory}
$LogPayLoad | Add-Member -NotePropertyMembers @{$CustomLog2Name = $MyLog2DataInventory}

# Construct main payload to send to LogCollectorAPI // IMPORTANT // KEEP AND DO NOT CHANGE THIS
$MainPayLoad = [PSCustomObject]@{
	AzureADTenantID = $AzureADTenantID
	AzureADDeviceID = $AzureADDeviceID
	LogPayloads = $LogPayLoad
}
$MainPayLoadJson = $MainPayLoad| ConvertTo-Json -Depth 9	

# Sending data to API
try {
	$ResponseInventory = Invoke-RestMethod $AzureFunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson
	$OutputMessage = $OutPutMessage + "Inventory:OK " + $ResponseInventory
} 
catch {
	$ResponseInventory = "Error Code: $($_.Exception.Response.StatusCode.value__)"
	$ResponseMessage = $_.Exception.Message
	$OutputMessage = $OutPutMessage + "Inventory:Fail " + $ResponseInventory + $ResponseMessage
}

# Check status and report to Proactive Remediations
if ($ResponseInventory-match "200"){
	Write-Output $OutputMessage
	Exit 0
} else {
	Write-Output "Error: $($ResponseInventory), Message: $($ResponseMessage)"
	Exit 1
	}
#endregion script
