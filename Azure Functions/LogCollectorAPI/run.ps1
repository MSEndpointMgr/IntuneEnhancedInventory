# Intune Enhanced Inventory 
# Version 1.2 
# Created and maintained by @JankeSkanke 
# Requires minimum version  3.5.0 of the Enhanced Inventory Proactive Remediations Script
# Updated 14.Oct.2022

using namespace System.Net
# Input bindings are passed in via param block.
param($Request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#region functions
function Get-AuthToken {
    <#
    .SYNOPSIS
        Retrieve an access token for the Managed System Identity.
    
    .DESCRIPTION
        Retrieve an access token for the Managed System Identity.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }
        # Handle return value
        return $AuthenticationHeader
    }
}#end function 
function Send-LogAnalyticsData() {
    <#
   .SYNOPSIS
       Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .DESCRIPTION
       Send log data to Azure Monitor by using the HTTP Data Collector API
   
   .NOTES
       Author:      Jan Ketil Skanke
       Contact:     @JankeSkanke
       Created:     2022-01-14
       Updated:     2022-01-14
   
       Version history:
       1.0.0 - (2022-01-14) Function created
   #>
   param(
       [string]$sharedKey,
       [array]$body, 
       [string]$logType,
       [string]$CustomerId
   )
   #Defining method and datatypes
   $method = "POST"
   $contentType = "application/json"
   $resource = "/api/logs"
   $date = [DateTime]::UtcNow.ToString("r")
   $contentLength = $body.Length
   #Construct authorization signature
   $xHeaders = "x-ms-date:" + $date
   $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
   $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
   $keyBytes = [Convert]::FromBase64String($sharedKey)
   $sha256 = New-Object System.Security.Cryptography.HMACSHA256
   $sha256.Key = $keyBytes
   $calculatedHash = $sha256.ComputeHash($bytesToHash)
   $encodedHash = [Convert]::ToBase64String($calculatedHash)
   $signature = 'SharedKey {0}:{1}' -f $CustomerId, $encodedHash
   
   #Construct uri 
   $uri = "https://" + $CustomerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
   
   #validate that payload data does not exceed limits
   if ($body.Length -gt (31.9 *1024*1024)){
       throw("Upload payload is too big and exceed the 32Mb limit for a single upload. Please reduce the payload size. Current payload size is: " + ($body.Length/1024/1024).ToString("#.#") + "Mb")
   }
   $payloadsize = ("Upload payload size is " + ($body.Length/1024).ToString("#.#") + "Kb ")
   
   #Create authorization Header
   $headers = @{
       "Authorization"        = $signature;
       "Log-Type"             = $logType;
       "x-ms-date"            = $date;
       "time-generated-field" = $TimeStampField;
   }
   #Sending data to log analytics
   $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
   $statusmessage = "$($response.StatusCode):$($payloadsize)"
   return $statusmessage 
}#end function
#endregion functions

Write-Information "LogCollectorAPI function received a request."
#region initialize

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK

# Define variables from environment
$LogControll = $env:LogControl
# Get secrets from Keyvault
$CustomerId = $env:WorkspaceID
$SharedKey  = $env:SharedKey

# Get TenantID from my logged on MSI account for verification 
$TenantID = $env:TenantID

# Extracting and processing inbound parameters to variables for matching
$MainPayLoad = $Request.Body.LogPayloads
$InboundDeviceID= $Request.Body.AzureADDeviceID
$InboundTenantID = $Request.Body.AzureADTenantID

$LogsReceived = New-Object -TypeName System.Collections.ArrayList
foreach ($Key in $MainPayLoad.Keys) {
    $LogsReceived.Add($($Key)) | Out-Null
}
Write-Information "Logs Received $($LogsReceived)"

#Required empty variable for posting to Log Analytics
$TimeStampField = ""

#endregion initialize

#region script
# Write to the Azure Functions log stream.
Write-Information "Inbound DeviceID $($InboundDeviceID)"
Write-Information "Inbound TenantID $($InboundTenantID)"
Write-Information "Environment TenantID $TenantID"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Verify request comes from correct tenant
if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"
    # Retrieve authentication token
    $Script:AuthToken = Get-AuthToken

    # Query graph for device verification 
    $DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
    $DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

    # Assign to variables for matching 
    $DeviceID = $DeviceIDResponse.deviceId  
    $DeviceEnabled = $DeviceIDResponse.accountEnabled    
    Write-Information "DeviceID $DeviceID"   
    Write-Information "DeviceEnabled: $DeviceEnabled"
    # Verify request comes from a valid device
    if($DeviceID -eq $InboundDeviceID){
        Write-Information "Request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "Requesting device is not disabled in Azure AD"                       
            foreach ($LogName in $LogsReceived){
                Write-Information "Processing $($LogName)"
                # Check if Log type control is enabled
                if ($LogControll -eq "true"){
                # Verify log name applicability
                Write-Information "Log name control is enabled, verifying log name against allowed values"
                [Array]$AllowedLogNames = $env:AllowedLogNames
                Write-Information "Allowed log names: $($AllowedLogNames)"
                $LogCheck = $AllowedLogNames -match $LogName
                    if(-not ([string]::IsNullOrEmpty($LogCheck))){
                        Write-Host "Log $LogName Allowed"
                        [bool]$LogState = $true
                    }
                    else {
                        Write-Warning "Logname $LogName not allowed"
                        [bool]$LogState = $false
                    }       
                }
                else{
                    Write-Information "Log control is not enabled, continue"
                    [bool]$LogState = $true
                }
                if ($LogState){
                    $Json = $MainPayLoad.$LogName | ConvertTo-Json
                    $LogSize = $json.Length
                    # Verify if log has data before sending to Log Analytics
                    if ($LogSize -gt 0){
                        Write-Information "Log $($logname) has content. Size is $($json.Length)"
                        $LogBody = ([System.Text.Encoding]::UTF8.GetBytes($Json))
                        # Sending logdata to Log Analytics
                        $ResponseLogInventory = Send-LogAnalyticsData -customerId $CustomerId -sharedKey $SharedKey -body $LogBody -logType $LogName
                        Write-Information "$($LogName) Logs sent to LA $($ResponseLogInventory)"
                        $PSObject = [PSCustomObject]@{
                            LogName = $LogName
                            Response = $ResponseLogInventory
                        }
                        $ResponseArray.Add($PSObject) | Out-Null
                        $StatusCode = [HttpStatusCode]::OK
                    }
                    else {
                        # Log is empty - return status 200 but with info about empty log
                        Write-Information "Log $($logname) has no content. Size is $($json.Length)"
                        $PSObject = [PSCustomObject]@{
                            LogName = $LogName
                            Response = "200:Log does not contain data"
                        }
                        $ResponseArray.Add($PSObject) | Out-Null
                    }
                }
                else {
                    Write-Warning "Log $($LogName) is not allowed"
                    $StatusCode = [HttpStatusCode]::OK
                    $PSObject = [PSCustomObject]@{
                        LogName = $LogName
                        Response = "Logtype is not allowed"
                    }
                    $ResponseArray.Add($PSObject) | Out-Null                   
                }
            }
        }
        else{
            Write-Warning "Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
        }
    }
    else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
    }
}
else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
}
#endregion script
$body = $ResponseArray | ConvertTo-Json 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
