using namespace System.Net
# Input bindings are passed in via param block.
param($Request, $TriggerMetadata)
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
Function Send-LogAnalyticsData() {
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
       [string]$customerId
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
   $signature = 'SharedKey {0}:{1}' -f $customerId, $encodedHash
   
   #Construct uri 
   $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
   
   #validate that payload data does not exceed limits
   if ($body.Length -gt (31.9 *1024*1024))
   {
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
   $statusmessage = "$($response.StatusCode) : $($payloadsize)"
   return $statusmessage 
}#end function
#endregion functions

#Deployed 01-14-2022

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK

# Retrieve authentication token
$Script:AuthToken = Get-AuthToken

# Assigning and getting variables needed for matching. 
# Get secrets from Keyvault
$CustomerId = $env:WorkspaceID
$SharedKey  = $env:SharedKey
# Get TenantID from my logged on MSI account for verification 
$TenantID = $env:TenantID
# Assign inbound parameters to variables for matching
$InboundDeviceID = $Request.Body.AzureADDeviceID
$InboundTenantID = $Request.Body.AzureADTenantID

# Query graph for device verification 
$DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
$DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value
# Assign to variables for matching 
$DeviceID = $DeviceIDResponse.deviceId  
$DeviceEnabled = $DeviceIDResponse.accountEnabled

$AppLogName = $Request.Body.AppLogName
$DeviceLogName = $Request.Body.DeviceLogName
#Required empty variable for posting to Log Analytics
$TimeStampField = ""

# Write to the Azure Functions log stream.
Write-Information "PowerShell HTTP trigger function processed a request."
Write-Information "Inbound DeviceID $($Request.Body.AzureADDeviceID)"
Write-Information "Inbound TenantID $($Request.Body.AzureADTenantID)"
Write-Information "My TenantID $TenantID"
Write-Information "DeviceID $DeviceID"
Write-Information "DeviceEnabled: $DeviceEnabled"
Write-Information "Logtypes received $($AppLogName), $($DeviceLogName)"

if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"
    if($DeviceID -eq $InboundDeviceID){
        Write-Information "request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "requesting device is not disabled in Azure AD"                       
            #Write-Information "Ingesting $($LogType) to Log Analytics"
                       
            # Verify valid logtype before continuing
            if (-not ([string]::IsNullOrEmpty($AppLogName))){
                # Prepare logdata from request payload
                $Json = $Request.Body.AppPayload | ConvertTo-Json
                $LogBody = ([System.Text.Encoding]::UTF8.GetBytes($Json))
                # Sending logdata to Log Analytics
                $AppResponseLogInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body $LogBody -logType $AppLogName
                Write-Information "$($AppLogName) Logs sent to LA $($AppResponseLogInventory)"
                $AppResponse = "App:$AppResponseLogInventory,"
                $StatusCode = [HttpStatusCode]::OK
            }
            if (-not ([string]::IsNullOrEmpty($DeviceLogName))){
                # Prepare logdata from request payload
                $Json = $Request.Body.DevicePayload | ConvertTo-Json
                $LogBody = ([System.Text.Encoding]::UTF8.GetBytes($Json))
                # Sending logdata to Log Analytics
                $DeviceResponseLogInventory = Send-LogAnalyticsData -customerId $customerId -sharedKey $sharedKey -body $LogBody -logType $DeviceLogName
                Write-Information "$($DeviceLogName) Logs sent to LA $($DeviceResponseLogInventory)"
                $DeviceResponse = "Device:$DeviceResponseLogInventory,"
                $StatusCode = [HttpStatusCode]::OK
            }
            $Body = $AppResponse + $DeviceResponse    

        }else{
            Write-Warning"Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
        }
    }else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
    }
}else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
}

# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})

