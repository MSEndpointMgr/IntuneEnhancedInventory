// Define parameters
@description('Provide the name of the existing Function App that was given when Intune enchanced inventory was initially deployed.')
param FunctionAppName string
@description('Provide the name of the existing Key Vault that was created when Intune enchanced inventory was initially deployed.')
param KeyVaultName string
@description('Provide the name of the existing Storage Account that was automatically given Intune enchanced inventory was initially deployed.')
param StorageAccountName string

// Automatically define variables based on param input
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'

// Define existing resources based on param input
// Define existing resources based on param input
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' existing = { 
  name: FunctionAppName
}
resource KeyVault 'Microsoft.KeyVault/vaults@2019-09-01' existing = {
  name: KeyVaultName
}
resource StorageAccount 'Microsoft.Storage/storageAccounts@2021-06-01' existing = {
  name: StorageAccountName
}
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02-preview' existing = {
  name: FunctionAppInsightsName
}

var KeyVaultRealName = KeyVault.name

resource FunctionAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${FunctionApp.name}/appsettings'
  properties: {
    AllowedLogNames: '"AppInventory",  "DeviceInventory", "SampleInventory"'
    APPINSIGHTS_INSTRUMENTATIONKEY: reference(FunctionAppInsightsComponents.id, '2020-02-02').InstrumentationKey
    APPLICATIONINSIGHTS_CONNECTION_STRING: reference(FunctionAppInsightsComponents.id, '2020-02-02').ConnectionString
    AzureWebJobsDisableHomepage: 'true'
    AzureWebJobsStorage: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
    FUNCTIONS_EXTENSION_VERSION: '~4'
    FUNCTIONS_WORKER_PROCESS_COUNT: '4'
    FUNCTIONS_WORKER_RUNTIME: 'powershell'
    LogControl: 'false'
    PSWorkerInProcConcurrencyUpperBound: '10'
    SharedKey: '@Microsoft.KeyVault(VaultName=${KeyVaultRealName};SecretName=SharedKey)'
    TenantID: subscription().tenantId
    WEBSITE_CONTENTAZUREFILECONNECTIONSTRING: 'DefaultEndpointsProtocol=https;AccountName=${StorageAccount.name};AccountKey=${StorageAccount.listKeys().keys[0].value}'
    WEBSITE_CONTENTSHARE: toLower('LogAnalyticsAPI')
    WEBSITE_RUN_FROM_PACKAGE: 1    
    WorkspaceID: '@Microsoft.KeyVault(VaultName=${KeyVaultRealName};SecretName=WorkSpaceID)' 
  }
  dependsOn: [
    FunctionAppZipDeploy
  ]
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/IntuneEnhancedInventory/releases/download/v1.2/LogCollectorAPI.zip'
  }
}

output functionAppTriggerUrl string = 'https://${FunctionApp.properties.defaultHostName}/api/LogCollectorAPI'
