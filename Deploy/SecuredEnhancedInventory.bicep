// Define parameters
@description('Provide a name for the Function App that consists of alphanumerics. Name must be globally unique in Azure and cannot start or end with a hyphen.')
param FunctionAppName string
@allowed([
  'Y1'
  'EP1'
  'EP2'
  'EP3'
])

@description('Select the desired App Service Plan of the Function App. Select Y1 for free consumption based deployment.')
param FunctionAppServicePlanSKU string = 'Y1'

@minLength(3)
@maxLength(24)
@description('Provide a name for the Key Vault. Name must be globally unique in Azure and between 3-24 characters, containing only 0-9, a-z, A-Z, and - characters.')
param KeyVaultName string

//@description('Location for all resources.')
//param location string = resourceGroup().location

@description('Provide the name of the existing Log Analytics workspace that has your Intune Diagnostics/Inventory logs.')
param LogAnalyticsWorkspaceName string

@description('Provide the name of the resource group for your excisting Intune Log Analytics Workspace')
param LogAnalyticsResourceGroup string

@description('Provide the Subscription ID for the Azure Subscription that contains your excisting Intune Log Analytics Workspace')
param LogAnalyticsSubcriptionID string

@description('Provide any tags required by your organization (optional)')
param Tags object = {}

// Define variables
var UniqueString = uniqueString(resourceGroup().id)
var FunctionAppNameNoDash = replace(FunctionAppName, '-', '')
var FunctionAppNameNoDashUnderScore = replace(FunctionAppNameNoDash, '_', '')
var StorageAccountName = toLower('${take(FunctionAppNameNoDashUnderScore, 17)}${take(UniqueString, 5)}sa')
var FunctionAppServicePlanName = '${FunctionAppName}-fa-plan'
var FunctionAppInsightsName = '${FunctionAppName}-fa-ai'

 

// Reference excisting Log Analytics Workspace
resource LogAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2020-10-01' existing = {
  name: LogAnalyticsWorkspaceName
  scope: resourceGroup(LogAnalyticsSubcriptionID,LogAnalyticsResourceGroup)
}

// Appending variables for secrets 
var WorkSpaceIDSecret = LogAnalyticsWorkspace.properties.customerId
var SharedKeySecret = LogAnalyticsWorkspace.listKeys().primarySharedKey

// Create storage account for Function App
resource storageaccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: StorageAccountName
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties:{
    supportsHttpsTrafficOnly: true
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    allowSharedKeyAccess: true
  }
  tags: Tags
}

// Create app service plan for Function App
resource appserviceplan 'Microsoft.Web/serverfarms@2021-01-15' = {
  name: FunctionAppServicePlanName
  location: resourceGroup().location
  kind: 'Windows'
  properties: {}
  sku: {
    name: FunctionAppServicePlanSKU
  }
  tags: Tags
}

// Create application insights for Function App
resource FunctionAppInsightsComponents 'Microsoft.Insights/components@2020-02-02' = {
  name: FunctionAppInsightsName
  location: resourceGroup().location
  kind: 'web'
  properties: {
    Application_Type: 'web'
  }
  tags: union(Tags, 
    {
    'hidden-link:${resourceId('Microsoft.Web/sites', FunctionAppInsightsName)}': 'Resource'
  })
}

// Create function app
resource FunctionApp 'Microsoft.Web/sites@2020-12-01' = {
  name: FunctionAppName
  location: resourceGroup().location
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appserviceplan.id
    containerSize: 1536
    httpsOnly: true
    siteConfig: {
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      powerShellVersion: '~7'
      scmType: 'None'
      use32BitWorkerProcess: false
      appSettings: [
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower('LogAnalyticsAPI')
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
        {
          name: 'AzureWebJobsDisableHomepage'
          value: 'true'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_PROCESS_COUNT'
          value: '4'
        }
        {
          name: 'PSWorkerInProcConcurrencyUpperBound'
          value: '10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02').InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: reference(FunctionAppInsightsComponents.id, '2020-02-02').ConnectionString
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'powershell'
        }
      ]
    }
  }
  tags: Tags
}

// Create Key Vault
resource KeyVault 'Microsoft.KeyVault/vaults@2019-09-01' = {
  name: KeyVaultName
  location: resourceGroup().location
  properties: {
    enabledForDeployment: false
    enabledForTemplateDeployment: false
    enabledForDiskEncryption: false
    tenantId: subscription().tenantId
    accessPolicies: [
      {
        tenantId: FunctionApp.identity.tenantId
        objectId: FunctionApp.identity.principalId
        permissions: {
          secrets: [
            'get'
            'list'
          ]
        }
      }
    ]
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
  resource WorkspaceID 'secrets' = {
    name: 'WorkSpaceID'
    properties: {
    value: WorkSpaceIDSecret
    }
  }
  resource SharedKey 'secrets' = {
    name: 'SharedKey'
    properties: {
      value: SharedKeySecret
    }
  }
}

// Add ZipDeploy for Function App
resource FunctionAppZipDeploy 'Microsoft.Web/sites/extensions@2015-08-01' = {
  parent: FunctionApp
  name: 'ZipDeploy'
  properties: {
      packageUri: 'https://github.com/MSEndpointMgr/IntuneEnhancedInventory/releases/download/v1.2/LogCollectorAPI.zip'
  }
}

resource FunctionAppSettings 'Microsoft.Web/sites/config@2020-06-01' = {
  name: '${FunctionApp.name}/appsettings'
  properties: {
    AzureWebJobsStorage: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
    WEBSITE_CONTENTAZUREFILECONNECTIONSTRING: 'DefaultEndpointsProtocol=https;AccountName=${storageaccount.name};AccountKey=${storageaccount.listKeys().keys[0].value}'
    WEBSITE_CONTENTSHARE: toLower('LogAnalyticsAPI')
    WEBSITE_RUN_FROM_PACKAGE: 1
    AzureWebJobsDisableHomepage: 'true'
    FUNCTIONS_EXTENSION_VERSION: '~4'
    FUNCTIONS_WORKER_PROCESS_COUNT: '4'
    FUNCTIONS_WORKER_RUNTIME: 'powershell'
    PSWorkerInProcConcurrencyUpperBound: '10'
    APPINSIGHTS_INSTRUMENTATIONKEY: reference(FunctionAppInsightsComponents.id, '2020-02-02').InstrumentationKey
    APPLICATIONINSIGHTS_CONNECTION_STRING: reference(FunctionAppInsightsComponents.id, '2020-02-02').ConnectionString
    TenantID: subscription().tenantId
    WorkspaceID: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=WorkSpaceID)'
    SharedKey: '@Microsoft.KeyVault(VaultName=${KeyVaultName};SecretName=SharedKey)'
    AllowedLogNames: '"AppInventory",  "DeviceInventory", "SampleInventory"'
    LogControl: 'false'
  }
  dependsOn: [
    FunctionAppZipDeploy
  ]
}

output functionAppTriggerUrl string = 'https://${FunctionApp.properties.defaultHostName}/api/LogCollectorAPI'
