# IntuneEnhancedInventory
Repository for the Intune Custom Inventory solution by MSEndpointmgr.com

## Option 1 
Use the simple proactive remediation that sends data direct to Log Analytics Workspace with secrets in code. 
[Read the blogpost: https://msendpointmgr.com/2021/04/12/enhance-intune-inventory-data-with-proactive-remediations-and-log-analytics/](https://msendpointmgr.com/2021/04/12/enhance-intune-inventory-data-with-proactive-remediations-and-log-analytics/)

## Option 2 
Use the new and updated proactive remediation that sends data through a Azure Function App to keep secret out of code and secure that only approved and known clients can send data to your log workspace. 

1. Deploy Azure Function using our template.  
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FMSEndpointMgr%2FIntuneEnhancedInventory%2Fmain%2FDeploy%2FSecuredEnhancedInventory.json) 
3. Set API Permissions for MSI to graph with Add-MSIGraphPermissions.ps1 
4. Deploy the Invoke-CustomInventoryAzureFunction.ps1 Proactive remediation after you added your Azure Function URL to the script. 

[Read the blogpost: https://msendpointmgr.com/2022/01/17/securing-intune-enhanced-inventory-with-azure-function/ ](https://msendpointmgr.com/2022/01/17/securing-intune-enhanced-inventory-with-azure-function/)

