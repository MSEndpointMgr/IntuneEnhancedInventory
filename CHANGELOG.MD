# Changelog for Intune Enhanced Inventory Solution 

## Changelog for Log Collector API Azure Function

### 1.2 
* Requires Proactive Remeditaion Script version 3.5
* Changed response logic in the function. Instead of returning a concated string, the function now returns a payload containing logname and status for each log as a separate entry. This makes it much easier to validate each log ingestion separated if you have many logs in the same PR Script. Fixes issues with the PR reporting wrongly. 
* Function now checks if the log you are sending is not empty. If the log is empty the function will not try to send data to Log Analytics and will return status 200 with a message about log empty. This fixes that the PR returns and error if you are collection for instance specific eventlog entries and the last 24 hours contains zero entries. 

### 1.1 
* Requires Proactive Remediation Script version 2.0 - up to and including version 3.0.x 
* Removed hardcoding for collecting only DeviceInventory or ApplicationInventory. The Azure Function can now handle any log as long as the data is sendt using the correct formatting. 

## Changelog for Inventory Collection Proactive remediation
2.0 - (2021 - 08 - 29) Moved secrets out of code - now running via Azure Function
2.0.1 (2021-09-01) Removed all location information for privacy reasons 
2.1 - (2021-09-08) Added section to cater for BIOS release version information, for HP, Dell and Lenovo and general bugfixes
2.1.1 - (2021-21-10) Added MACAddress to the inventory for each NIC. 
3.0.0 - (2022-22-02) Azure Function updated - Requires version 1.1 of Azure Function LogCollectorAPI for more dynamic log collecting
3.0.1 - (2022-15-09) Updated to support CloudPC (Different method to find AzureAD DeviceID for verification) 
3.5.0 - (2022-14-10) Azure Function updated - Requires version 1.2 Updated output logic to be more dynamic. Fixed a bug in the randomizer function and disabled inventory collection during provisioning day.
