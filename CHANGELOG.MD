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

### 3.5.0 - Requires Azure Function version 1.2 
* Updated output logic in correspondace with new Azure Function returning a payload object instead of string. 
* Fixed a bug in the randomizer function, use the spread the load on the Azure Function over X minutes for larger environment.
* Adding 2 variables
* * Turn on / off randomizer function 
* * Set the timespan to randomize over 
* * Disabled inventory collection during provisioning day.

### 3.0.1 - Requires Azure Function version 1.1 
* Added support for CloudPC (Different method to find AzureAD DeviceID for verification) 

### 3.0.0 -  Requires Azure Function version 1.1 
* Added options to more easily add different custom logs and inventory by creating 1 main payload to be sent to Azure Function
* Added sample PR to show how to ingest your own custom data. 
* Generic bugfixes 

### 2.x - Requires Azure function 1.0 
* Added MACAddress to the inventory for each NIC. 
* Added section to cater for BIOS release version information, for HP, Dell and Lenovo and general bugfixes
* Removed all location gathering for privacy reasons 
* Moved secrets out of code - now running via Azure Function

