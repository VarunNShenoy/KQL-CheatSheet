# Suspicious Defence Evasion 

## Objective 

Investigate potential defense evasion techniques to determine whether suspicious activity represents legitimate administrative behavior or malicious attempts to bypass security controls by analyzing process execution, security tool tampering, log clearing, obfuscated commands, disabling of defensive mechanisms, registry modifications, and other suspicious activity patterns.

## Table Used 

DeviceProcessEvents
DeviceFileEvents
DeviceEvents

## Investigation Querries 

### Powershell Execution with Suspicious Arguments 

```kql
DeviceProcessEvents 
| where DeviceName == "Device_Name" 
| where TimeGenerated > ago(7d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any (
"-enc", "-encodedcommand",
    "-windowstyle hidden",
    "-executionpolicy bypass",
    "-nop", "-noprofile",
    "DownloadString",
    "Invoke-Expression",
    "IEX",
    "FromBase64String"
)
| project Timestamp, DeviceName, AccountName,
          FileName, ProcessCommandLine,
          InitiatingProcessFileName,
          InitiatingProcessCommandLine,
          ProcessId, InitiatingProcessId
| order by Timestamp desc
```

##### Note: This query may generate a high volume of results, including legitimate administrative activity such as Intune-managed PowerShell executions. Further refine the filtering criteria based on the initial results and validate the execution context to distinguish legitimate administrative activity from potentially malicious behavior. 

#### What to look for 

- Encoded commands: Identify Base64-encoded PowerShell commands.
- Hidden execution: Look for PowerShell running with hidden windows.
- Execution policy bypass: Check for attempts to bypass PowerShell restrictions.
- Download activity: Identify scripts downloaded from external URLs.
- Command obfuscation: Look for IEX, Invoke-Expression, and FromBase64String.
- Parent process: Check whether PowerShell was launched by unusual applications.
- User context: Identify unexpected user or privileged account execution.
- Legitimate activity: Validate Intune, SCCM, and approved administrative scripts.
- Suspicious patterns: Investigate unusual command execution and repeated activity.





