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

### Microsoft Defender Tampering (T1562.001)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("Set-MpPreference", "Add-MpPreference")
| where ProcessCommandLine has_any (
    "DisableRealtimeMonitoring", "DisableBehaviorMonitoring",
    "DisableIOAVProtection", "DisableScriptScanning",
    "ExclusionPath", "ExclusionExtension", "ExclusionProcess")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "TamperingAttempt"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
```

#### What to look out for

- Exclusions added for temp, user-writable or download paths
- Real-time or behavior monitoring turned off
- Tampering attempts blocked by Tamper Protection (high-fidelity signal)
- Changes made by non-admin tooling, or outside change windows

### Stopping or Disabling Security Services (T1562.001)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("sc.exe", "net.exe", "net1.exe", "taskkill.exe", "powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("WinDefend", "Sense", "MsMpEng", "wscsvc",
        "SecurityHealthService", "EventLog", "Sysmon", "WdFilter", "MDCoreSvc")
| where ProcessCommandLine has_any ("stop", "delete", "disabled", "Stop-Service", "Set-Service", "/f")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### What to look for

- sc config <svc> start= disabled or sc stop against EDR, AV or logging service
- taskkill /f against security agent processes

### Log Clearing and Audit Policy Changes (T1070.001, T1562.002)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "wevtutil.exe" and ProcessCommandLine has_any ("cl", "clear-log"))
    or ProcessCommandLine has_any ("Clear-EventLog", "Remove-EventLog", "ClearEventLog")
    or (FileName =~ "fsutil.exe" and ProcessCommandLine has_all ("usn", "deletejournal"))
    or (FileName =~ "auditpol.exe" and ProcessCommandLine has_any ("/clear", "/remove", "disable"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "SecurityLogCleared"
| project Timestamp, DeviceName, InitiatingProcessAccountName,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

What to look for

- Security, System or PowerShell logs cleared
- USN journal deletion
- Audit categories disabled with auditpol
- Log clearing shortly before or after other suspicious activity on the same host

### Weakening Security Controls via Registry (T1562.001, T1112)

```kql
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
| where RegistryKey has_any (
    @"Microsoft\Windows Defender",
    @"Policies\Microsoft\Windows Defender",
    @"CurrentVersion\Policies\System",
    @"Control\SecurityProviders\WDigest",
    @"PowerShell\ScriptBlockLogging",
    @"PowerShell\ModuleLogging")
| where RegistryValueName in~ ("DisableAntiSpyware", "DisableRealtimeMonitoring",
        "DisableBehaviorMonitoring", "TamperProtection", "EnableLUA",
        "ConsentPromptBehaviorAdmin", "LocalAccountTokenFilterPolicy",
        "UseLogonCredential", "EnableScriptBlockLogging", "EnableModuleLogging")
    or RegistryKey has "Exclusions"
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey,
          RegistryValueName, RegistryValueData, InitiatingProcessFileName,
          InitiatingProcessCommandLine
| order by Timestamp desc
```
#### What to look for

- Defender disabled or exclusions added
- UAC weakened (EnableLUA=0)
- WDigest cleartext credential caching enabled (UseLogonCredential=1)
- PowerShell logging disabled
- Changes made by something other than Group Policy or Intune

### Obfuscated Files or Information (T1027)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (
    "powershell.exe", "pwsh.exe",
    "cmd.exe", "wscript.exe", "cscript.exe"
)
| where ProcessCommandLine matches regex
    @"(?i)(\^|`|\bxor\b|%[a-z0-9_]+%)"
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc
```

##### Note: This query may generate a high volume of results, including legitimate administrative activity such as Intune-managed PowerShell executions. Further refine the filtering criteria based on the initial results and validate the execution context to distinguish legitimate administrative activity from potentially malicious behavior. 

### Clear Command History

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any (
    "Clear-History",
    "ConsoleHost_history.txt",
    "PSReadLine"
)
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

#### What to look for

- Look for events attempting to clear powershell command history.

### Disable Windows Event Logging (T1562.002)

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where
    (FileName =~ "wevtutil.exe"
     and ProcessCommandLine has "sl")
    or
    (FileName =~ "auditpol.exe"
     and ProcessCommandLine has_any (
        "/clear",
        "/remove",
        "/success:disable",
        "/failure:disable"
     ))
| project Timestamp, DeviceName, AccountName,
    FileName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```







