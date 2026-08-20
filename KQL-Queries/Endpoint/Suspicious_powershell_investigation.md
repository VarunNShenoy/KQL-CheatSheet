# Suspicious Powershell Investigation

## Objective 

Investigate PowerShell execution to determine whether the activity is legitimate administrative activity or potentially malicious by analyzing command-line arguments, parent-child relationships, network activity, persistence mechanisms, and other suspicious execution patterns.

## Table Used

DeviceProcessEvents
DeviceNetworkEvents
DeviceFileEvents
DeviceEvents

## Investigation Steps

- Identify the PowerShell process and the user account that executed it.
- Review the PowerShell command line and identify suspicious or obfuscated arguments.
- Identify the parent/initiating process and determine why PowerShell was launched.
- Review child processes spawned by PowerShell.
- Check for file creation, modification, or execution associated with PowerShell.
- Review network connections initiated by PowerShell.
- Determine whether PowerShell modified security controls or system configuration.
- Check for persistence mechanisms established through PowerShell.
- Correlate the activity with other endpoint, identity, and security events.
- Determine whether the activity is consistent with legitimate administrative activity or potentially malicious behavior.
- If malicious activity is confirmed, investigate subsequent activity on the affected device and user account.

## Investigation Queries

### Identify PowerShell execution details

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where FileName =~ "powershell.exe"
    or FileName =~ "pwsh.exe"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId
| order by Timestamp asc
```

#### What to look for

- PowerShell launched by an unusual or suspicious parent process such as EncodedCommand or other obfuscation, ExecutionPolicy Bypass.
- Download or remote-content activity.
- Scripts executed from unusual locations.
- PowerShell spawning cmd.exe, rundll32.exe, mshta.exe, or other suspicious processes.
- Commands that modify Defender or other security settings.
- PowerShell executed under an unexpected account.

### Identify Encoded or Obfuscated PowerShell

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where FileName =~ "powershell.exe"
    or FileName =~ "pwsh.exe"
| where ProcessCommandLine has_any (
    "-EncodedCommand",
    "-enc",
    "FromBase64String",
    "IEX",
    "Invoke-Expression"
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessId,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId
| order by Timestamp asc
```

#### What to look out for 

-EncodedCommand / -enc usage.
-Base64 decoding such as FromBase64String.
-IEX / Invoke-Expression.
-Long or heavily obfuscated command lines.
-Obfuscated URLs, domains, or file paths.
-PowerShell launched by an unusual parent process.
-Encoded commands combined with download or execution activity.

### Identify Network Connections Initiated by Powershell.exe

```kql
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "powershell.exe"
    or InitiatingProcessFileName =~ "pwsh.exe"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    ActionType
| order by Timestamp asc
```

#### What to look for

- Connections to unexpected external IP addresses or domains.
- PowerShell connecting to external resources shortly after execution.
- Connections to suspicious or previously unseen destinations.
- Unusual destination ports.
- Multiple external destinations contacted by the same PowerShell process.
- Network activity associated with download or remote execution commands.
- Whether the destination is consistent with the user's or organization's normal activity.

#### Note: 

If you identify a suspicious connection, pivot using RemoteIP, RemoteUrl, InitiatingProcess and Correlate it with DeviceProceeEvents, DeviceNetworkEvents


### Identify Files Created or Modified by PowerShell

```kql
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "powershell.exe"
    or InitiatingProcessFileName =~ "pwsh.exe"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    AccountName
| order by Timestamp asc
```

#### What to look for

- Executables or scripts created shortly after PowerShell execution.
- Files written to unusual locations such as temporary or user-writable directories.
- .ps1, .bat, .cmd, .vbs, .js, .dll, or executable files created by PowerShell.
- Files with suspicious or randomized names.
- Files associated with known malicious hashes.
- PowerShell creating a file and subsequently executing it.
- File creation followed by network activity.
- Files written into locations commonly associated with persistence.
- Unexpected file modifications under system or security-related directories.

### Identify Child process spawned by PowerShell

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "powershell.exe"
 or InitiatingProcessFileName =~ "pwsh.exe"
| project 
  TimeStamp, 
  DeviceName,
  AccountName,
  FileName,
  ProcessId,
  ProcessCommandLine,
  InitiatingProcessFileName,
  InitiatingProcessCommandLine,
  InitiatingProcessId
| order by Timestamp asc
```

#### What to look for
- PowerShell spawning cmd.exe.
- PowerShell spawning rundll32.exe, regsvr32.exe, mshta.exe, or other LOLBins.
- PowerShell launching executable files from unusual directories.
- PowerShell spawning scripting interpreters such as wscript.exe or cscript.exe.
- PowerShell launching discovery commands such as whoami, ipconfig, net, or systeminfo.
- PowerShell spawning processes that establish persistence or modify security settings.
- Child processes executing shortly after an encoded or obfuscated PowerShell command.
- Unexpected child processes that are inconsistent with the user's administrative activity.


### Powershell Security Control Modification

```kql
DeviceEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where AdditionalFields has_any (
    "Defender",
    "Antivirus",
    "DisableRealtimeMonitoring",
    "ExclusionPath",
    "ExclusionProcess",
    "ExclusionExtension"
)
    or ProcessCommandLine has_any (
        "Set-MpPreference",
        "Add-MpPreference",
        "Remove-MpPreference",
        "DisableRealtimeMonitoring",
        "ExclusionPath",
        "ExclusionProcess",
        "ExclusionExtension"
    )
| project
    Timestamp,
    DeviceName,
    ActionType,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp asc
```

#### What to look for

Pay particular attention to PowerShell commands involving:

- Set-MpPreference
- Add-MpPreference
- Remove-MpPreference
- DisableRealtimeMonitoring
- ExclusionPath
- ExclusionProcess
- ExclusionExtension
- Changes to Defender scanning or protection settings
- Security exclusions pointing to suspicious directories
- Changes performed by an unexpected user
- Changes immediately following encoded/obfuscated PowerShell
- Security-control changes followed by file creation or network activity


### Persistance set using Powershell

```kql
DeviceEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "powershell.exe"
    or InitiatingProcessFileName =~ "pwsh.exe"
| where ActionType has_any (
    "RegistryValueSet",
    "ScheduledTaskCreated",
    "ServiceInstalled",
    "FileCreated"
)
| project
    Timestamp,
    DeviceName,
    ActionType,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    RegistryKey,
    RegistryValueName,
    RegistryValueData,
    AdditionalFields
| order by Timestamp asc
```

#### What to look for

- PowerShell creating or modifying Run/RunOnce registry entries.
- Scheduled tasks created immediately after PowerShell execution.
- New services created through PowerShell.
- Executables or scripts placed in Startup directories.
- Persistence pointing to unusual user-writable locations such as %TEMP% or %APPDATA%.
- Registry values containing PowerShell commands or encoded commands.
- Persistence mechanisms referencing .ps1, .vbs, .js, .dll, or suspicious executables.
- Persistence established shortly after suspicious PowerShell or Defender-modification activity.
- Persistence created by an unexpected user or process.

#### Note

Don't classify a scheduled task or registry modification as malicious by itself. Context, command line, account, timing, target path, and subsequent execution are what make the finding suspicious.


### Attempt to build powershell Execution Timeline

```kql
union
(
    DeviceProcessEvents
    | where DeviceName == "<DEVICE_NAME>"
    | where Timestamp between (
        datetime(<START_TIME>) .. datetime(<END_TIME>)
    )
    | where FileName =~ "powershell.exe"
        or FileName =~ "pwsh.exe"
        or InitiatingProcessFileName =~ "powershell.exe"
        or InitiatingProcessFileName =~ "pwsh.exe"
    | project
        Timestamp,
        DeviceName,
        EventType = "Process",
        ActionType,
        AccountName,
        FileName,
        ProcessId,
        ProcessCommandLine,
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessId,
        RemoteIP = "",
        RemoteUrl = "",
        RemotePort = int(null),
        FolderPath = ""
),
(
    DeviceFileEvents
    | where DeviceName == "<DEVICE_NAME>"
    | where Timestamp between (
        datetime(<START_TIME>) .. datetime(<END_TIME>)
    )
    | where InitiatingProcessFileName =~ "powershell.exe"
        or InitiatingProcessFileName =~ "pwsh.exe"
    | project
        Timestamp,
        DeviceName,
        EventType = "File",
        ActionType,
        AccountName,
        FileName,
        ProcessId = int(null),
        ProcessCommandLine = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessId,
        RemoteIP = "",
        RemoteUrl = "",
        RemotePort = int(null),
        FolderPath
),
(
    DeviceNetworkEvents
    | where DeviceName == "<DEVICE_NAME>"
    | where Timestamp between (
        datetime(<START_TIME>) .. datetime(<END_TIME>)
    )
    | where InitiatingProcessFileName =~ "powershell.exe"
        or InitiatingProcessFileName =~ "pwsh.exe"
    | project
        Timestamp,
        DeviceName,
        EventType = "Network",
        ActionType,
        AccountName = "",
        FileName = "",
        ProcessId = int(null),
        ProcessCommandLine = "",
        InitiatingProcessFileName,
        InitiatingProcessCommandLine,
        InitiatingProcessId,
        RemoteIP,
        RemoteUrl,
        RemotePort,
        FolderPath = ""
)
| order by Timestamp asc
```

###### Need to verify yet

After getting all these determine whether the PowerShell activity is legitimate administrative activity or potentially malicious.


Determine whether the observed PowerShell activity is:

- Legitimate administrative activity
- Suspicious but inconclusive
- Confirmed malicious

Support the conclusion using:

- Command line
- User/account
- Parent process
- Child processes
- File activity
- Network activity
- Security-control changes
- Persistence
- Related endpoint/identity events