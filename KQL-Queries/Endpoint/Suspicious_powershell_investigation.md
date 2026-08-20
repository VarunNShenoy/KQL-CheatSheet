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