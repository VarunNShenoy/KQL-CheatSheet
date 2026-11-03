# Process Investigation

## Objective

Investigate suspicious process execution on an endpoint by identifying the process, user, command line, parent process, and execution context and determine whether the activity is legitimate or potentially malicious.

## Table Used

DeviceProcessEvents
DeviceNetworkEvents

## Investigation Steps

- Identify the suspicious process.
- Identify the user who executed this process.
- Review the command line used.
- Identify the parent/initiating process.
- Determine the process execution timeline.
- Check whether the process spawned other suspicious process.
- Check the Network Connections made by this process.
- Review related file activity.
- If malicious activity is confirmed, investigate the user's and device's subsequent activity.

## Investigation Quries

### Investigate process execution Detials

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where InitiatingProcessFileName =~ "<SUSPICIOUS_PROCESS>"
    or FileName =~ "<SUSPICIOUS_PROCESS>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>) // END_TIME can be 30 mins from START_TIME
)
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

#### What to look for

- AccountName — Which user executed the process?
- ProcessCommandLine — Were suspicious arguments or commands used?
- InitiatingProcessFileName — What process launched it?
- InitiatingProcessCommandLine — How was it launched?
- InitiatingProcessParentFileName — What was higher in the process chain?
- Was the process executed from an unusual location?
- Does the parent-child relationship make sense?

### Identify the Child Process 

This is useful when you've already identified a suspicious process and want to determine whether it spawned additional processes.

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>) // END_TIME can be 30 mins from START_TIME
)
| where InitiatingProcessId == <SUSPICIOUS_PROCESS_ID>
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessId
| order by Timestamp asc
```

#### What to look for

- Unexpected child processes.
- PowerShell spawning cmd.exe, rundll32.exe, mshta.exe, etc.
- Office applications spawning scripting interpreters.
- Browsers spawning unusual executables.
- Security tools or system processes spawning unexpected programs.
- Commands that perform discovery, download files, modify accounts, or establish persistence.

### Review Process Command line

```kql
DeviceProcessEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "<SUSPICIOUS_PROCESS>"
    or FileName =~ "<SUSPICIOUS_PROCESS>"
| project
    Timestamp,
    DeviceName,
    AccountName,
    FileName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessId
| order by Timestamp asc
```

#### What to look out for

- Encoded or obfuscated commands.
- PowerShell download, execution, or remote-content commands.
- Commands that modify security settings or Defender configuration.
- Credential, account, or system discovery commands.
- Scripts or executables launched from unusual locations.
- Suspicious or unusual command-line arguments.
- A suspicious or unexpected parent process launching the command.
- Commands executed under an unexpected user account.
- Commands that establish persistence or modify system configuration.
- Commands that initiate suspicious network activity or connect to external resources.

#### NOTE

- Identify the suspicious process and any processes it directly initiated.
- If the results show a process such as powershell.exe being launched by the suspicious process, note its ProcessId.
- Pivot on that ProcessId within the same investigation timeframe to identify processes subsequently launched by PowerShell.
- Continue following the process chain where necessary to establish the complete execution sequence.

### Review Network Activity From a Suspicious Process

```kql
DeviceNetworkEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "<SUSPICIOUS_PROCESS>"
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
- Connections to known malicious or suspicious infrastructure.
- Unusual destination ports.
- A process communicating shortly after execution.
- Connections to multiple external destinations.
- Unexpected network activity from processes that normally shouldn't communicate externally.
- HTTP/HTTPS connections associated with suspicious command execution.
- Network activity occurring immediately after a suspicious process was launched.

### Identify file activity associated with a suspicious process

```kql
DeviceFileEvents
| where DeviceName == "<DEVICE_NAME>"
| where Timestamp between (
    datetime(<START_TIME>) .. datetime(<END_TIME>)
)
| where InitiatingProcessFileName =~ "<SUSPICIOUS_PROCESS>"
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

- Files created or modified by the suspicious process.
- Executables, scripts, or DLLs written to disk.
- Files created in unusual directories such as temporary or user-writable locations.
- Suspicious file extensions.
- Files with a SHA256 hash that can be investigated further.
- The process creating a file and subsequently executing it.
- File activity occurring immediately before or after suspicious network activity.

#### Note

Keep the same <START_TIME> / <END_TIME> window you used for the process investigation so your pivots stay within the same incident timeline.

if confirmed that the file is malicious, then we can pivot to check file persistance within the environment.

## Identify other devices with the same file hash

```kql
DeviceFileEvents
| where SHA256 == "<SUSPICIOUS_SHA256>"
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    AccountName
| order by Timestamp asc
```

#### What to look for

- Whether the same hash appeared on multiple devices.
- Whether the file was created, modified, or executed.
- Different file paths associated with the same hash.
- Different users interacting with the file.
- Whether the file appeared on other devices before or after the original incident.
- Whether the same suspicious process was responsible for creating or executing it.



