# Persistence related Querries

## Objective

### Registry Run Keys (T1547.001)

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has_any (
    @"\Software\Microsoft\Windows\CurrentVersion\Run",
    @"\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    @"\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
)
| project Timestamp,
          DeviceName,
          RegistryKey,
          RegistryValueName,
          RegistryValueData,
          InitiatingProcessFileName,
          AccountName
| order by Timestamp desc
```
#### What to look for

- Suspicious registry entries: Newly created or modified Run/RunOnce values containing unexpected executable or script paths.
- Unusual file locations: Registry values pointing to executables or scripts in Temp, AppData, Downloads, or other user-writable directories.
- Suspicious command execution: Registry values containing PowerShell, cmd.exe, wscript.exe, mshta.exe, or encoded commands.
- Unexpected initiating processes: Registry modifications performed by unusual applications, scripting interpreters, or unexpected user accounts.
- Persistence execution: Verify whether the registry entry executes during user logon or startup and whether it launches suspicious processes or establishes additional persistence.


### Startup Folder Execution (T1547.001)

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath contains @"\Microsoft\Windows\Start Menu\Programs\Startup"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where
    FileName endswith ".exe"
    or FileName endswith ".dll"
    or FileName endswith ".bat"
    or FileName endswith ".cmd"
    or FileName endswith ".vbs"
    or FileName endswith ".vbe"
    or FileName endswith ".js"
    or FileName endswith ".jse"
    or FileName endswith ".ps1"
    or FileName endswith ".hta"
    or FileName endswith ".lnk"
    or FileName endswith ".wsf"
    or FileName endswith ".scr"
| where not(InitiatingProcessFileName in~ (
    "trustedinstaller.exe",
    "intunemanagementextension.exe",
    "ccmexec.exe"
))
| project
    Timestamp,
    DeviceName,
    ActionType,
    FileName,
    FolderPath,
    SHA256,
    AccountName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessParentFileName
| order by Timestamp desc
```

#### Note: This query may generate results involving legitimate software installations, application updates, and approved endpoint management activities. Further refine the results based on your organization's environment by validating known software publishers, file hashes, installation paths, initiating processes, and approved deployment tools. Avoid blanket exclusions, as legitimate Windows processes can also be abused to establish persistence.

#### What to look for

- Suspicious file types: Unexpected .exe, .dll, .ps1, .vbs, .bat, or .lnk files in Startup folders.
- Unusual file locations: Startup entries referencing executables or scripts stored in Temp, AppData, Downloads, or other user-writable directories.
- Suspicious initiating processes: Startup files created by PowerShell, cmd.exe, wscript.exe, cscript.exe, or unexpected applications.
- Unexpected modifications: Existing Startup files modified, renamed, or replaced outside approved software installation or update activity.
- Persistence execution: Verify whether newly created Startup entries execute during user logon and whether they launch suspicious processes or establish further persistence.

### Scheduled Task Creation (T1053.005)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has_any (
    "/create",
    "-create"
)
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName
```

#### Note: This query may generate results involving legitimate software installations, application updates, and approved endpoint management activities. Further refine the results based on your organization's environment by validating known software publishers, file hashes, installation paths, initiating processes, and approved deployment tools. Avoid blanket exclusions, as legitimate Windows processes can also be abused to establish persistence.

#### What to look for 

- Suspicious task creation: Newly created scheduled tasks with unusual names, misleading names, or names resembling legitimate Windows tasks.
- Unusual execution paths: Tasks configured to execute scripts or binaries from Temp, AppData, Downloads, or other user-writable directories.
- Suspicious command execution: Task commands containing PowerShell, cmd.exe, wscript.exe, mshta.exe, encoded commands, or unexpected script arguments.
- Unexpected initiating processes: Scheduled tasks created by unusual applications, scripting interpreters, or unexpected user accounts.
- Persistence behavior: Tasks configured to execute at user logon, system startup, or recurring intervals, particularly when they launch suspicious executables or scripts.

### Windows Service Creation (T1543.003)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "sc.exe"
| where ProcessCommandLine has "create"
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine,
          InitiatingProcessFileName
```

#### What to look for 

- Suspicious service creation: Newly created services with unusual names, misleading names, or names resembling legitimate Windows services.
- Unusual executable paths: Services configured to execute binaries or scripts from Temp, AppData, Downloads, or other user-writable directories.
- Suspicious service commands: Review binPath values for PowerShell, cmd.exe, encoded commands, script interpreters, or unexpected executable arguments.
- Unexpected initiating processes: Service creation performed by PowerShell, cmd.exe, unknown executables, or unexpected user accounts.
- Persistence and execution: Investigate service startup configuration, especially automatic startup, privileged service accounts, and services executing suspicious binaries.

### Persistent Local User Creation

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "net user",
    "New-LocalUser"
)
| project Timestamp,
          DeviceName,
          AccountName,
          ProcessCommandLine
```





