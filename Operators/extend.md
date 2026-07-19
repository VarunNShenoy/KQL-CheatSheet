# Extendclea Operator

The `extend` Operator creates calculated columns and append them to the result set.

## Syntax

```kql
TableName
| extend [ColumnName | (ColumnName[, ...]) =] Expression [, ...]
```

---

## Parameters

| Name        | Type   | Required | Description                                                   |
|-------------|--------|----------|---------------------------------------------------------------|
| T           | string | Yes      | The tabular input to extend.        |
| ColumnName  | string | No       | name of the Column to add or update |
| Expression  | string | No       | Calculation to perform over the input              |

### Conditions 

1. if ColumnName is omitted, the output column name of Expression is automatically generated.
2. if the Expression retuns more than one column, a list of column names can be specified in the parentheses.Then, Expression's output columns is given the specified names. If a list of the column names isn't specified, all Expression's output columns with generated names are added to the output.

---

## Basic Example

```kql
SigninLogs
| extend
    IsSuccess = (ResultType == 0),
    FailureReason = ResultDescription,
    DeviceRegistered = isnotempty(DeviceDetail.deviceId)
| project
    UserPrincipalName,
    AppDisplayName,
    IsSuccess,
    FailureReason,
    DeviceRegistered
```

### Output

Creates new columns named IsSuccess which returns either True or False, FailureReason containing ResultDescription and DeviceRegistered with the device id. It projects all these columns along with UPN and AppDisplayName
---

## Common Use Cases

### Hunting for Download/Exfil Commands

```kql
DeviceProcessEvents
| extend SuspiciousCommand = iff(
    ProcessCommandLine has_any ("curl", "wget", "Invoke-WebRequest", "certutil", "bitsadmin"),
    "Yes", "No")
| where SuspiciousCommand == "Yes"
| project TimeGenerated, DeviceName, InitiatingProcessParentFileName, ProcessCommandLine, SuspiciousCommand
| order by Timestamp desc
```

### Detect Persistance Attempts

```kql
DeviceProcessEvents
| extend PersistenceAttempt = iff(
    ProcessCommandLine has_any ("schtasks","reg add","reg import"),
    "Yes","No")
| where PersistenceAttempt == "Yes"
| project TimeGenerated, DeviceName, ProcessCommandLine, PersistenceAttempt
```
---

## Performance Tips

- √ Use extend to add calculated columns inline
- √ Keep derived columns simple (avoid heavy functions in extend)
- √ Apply extend before summarize or join if the new column is needed downstream
- √ Use extend for flags (Yes/No) to simplify filtering
- √ Combine multiple conditions in a single extend to reduce steps
- ✗ Avoid creating unused extended columns
- ✗ Avoid chaining too many extend statements when one can do the job
- ✗ Avoid extending with expensive regex or parsing unless necessary
- ✗ Avoid extending columns that duplicate existing fields

---

## Real-World Threat Hunting Examples

### Hunting for Download/Exfil Commands

```kql
DeviceProcessEvents
| extend SuspiciousDownload = iff(
    ProcessCommandLine has_any ("curl","wget","Invoke-WebRequest","certutil","bitsadmin","scp","ftp"),
    "Yes","No")
| where SuspiciousDownload == "Yes"
| project TimeGenerated, DeviceName, ProcessCommandLine, SuspiciousDownload
```

### Determine wheather a Device is registered

```kql
SigninLogs
| extend DeviceRegistered = isnotempty(DeviceDetail.deviceId)
| summarize Count=count() by DeviceRegistered
```
---

## Microsoft Documentation

https://learn.microsoft.com/en-us/kusto/query/extend-operator?view=microsoft-fabric