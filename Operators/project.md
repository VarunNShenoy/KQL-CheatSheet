# Project Operator

The `project` operator is used to select the coloumns to include, rename or drop and insert new computed columns.

The Order of the columns in the result is specified by the order of the argumnets. Only the columns specified in the arguments are included in the result. Any other columns in the input is dropped

## Syntax

```kql
TableName
| project ColumnName [= Expression] [, ...]
```

---

## Parameters

| Name        | Type   | Required | Description                                                   |
|-------------|--------|----------|---------------------------------------------------------------|
| T           | string | Yes      | The tabular input for which to project certain columns.        |
| ColumnName  | string | No       | A column name or comma-separated list of column names to appear in the output. |
| Expression  | string | No       | The scalar expression to perform over the input.              |

### Conditions 

1. Either ColumnName or Expression must be specified 
2. if there's no expression, then a column of ColumnName must appear in the input
3. if ColumnName is omitted, the output column name of Expression will be qutomatically generated.
4. if Expression returns more than one column, a list of column names can be specified in paratheses. If a list of the column names isn't specified, all Expression's output columns with generated names wil be added to the output 

---

## Basic Example

```kql
SigninLogs
| project UserPrincipalName, IPAddress, AppDisplayName, DeviceDetail
```

### Output

Returns the following columns from the SigninLogs Table. Returned columns are UserPrincipalName, IPAddress, Location, DeviceDetail

---

## Common Use Cases

### Filter Successful Logins and display UPN, App Display Name, Location, SignInTime which is Time Generated.

```kql
SigninLogs
| where ResultType == 0   // 0 usually indicates success
| project UserPrincipalName, AppDisplayName, Location = tostring(LocationDetails), SignInTime = TimeGenerated
```

### Filter Successful Logins from an specific app

```kql
SigninLogs
| where ResultType == 0 and AppDisplayName == "Office 365 Exchange Online"
| project UserPrincipalName, Location = tostring(LocationDetails), SignInTime
| order by SignInTime desc
```
---

## Performance Tips

- ✔ Project only the columns you need
- ✔ Rename columns for clarity and readability
- ✔ Create derived columns inline to avoid extra steps
- ✔ Apply project before expensive operations like join or summarize
- ✔ Reorder columns to highlight the most important fields
- ✘ Avoid projecting unused or redundant columns
- ✘ Avoid carrying forward large datasets without trimming with project
---

## Real-World Threat Hunting Examples

### Brute Force/Password Spraying

```kql
SigninLogs
| where ResultType != 0   // failed sign-ins
| summarize FailedAttempts = count() by UserPrincipalName, AppDisplayName
| where FailedAttempts > 10
| order by FailedAttempts desc
```

### Rare sign in locations

```kql
SigninLogs
| where ResultType == 0
| summarize Locations = make_set(LocationDetails) by UserPrincipalName
| where array_length(Locations) > 3
```

### Suspicious Device Sign-ins

```kql
SigninLogs
| where ResultType == 0
| where isempty(DeviceDetail.DeviceId) or DeviceDetail.IsCompliant == false
| project UserPrincipalName, AppDisplayName, Location = tostring(LocationDetails), SignInTime = TimeGenerated
```

### Failed -> Successful Login Patterns

```kql
SigninLogs
| summarize FailedCount = countif(ResultType != 0), SuccessCount = countif(ResultType == 0) by UserPrincipalName
| where FailedCount > 5 and SuccessCount > 0
```

### Suspicious Process Execution (Defender for Endpoint)

```kql
DeviceProcessEvents
| where FileName in ("mimikatz.exe", "procdump.exe")
| project DeviceName, InitiatingProcessAccountName, FileName, TimeGenerated
```

## Microsoft Documentation

https://learn.microsoft.com/en-us/kusto/query/project-operator?view=microsoft-fabric