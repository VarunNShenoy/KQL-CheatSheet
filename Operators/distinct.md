# Distinct Operator

The `distinct` Operator produces a table with the distinct combination of the provided columns of the input table.

## Syntax

```kql
Table Name
| distinct ColumnName [, ColumnName2, ...]
```

## Parameters 

| Name | Type  | Required | Description |
| ColumnName | String | yes | The colummn name to search for distinct values |

---

### Note 

The distinct operator supports providing an asterisk * as the group key to denote all columns, which is helpful for wide tables.

## Basic Examples

```kql
SigninLogs
| where IPAddress == "IP_Address"
| where ResultType == 0
| distinct UserPrincipalName
```

### Output

Returns unique users who have signed in from an specific IP Address.

---

## Common use cases 

### Unique parent-child process pairs

```kql
DeviceProcessEvents
| distinct InitiatingProcessParentFileName, ProcessName
```

### Unique Failure Reasons

```kql
SigninLogs
| where ResultType != 0
| distinct ResultDescription
```

### Distinct External IP's per user

```kql
DeviceLogonEvents
| where RemoteIPType == "Public"
| distinct AccountName, RemoteIP
```
---

## Performance Tips

- √ Use `distinct` for quick de‑duplication when you only need unique values
- √ Apply `where` filters first to reduce dataset size before distinct
- √ Project only the necessary columns before distinct
- √ Combine `distinct` with `summarize dcount()` when you need counts of unique values
- √ Use `distinct` for exploration/baselining, then switch to summarize for analytics
- ✗ Avoid running distinct on very high‑cardinality fields (like raw command lines) without filtering
- ✗ Avoid distinct on huge datasets without a time filter (e.g., always use `TimeGenerated > ago(7d)`)
- ✗ Avoid carrying unused columns into distinct
- ✗ Avoid chaining multiple distinct steps — one well‑placed distinct is enough

---

## Real World Threat Hunting Examples


### Password spray using DeviceLogonEvents --> grouped by accounts

```kql
DeviceLogonEvents
| where TimeGenerated > ago (24h)
| where ActionType == "LogonFailed"
| summarize FailedCount = count(), DistinctDevices = dcount(DeviceName) by AccountName //count() → counts total rows for each account & dcount(DeviceName) → counts unique device names per account.
| DistinctDevices > 10
| sort by DistinctDevices desc
```

### Multiple Failed Logon's from the same Device (BruteForce)

```kql
DeviceLogonEvents
| where TimeGenerated > ago (24h)
| where ActionType == "LogonFailed"
| summarize FailedAttempts = count() by DeviceName, AccountName
| where FailedAttempts > 20
| sort by FailedAttempts desc
```
---

## Microsoft Documentation

https://learn.microsoft.com/en-us/power-platform/power-fx/reference/function-distinct

