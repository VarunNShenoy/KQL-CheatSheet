# where Operator

The `where` operator n Kusto Query Language (KQL) is used to filter rows from a table or dataset based on a specified predicate (condition), returning only those rows where the expression evaluates to true.

## Syntax

```kql
TableName
| where Condition
```

---

## Parameters

| Parameter | Description |
|-----------|-------------|
| condition | Expression that evaluates to true or false |

-----

## Basic Example

```kql
SigninLogs
| where Resulttype == 0
```

### Output

Returns only successful sign-in events 

---

## Common use Cases

### Filter Successful Logins

```kql
SigninLogs
| where ResultType == 0
```

### Filter Failed Logins

```kql
SigninLogs
| where ResultType != 0
```

### Filter Specific User

```kql
SigninLogs
| where UserPrincipalName == "user@contoso.com"
```

### Filter Specific IP

```kql
SigninLogs
| where IPAddress == "8.8.8.8"
```

### Multiple Conditions

```kql
SigninLogs
| where ResultType == 0
| where Country == "India"
```

or

```kql
SigninLogs
| where ResultType == 0 and Country == "India"
```

---

## Performance Tips

✅ Filter as early as possible in the query.
❌ Avoid filtering after expensive operations.

## Real-World Threat Hunting Examples

### Failed Login Attempts

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts=count()
    by UserPrincipalName
```

### Sign-ins from a Specific Country

```kql
SigninLogs
| where Location contains "Russia"
```

### Suspicious IP Activity

```kql
SigninLogs
| where IPAddress == "185.220.101.1"
```
---

## Microsoft Documentation

https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/where-operator