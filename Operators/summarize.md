# Summarize Operator

The `Summarize` operator produces a table that aggregrates the content of the inmput table 

## Syntax

```kql
TableName
 summarize [ SummarizeParameters ] [[Column =] Aggregation [, ...]] [by [Column =] GroupExpression [, ...]]
```
---

## Parameters

| Name              | Type   | Required | Description                                                                 |
|-------------------|--------|----------|-----------------------------------------------------------------------------|
| Column            | string |          | The name for the result column. Defaults to a name derived from the expression. |
| Aggregation       | string | ✔        | A call to an aggregation function such as `count()` or `avg()`, with column names as arguments. |
| GroupExpression   | scalar | ✔        | A scalar expression that can reference the input data. The output has as many records as there are distinct values of all the group expressions. |
| SummarizeParameters | string |          | Zero or more space‑separated parameters in the form of `Name = Value` that control the behavior. See supported parameters. |

---

## Default vlaues of aggregations

| Operator                                                                                                      | Default value              |
|---------------------------------------------------------------------------------------------------------------|----------------------------|
| count(), countif(), dcount(), dcountif(), count_distinct(), sum(), sumif(), variance(), varianceif(), stdev(), stdevif() | 0                          |
| make_bag(), make_bag_if(), make_list(), make_list_if(), make_set(), make_set_if()                             | empty dynamic array ([])   |
| All others                                                                                                    | null                       |


## Basic Example

```kql
SigninLogs
| where ResultType == 0                     // successful sign-ins
| where IPAddress == "<IP_Address>"         // filter by specific IP
| summarize Count = count() by UserPrincipalName
| order by Count desc
```

### Output

Returns only successful sign-in from an specific IP.

---

## Common Use Cases

### Failed Login Attempts

```kql
SigninLogs
| where ResultType == "50126" or ResultType == "50053"
| summarize Count = count() by UserPrincipalName, bin(TimeGenerated, 1h)
| order by Count desc
```

### Suspicious IP Address

```kql
SigninLogs
| where IPAddress has_any ("192.168.1.1", "10.0.0.1")
| summarize Count = count() by IPAddress, bin(TimeGenerated, 1h)
| order by Count desc
```

### Unusual Login Locations

```kql
SigninLogs
| where Location not in ("US", "UK")
| summarize Count = count() by Location, bin(TimeGenerated, 1h)
| order by Count desc
```

### Data Exfiltration

```kql
NetworkSession
| where BytesSent > 1000000
| summarize Count = count() by SourceIP, bin(TimeGenerated, 1h)
| order by Count desc
```
---

## Performance Tips

- √ Filter early with `where` before summarize to reduce dataset size
- √ Use `bin(TimeGenerated, 1h)` or similar to group time efficiently
- √ Project only necessary columns before summarize
- √ Apply summarize only on relevant fields (avoid wide grouping)
- √ Use specific aggregation functions (`count()`, `avg()`, `sum()`) instead of generic scans
- √ Materialize subqueries if reused multiple times
- √ Order results after summarize, not before
- ✗ Avoid summarizing without a time filter (can scan huge datasets)
- ✗ Avoid grouping by high‑cardinality fields (e.g., full command line)
- ✗ Avoid carrying unused columns into summarize
- ✗ Avoid chaining multiple summarize steps when one can achieve the result

---

## Real-World Threat Hunting Examples

### Users signing in from Multiple IP's

```kql
SigninLogs
| summarize UniqueIPs = dcount(IPAddress) by UserPrincipalName
| where UniqueIPs > 5
| sort by UniqueIPs desc
```

### Password Spray Detection

```kql
SigninLogs
| where ResultType != 0
| summarize UniqueUsers = dcount(UserPrincipalName) by IPAddress
| where UniqueUsers > 10
| sort by UniqueUsers desc
```

### Rare Parent-child Process Relationship

```kql
DeviceProcessEvents
| where DeviceName == "X"
| summarize ExecutionCount = count()
    by InitiatingProcessFileName, FileName
| where ExecutionCount < 5
```

---

## Microsoft Documentation

https://learn.microsoft.com/en-us/kusto/query/summarize-operator?view=microsoft-fabric