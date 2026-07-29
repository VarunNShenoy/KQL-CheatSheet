# Password Spray 

## Objective 

Detect IP Address attempting to authneticate to multiple user accounts with failed sign-in's within the short period. Password spraying is commonly used to compromise accounts. Password spraying is a "low-and-slow" brute force attack where threat actors attempt to access multiple user accounts using a small set of common or default passwords (e.g., "Password123!", "Welcome1") rather than targeting a single account with many guesses.

## Table User 

- SigninLogs

## KQL

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count(),
            TargetedUsers = dcount(UserPrincipalName)  by IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 20
| where TargetedUsers >= 10
| order by FailedAttempts desc
```

## Investigation Steps

- Check