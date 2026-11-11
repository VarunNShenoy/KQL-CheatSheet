# MFA Fatigue Investigation

## Overview

MFA Fatigue is an attack technique in which an attacker repeatedly triggers Multi-Factor Authentication (MFA) push notifications in an attempt to make a legitimate user approve a fraudulent authentication request.

## Table Used/Data Source

- SigninLogs

## Key investigation objectives:

- Identify repeated MFA failures.
- Detect excessive authentication attempts.
- Identify suspicious source IP addresses.
- Investigate MFA denials and timeouts.
- Correlate failed MFA attempts with subsequent successful sign-ins.

## Check for Failed MFA Authentication Attempts

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "500121"
| project TimeGenerated,
          UserPrincipalName,
          IPAddress,
          Location,
          AppDisplayName,
          ResultType,
          ResultDescription
| order by TimeGenerated desc
```

### What to look for

- Identify users with repeated failures
- Check whether failures originate from the same IP.
- Review the failure descriptions
- Determine whether the user subsequently authenticated successfully.

#### Note: Result code 500121 is not proof of MFA fatigue. It can represent different strong-authentication failures.

## Detect Repeated MFA Failures from the Same IP

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == "500121"
| summarize FailedAttempts = count(),
            Applications = make_set(AppDisplayName)
            FailureReasons = make_set(ResultDescription)
   by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 5
```

### What to look for 

- Look for five or more failures within 15 minutes.
- Identify whether the same IP repeatedly targets a user.
- Review whether multiple applications are involved.
