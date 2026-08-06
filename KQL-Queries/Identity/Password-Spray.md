# Password Spray 

## Objective 

Investigate a suspected password spray attack by identifying the targeted accounts, validating whether any authentication attempts were successful, assessing the affected devices and applications, and determining whether the activity resulted in account compromise.
 
 Password spraying is commonly used to compromise accounts. Password spraying is a "low-and-slow" brute force attack where threat actors attempt to access multiple user accounts using a small set of common or default passwords (e.g., "Password123!", "Welcome1") rather than targeting a single account with many guesses.

## Table Used / Data Source 

- SigninLogs

## Investigation Steps

- Identify all user accounts targeted by the suspicious IP address.
- Determine whether any authentication attempts were successful.
- Review the device information to verify whether the sign-ins originated from a registered, managed, or previously known device.
- If a successful sign-in occurred from an unknown or unmanaged device, treat it as a potential account compromise and continue the investigation.
- Identify the applications targeted during the authentication attempts (e.g., Exchange Online, SharePoint Online, Microsoft Teams, Azure Portal).
- Review the device and browser details, including the operating system, browser, client application, and user agent, for any unusual patterns.
- Check the geographic location, ISP, and IP reputation to determine whether the source is expected for the user or organization.
- Review Conditional Access and MFA results to determine whether access was blocked, challenged, or successfully granted.
- If a successful authentication occurred, pivot to the user's subsequent activities (endpoint, email, cloud, and audit logs) to identify any malicious actions performed after login.

## Investigation Queries 

### Which users were targeted? 

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| summarize 
     TotalAttempts = count()
     FailedAttempts = countif(ResultType != 0)
     SuccessfulAttempts = countif(ResultType == 0)
    by UserPrincipalName
| order by FailedAttempts desc
```

#### what to look for 

- Users with a high number of failed attempts.
- Any account with successful authentication.
- Privileged or VIP accounts.

### Were any authentication attempts successful for accounts involved?

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where UserPrincipalName == "<TARGETED_USER>"
| where ResultType == 0
| project
    TimeGenerated,
    UserPrincipalName,
    AppDisplayName,
    ClientAppUsed,
    IPAddress,
    Location,
    ConditionalAccessStatus
| order by TimeGenerated desc
```

#### What to look for

- Any successful login from the suspicious IP.
- Which application was accessed.
- Whether Conditional Access allowed access.

### Did the sign-in originate from a known or managed device?

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where UserPrincipalName == "<TARGETTED_USER>"
| project
    TimeGenerated,
    UserPrincipalName,
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceName = tostring(DeviceDetail.displayName),
    TrustType = tostring(DeviceDetail.trustType),
    IsManaged = tostring(DeviceDetail.isManaged),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    OperatingSystem = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    ResultType
| order by TimeGenerated desc
```

#### What to look for

- Unknown devices.
- Unmanaged devices.
- Non-compliant devices.
- Device shared by multiple users.

### Which applications were targeted?

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where UserPrincipalName == "<TARGETTED_USER>"
| summarize
    Attempts = count(),
    SuccessfulLogins = countif(ResultType == 0),
    FailedLogins = countif(ResultType != 0)
    by AppDisplayName
| order by Attempts desc
```

#### what to look for

- Exchange Online
- SharePoint Online
- Microsoft Teams
- Azure Portal
- Custom enterprise applications


### Was Conditional Access applied?

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where UserPrincipalName == "TARGETED_USER>"
| project TimeGenerated,
          UserPrincipalName,
          ConditionalAccessStatus,
          ConditionalAccessPolicies,
          ResultType
| order by TimeGenerated desc
```

#### What to look for

- Was access allowed or blocked?
- Which Conditional Access policies were evaluated?
- Were policies applied Successfully?

### Was the sign-in from an unusual location?

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| where UserPrincipalName == "<TARGETED_USER>"
| project TimeGenerated,
          UserPrincipalName,
          Country = tostring(LocationDetails.countryOrRegion),
          State = tostring(LocationDetails.state)
          City = tostring(LocationDetails.city)
          IPAddress,
          ResultType,
| order by TimeGenerated desc
```

#### What to look for

- Countries the user has never authenticated from.
- Locations inconsistent with the user's normal activity.
- Multiple countries within a short timeframe.

### What browsers and Operating Systems were used

```kql
SigninLogs
| where IPAddress == "<SUSPICIOUS_IP>"
| summarize Attempts = count()
     by
     Browser = tostring(DeviceDetail.browser),
     OperatingSystem = tostring(DeviceDetail.operatingSystem)
| order by Attempts desc
```

#### What to look for

- Raare browsers
- Unexpected operating systems


