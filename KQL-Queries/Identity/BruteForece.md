# BruteForce

## Objective 

Investigate repeated authentication attempts against a single user account to determine whether an attacker was attempting to guess the user's password and whether the attack resulted in succesful compromise.

## Table Used

SigninLogs

## Investigation Steps

- Identify the targeted user account.
- Review the number and timing of failed authentication attempts.
- Determine whether any authentication attempts were successful.
- Check the source IP address(es) involved.
- Review the geographic location and IP reputation.
- Determine whether MFA was challenged or completed.
- Review device and browser information.
- Identify the applications targeted.
- If authentication succeeded, investigate post-authentication activity.

## Investigation Querries 

### Identify the Source IP's targetting the account

```kql
SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| where ResultType != 0
| summarize
   FailedAttempts = count()
   by IPAddress
| order by FailedAttempts desc
```

#### What to Look for

- One IP responsible for most attempts
- Multiple IP's targetting the same account
- Unexpected geographic sources

### Review the authentication timeline

```kql 
SigninLogs 
| where UserPrincipalName == "<TARGETED_USER>"
| project 
   TimeGenerated,
   IPAddress,
   ResultSignature
   ResultType
   AppDisplayName
| order by TimeGenerated desc
```

#### What to look out for

- Bursts of failed attempts.
- Repeated attempts within a short period.
- Failed attempts followed by a successful login.

### Determine wheather authentication successeded

```kql
SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| where IPAddress has_any ("SOURCE_IP1", "SOURCE_IP2")
| where ResultType == 0
| project
    TimeGenerated,
    IPAddress,
    AppDisplayName,
    ClientAppUsed,
    ConditionalAccessStatus
| order by TimeGenerated desc
```

#### Note: 

Inculde all the source_ip's which was discovered.

#### Check if there was any successful login right after failure attempts in a timeframe of 15 min

```kql 
SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    ResultType
| order by TimeGenerated asc
| extend AttemptType = iff(ResultType == 0, "Success", "Failure")
| extend
    PrevAttemptType = prev(AttemptType),
    PrevIPAddress = prev(IPAddress),
    PrevAttemptTime = prev(TimeGenerated)
| where AttemptType == "Success"
    and PrevAttemptType == "Failure"
    and IPAddress == PrevIPAddress
    and datetime_diff('minute', TimeGenerated, PrevAttemptTime) <= 15
| project
    SuccessTime = TimeGenerated,
    UserPrincipalName,
    IPAddress,
    PreviousFailedAttempt = PrevAttemptTime
| order by SuccessTime desc
```

#### what to look out for 

- IPs with success before failures → unusual sequence, may indicate compromised credentials or attacker testing persistence.
- Check IP reputation to spot malicious or risky sources.
- ISP vs. Cloud hosting → residential ISP IPs are more likely legitimate; cloud provider IPs (AWS, Azure, GCP) often abused for attacks.
- Expected environment usage → validate if IPs belong to corporate ranges, VPN gateways, or known geolocations.

### Check for Device Information

```kql
SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| project
    TimeGenerated,
    IPAddress,
    ResultType,
    DeviceId = tostring(DeviceDetail.deviceId),
    DeviceName = tostring(DeviceDetail.displayName),
    IsManaged = tostring(DeviceDetail.isManaged),
    IsCompliant = tostring(DeviceDetail.isCompliant),
    OperatingSystem = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser)
| order by TimeGenerated desc
```

#### What to look for:

- New device.
- Unmanaged device.
- Non-compliant device.
- Unusual OS/browser combination.

### Review Geographic Location

```kql
let baseline =
    SigninLogs
    | where UserPrincipalName == "<TARGETED_USER>"
    | where ResultType == 0
    | summarize UsualCountries = make_set(tostring(LocationDetails.countryOrRegion));

SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| extend Country = tostring(LocationDetails.countryOrRegion)
| extend AttemptType = iff(ResultType == 0, "Success", "Failure")
| extend IsUnusualCountry = iff(
    Country !in (toscalar(baseline.UsualCountries)),
    "Yes",
    "No"
)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    AttemptType,
    Country,
    IsUnusualCountry,
    AppDisplayName,
    ClientAppUsed
| order by TimeGenerated desc
```

#### what to look out for

- Spot unusual countries/states/cities compared to the user’s baseline.
- Check if expected (travel, VPN, corporate ranges).
- Cloud provider IPs → often suspicious unless explicitly used.
- Run IP reputation checks to confirm risk.


### Next Step 

After reviewing the authentication activity, device, location, client, MFA, and Conditional Access results, check for post-authentication activity if the account was successfully compromised. Pivot on the affected user and the time of the successful sign-in to determine whether the account was used to access resources, modify account settings, access email, execute processes, or perform other suspicious actions.
