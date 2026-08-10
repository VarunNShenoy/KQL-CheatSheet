# Impossible-Travel

## Objective

Investigate authentication activity where a user appears to have successfully signed in from geographically distant locations within a timeframe that may not be physically possible, and determine whether the activity indicates account compromise or legitimate travel/VPN usage.

## Table Used

SigninLogs

## Investigation Steps

- Identify the authentication events associated with the alert.
- Establish the user's login timeline and locations.
- Determine the time and location difference between successful sign-ins.
- Check whether the IP addresses are known or expected.
- Review device information for each authentication.
- Review browser and client application information.
- Review MFA and Conditional Access results.
- Determine whether the activity could be explained by VPN, proxy, corporate egress, or legitimate travel.
- If suspicious, investigate activity following the successful authentication.

## Investigation Queries 

### Identify successful sign-ins from different countries within a short time

```kql
SigninLogs
| where UserPrincipalName == "<TARGETED_USER>"
| where ResultType == 0
| extend
    Country = tostring(LocationDetails.countryOrRegion),
    State = tostring(LocationDetails.state),
    City = tostring(LocationDetails.city)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    State,
    City,
    AppDisplayName,
    ClientAppUsed
| order by TimeGenerated asc
| extend
    PreviousTime = prev(TimeGenerated),
    PreviousCountry = prev(Country),
    PreviousIPAddress = prev(IPAddress),
    PreviousCity = prev(City)
| extend
    TimeDifferenceMinutes = datetime_diff('minute', TimeGenerated, PreviousTime)
| where Country != PreviousCountry
| project
    PreviousTime,
    TimeGenerated,
    PreviousCountry,
    Country,
    PreviousCity,
    City,
    PreviousIPAddress,
    IPAddress,
    TimeDifferenceMinutes,
    AppDisplayName,
    ClientAppUsed
| order by TimeGenerated desc
```

#### What to look for

- Very short time difference between geographically distant countries.
- Successful authentication from two different countries.
- Different IP addresses associated with the transitions.
- Different devices or browsers between the two logins.
- A successful login from an unfamiliar location followed by another successful login elsewhere.

### Next Step

After identifying successful sign-ins from different countries within a short timeframe, investigate the associated IP addresses to determine whether the activity can be explained by legitimate VPN, proxy, corporate network, or cloud infrastructure. Review the IP reputation, ASN/ISP, VPN/proxy status, and geographic information before determining whether the impossible-travel activity is suspicious.