# Objective

To leverage external threat intelligence IOCs (IP addresses, domains, and URLs) and use KQL queries to identify potential malicious network connections within the organization's environment, helping SOC analysts detect suspicious communications and investigate potentially affected endpoints.

The workflow is:

- Maintain external threat intelligence IOCs in Excel.
- Upload the Excel data into Microsoft Sentinel as a Watchlist (recommended).
- Query the Watchlist using KQL.
- Correlate the IOCs with DeviceNetworkEvents.
- Identify affected endpoints, users, processes and connection timestamps.


## Prepare an Excel Sheet with following coloumns

** Threat_Intelligence_IOCs.xlsx (Example) **

| IOC               | IOCType | ThreatName    | Confidence |
|------------------|---------|--------------|------------|
| 185.199.110.153  | IP      | C2 Server    | 95         |
| evil-example.com | Domain  | Phishing     | 90         |
| malware-example.net | Domain | Malware    | 85         |
| 198.51.100.25    | IP      | Suspicious IP | 80        |

> **Note:** Example indicators are illustrative; do not treat them as confirmed malicious IOCs.

## Upload Excel into Microsoft Sentinel

- Open Microsoft Sentinel.
- Navigate to Configuration → Watchlist.
- Select Create new.
- Give the Watchlist alias: External_IOCs.
- Upload your CSV file (save the Excel workbook as CSV first).
- Set IOC as the SearchKey column.
- Complete the upload.

## KQL – Match Excel IP indicators against network connections

```kql
let IOCList =
    _GetWatchlist('External_IOCs')
    | where IOCType =~ "IP"
    | project IOC = SearchKey,
              ThreatName,
              Confidence;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "ConnectionSuccess"
| join kind=inner IOCList
    on $left.RemoteIP == $right.IOC
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemotePort,
    ThreatName,
    Confidence
| order by Timestamp desc
```

## KQL – Match Excel domain indicators

```kql
let IOCList =
    _GetWatchlist('External_IOCs')
    | where IOCType =~ "Domain"
    | project IOC = tolower(SearchKey),
              ThreatName,
              Confidence;
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where isnotempty(RemoteUrl)
| extend Domain = tolower(
    tostring(parse_url(
        iff(RemoteUrl contains "://",
            RemoteUrl,
            strcat("https://", RemoteUrl)
        )).Host)
)
| join kind=inner IOCList
    on $left.Domain == $right.IOC
| project
    Timestamp,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    Domain,
    RemoteIP,
    RemoteUrl,
    ThreatName,
    Confidence
| order by Timestamp desc
````

## KQL - Consolidated IOC matching report 

```kql
let IOCList =
    _GetWatchlist('External_IOCs')
    | project IOC = tolower(SearchKey),
              IOCType,
              ThreatName,
              Confidence;
let IPMatches =
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where ActionType == "ConnectionSuccess"
    | extend IOC = tolower(RemoteIP)
    | join kind=inner (
        IOCList | where IOCType =~ "IP"
    ) on IOC
    | project Timestamp, DeviceName,
              InitiatingProcessAccountName,
              InitiatingProcessFileName,
              IOC, IOCType, ThreatName,
              Confidence, RemoteUrl, ActionType;
let DomainMatches =
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where isnotempty(RemoteUrl)
    | extend IOC = tolower(
        tostring(parse_url(
            iff(RemoteUrl contains "://",
                RemoteUrl,
                strcat("https://", RemoteUrl)
            )).Host)
    )
    | join kind=inner (
        IOCList | where IOCType =~ "Domain"
    ) on IOC
    | project Timestamp, DeviceName,
              InitiatingProcessAccountName,
              InitiatingProcessFileName,
              IOC, IOCType, ThreatName,
              Confidence, RemoteUrl, ActionType;
union IPMatches, DomainMatches
| order by Timestamp desc
```

### Expected Investigation Report 

## 6. Expected Investigation Output

| Timestamp | Device | IOC | Type | Threat |
|-----------|---------|-----|------|---------|
| Connection time | LAPTOP-01 | 185.199.110.153 | IP | C2 Server |
| Connection time | DESKTOP-02 | evil-example.com | Domain | Phishing |

> **Note:** The output shows devices that communicated with indicators present in the threat intelligence watchlist. Replace "Connection time" with the actual event timestamp returned by the query.



