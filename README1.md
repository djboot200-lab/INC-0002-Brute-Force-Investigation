L2 Reporting and Findings:
# L2 Investigation Report — INC-0002

## 1. Incident Overview

| Field            | Details                                            |
| ---------------- | -------------------------------------------------- |
| Incident ID      | INC-0002                                           |
| Incident         | Suspected Brute-Force Attack with Successful Login |
| Severity         | High                                               |
| Priority         | P3                                                 |
| Status           | Escalated                                          |
| Detection Source | Splunk                                             |
| Host             | WIN-SOC-LAB                                        |
| Target Account   | Administrator                                      |
| Source IP        | 192.168.31.10                                      |
| Logon Type       | 10                                                 |
| Failed Logins    | 10 × Event ID 4625                                 |
| Successful Login | 1 × Event ID 4624                                  |
| MITRE ATT&CK     | T1110 — Brute Force                                |
| Data             | Synthetic / Simulated                              |

---

## 2. Executive Summary

Splunk identified a suspicious authentication pattern involving **10 failed Windows logins (4625)** followed by a **successful login (4624)** against the `Administrator` account within approximately 10 minutes.

The successful authentication used **Logon Type 10**, representing a remote interactive authentication context.

The activity is **consistent with a suspected brute-force pattern**. However, the available telemetry does not contain sufficient post-authentication evidence to confirm system compromise.

**L2 Assessment:**

> Suspicious authentication activity identified. Successful authentication confirmed. Compromise not confirmed.

---

## 3. Authentication Timeline

| Time     | Event        | Account       | Source        | Logon Type |
| -------- | ------------ | ------------- | ------------- | ---------: |
| 09:41:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:42:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:43:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:44:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:45:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:46:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:47:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:48:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:49:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:50:17 | 4625 Failed  | Administrator | 192.168.31.10 |         10 |
| 09:51:17 | 4624 Success | Administrator | 192.168.31.10 |         10 |

### Timeline Finding

```text
10 Failed Authentication Attempts
              ↓
Successful Authentication
              ↓
Suspicious Authentication Pattern
```

---

## 4. L2 Investigation Findings

### Finding 1 — Repeated Authentication Failures

**Confirmed**

10 Event ID `4625` failures were observed against the `Administrator` account.

### Finding 2 — Successful Authentication

**Confirmed**

An Event ID `4624` successful authentication occurred immediately after the failed attempts.

### Finding 3 — Remote Interactive Context

**Observed**

Logon Type `10` was recorded, indicating a remote interactive authentication context commonly associated with RDP.

### Finding 4 — Brute-Force Pattern

**Assessment: Suspicious / Medium Confidence**

The sequence of repeated failures followed by a successful authentication is consistent with a brute-force pattern.
### Finding 5 — Command execution, Network Discovery

**Observed**

cmd.exe created/executed → Command execution
whoami → System/account discovery
ipconfig → System/network configuration discovery

### Finding 6 — Compromise

**Not Confirmed**

No evidence of malicious process execution, persistence, malware, lateral movement, or data access is available in the current dataset.

---

## 5. Source & Account Analysis

### Target Account

`Administrator`

Because this is an administrative account, the successful authentication requires additional validation.

### Source Address

> `192.168.31.10` is an observed source address, not a confirmed attacker IP.

---

## 6. MITRE ATT&CK Mapping

### T1110 — Brute Force
### T1059.003 — Windows Command Shell → cmd.exe
### T1033 — System Owner/User Discovery → whoami
### T1016 — System Network Configuration Discovery → ipconfig

**Tactic:** Credential Access, Execution & Discovery

**Evidence:** Multiple failed authentication attempts followed by a successful authentication & Post-Authentication Command Execution followed by Discovery Activity.

No additional MITRE techniques are claimed without supporting telemetry.

---

## 7. Evidence Gap

| Evidence              | Status            |
| --------------------- | ----------------- |
| 4625 Failed Logins    | ✅ Available       |
| 4624 Successful Login | ✅ Available       |
| Target Account        | ✅ Available       |
| Source IP             | ✅ Available       |
| Logon Type            | ✅ Available       |
| Process Creation 4688 | ✅ Available       |
| PowerShell 4104       | ✅ Available       |
| Sysmon                | ❌ Not available   |
| Network Telemetry     | ❌ Not available   |
| Persistence Events    | ❌ Not available   |
| Malware Evidence      | ❌ Not available   |
| Lateral Movement      | ❌ Not established |

## 8. L2 Investigation Queries

> The original dataset was generated using Splunk `makeresults`; therefore it is **search-time data, not indexed telemetry**. The following queries represent the indexed-data workflow that would be used after ingestion into `soc_lab`.

### Authentication Correlation

`

### Successful Login Investigation


| makeresults count=11
| streamstats count as attempt
| eval EventCode=if(attempt<=10,4625,4624)
| eval Action=if(EventCode=4625,"Failed Login","Successful Login")
| eval TargetUserName="Administrator"
| eval Source_Network_Address="192.168.31.10"
| eval host="WIN-SOC-LAB"
| eval Logon_Type=10
| eval Failure_Reason=if(EventCode=4625,"Unknown user name or bad password","")
| eval _time=relative_time(now(), "-" . (11-attempt) . "m")
| sort 0 _time
| streamstats count(eval(EventCode=4625)) as Failed_Count
| eval Detection=if(EventCode=4624 AND Failed_Count>=10,
                    "BRUTE FORCE - 10 FAILED LOGINS FOLLOWED BY SUCCESS",
                    "")
| table _time host TargetUserName Source_Network_Address Logon_Type EventCode Action Failed_Count Failure_Reason Detection


### Post-Authentication Process Investigation

| makeresults count=4
| streamstats count as n
| eval _time=relative_time(strptime("2026-09-23 09:52:03","%Y-%m-%d %H:%M:%S"), "+" . ((n-1)*15) . "s")
| eval host="WIN-SOC-LAB"
| eval EventCode=4688
| eval User="Administrator"
| eval Source_Network_Address="192.168.31.10"
| eval ParentImage="C:\\Windows\\System32\\cmd.exe"
| eval NewProcessName=case(
    n=1,"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    n=2,"C:\\Windows\\System32\\whoami.exe",
    n=3,"C:\\Windows\\System32\\ipconfig.exe",
    n=4,"C:\\Windows\\System32\\net.exe"
)
| eval CommandLine=case(
    n=1,"powershell.exe",
    n=2,"whoami.exe",
    n=3,"ipconfig.exe",
    n=4,"net user"
)
| table _time host EventCode User Source_Network_Address ParentImage NewProcessName CommandLine
| sort 0 _time


---

## 10. IOC / IOA Summary

| Type           | Value         | Assessment                 |
| -------------- | ------------- | -------------------------- |
| Source IP      | 192.168.31.10 | Observed                   |
| Target Account | Administrator | Targeted                   |
| Host           | WIN-SOC-LAB   | Affected host              |
| Event          | 4625          | Failed authentication      |
| Event          | 4688          | Process creation           |
| Event          | 4624          | Successful authentication  |
| Logon Type     | 10            | Remote interactive context |

No confirmed malicious file hash, domain, executable, malware, or external attacker infrastructure was identified.

---

## 11. L2 Recommendations

1. Validate whether the successful `Administrator` login was authorized.
2. Identify the owner/system associated with `192.168.31.10`.
3. Review RDP/session telemetry.
4. Correlate post-login process and PowerShell activity.
5. Review network connections after `09:51:17`.
6. Check for persistence and account modifications.
7. Search other hosts for the same source IP/account.
8. If unauthorized activity is confirmed, follow the organization's containment and credential-reset procedures.

---

## 12. Final L2 Assessment

**Classification:** `Suspicious Brute-Force Pattern`

**Successful Authentication:** `Confirmed`

**Compromise:** `Not Confirmed`

**Primary MITRE Technique:** `T1110 — Brute Force`, 'T1059.003 – Windows Command Shell', 'T1033 – System Owner/User Discovery', 'T1016 – System Network Configuration Discovery'

**Confidence:** `Medium`

**Disposition:** `Escalated — Further Investigation Required`

### Final Analyst Statement

> The available evidence demonstrates a suspicious sequence of 10 failed authentication attempts followed by a successful authentication against the `Administrator` account. The activity is consistent with a suspected brute-force pattern and some process creation like powershell.exe,cmd.exe,ipconfig.exe,whoami.exe etc. However, current telemetry does not establish malicious execution or system compromise. Additional endpoint, network, RDP, and persistence telemetry is required for further L2 investigation.

---

## 13. Data Disclaimer

This is a **synthetic SOC lab project** created for educational and portfolio purposes.

The initial authentication telemetry was generated using Splunk `makeresults` and does not represent a real production incident.

The project demonstrates:

* Splunk detection engineering
* Windows authentication analysis
* SOC L1 triage
* L2 investigation methodology
* Timeline reconstruction
* MITRE ATT&CK mapping
* IOC/IOA analysis
* Evidence-gap identification
* Incident documentation
* Escalation and response planning
