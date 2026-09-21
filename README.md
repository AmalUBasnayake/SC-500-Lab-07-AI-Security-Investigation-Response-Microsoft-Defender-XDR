# SC-500 Lab 07 — AI Security Investigation & Response with Microsoft Defender XDR

<p align="center"><img src="Architecture/lab-07-banner.png" alt="SC-500 Lab 07 Banner"></p>

<p align="center"><b>Engineer-level AI runtime investigation, detection, incident correlation and controlled response using Microsoft Foundry, Microsoft Sentinel and Microsoft Defender XDR.</b></p>

<p align="center">AI Workload → Telemetry → KQL Detection → Sentinel Alert → XDR Incident → Investigation → Response → Resolution</p>

## Repository Description

> Engineer-level AI runtime threat investigation lab using Microsoft Foundry, Azure Monitor / Log Analytics, Microsoft Sentinel and Microsoft Defender XDR to validate AI workload telemetry, KQL-based detection, alert generation, XDR incident correlation, investigation and controlled incident response.

---

## 1. Lab Overview

This lab builds an end-to-end AI security operations workflow. A controlled Microsoft Foundry runtime activity is generated, telemetry is collected in Log Analytics, a KQL detection is evaluated by a Microsoft Sentinel scheduled analytics rule, the resulting signal is surfaced in Microsoft Defender XDR, and the incident is investigated and resolved with documented findings.

**Important:** this is a controlled validation exercise. The lab does **not** claim malicious activity, unauthorized access, compromise, data exfiltration or real-world impact.

## 2. Architecture

<p align="center"><img src="Architecture/lab-07-architecture-diagram.png" alt="Lab 07 Architecture Diagram"></p>

```text
Microsoft Foundry / GPT-5.6-Luna
            │
            ▼
 Azure Monitor + Log Analytics
 AzureMetrics / AzureDiagnostics
            │
            ▼
 Microsoft Sentinel
 Scheduled KQL Analytics Rule
            │
            ▼
 Security Alert
            │
            ▼
 Microsoft Defender XDR
 Incident Correlation
            │
            ▼
 Investigation
 Alert / Activities / Attack Story
            │
            ▼
 Controlled Response
            │
            ▼
 Resolved + Documented
```

## 3. Environment

| Component | Configuration |
|---|---|
| Lab | SC-500 Lab 07 |
| Region | East US |
| Resource Group | `rg-sc500-ai-investigation-lab` |
| Microsoft Foundry | `foundry-sc500-ai-investigation` |
| Foundry Project | `proj-default` |
| Model | `gpt-5.6-luna` |
| Model Version | `2026-07-09` |
| Deployment | Global Standard |
| Log Analytics | `law-sc500-ai-investigation` |
| Diagnostic Setting | `diag-foundry-sc500-ai-investigation` |
| Defender CSPM | Enabled |
| Defender AI Services | Enabled |
| Sentinel | Scheduled detection + incident creation |
| Defender XDR | Alert correlation + investigation |

## 4. Objectives

- Provision a dedicated AI workload for investigation.
- Deploy and validate GPT-5.6-Luna.
- Generate controlled runtime activity.
- Enable diagnostic logging and validate ingestion.
- Validate AI model request metrics.
- Build and save KQL investigation queries.
- Create a scheduled Microsoft Sentinel analytics rule.
- Generate a security alert from controlled telemetry.
- Correlate the alert into Microsoft Defender XDR.
- Investigate the incident and review attack story/activity data.
- Resolve the controlled incident with evidence-based documentation.

---

# 5. AI Workload & Runtime Validation

The Foundry resource was created with system-assigned identity, Microsoft-managed encryption and the dedicated lab resource group. A GPT-5.6-Luna deployment was then validated through the Foundry playground.

Controlled prompt:

```text
This is a controlled SC-500 AI security investigation validation test.
Respond with exactly: Investigation runtime validation successful.
```

Expected response:

```text
Investigation runtime validation successful.
```

### Evidence placement

- `04-foundry-resource-review.png`
- `05-foundry-resource-created.png`
- `06-foundry-resource-overview.png`
- `07-foundry-project-overview.png`
- `08-no-model-deployments-baseline.png`
- `10-gpt56-luna-deployment-playground.png`
- `11-gpt56-luna-controlled-runtime-test.png`
- `12-gpt56-luna-runtime-monitoring.png`
- `22-gpt56-luna-runtime-monitoring-post-logging.png`

---

# 6. Defender for Cloud Baseline

The AI security baseline included Defender CSPM, AI Services protection, suspicious prompt evidence and AI Model Security. Data Security for AI interactions was intentionally left disabled for this lab.

### Evidence

- `02-defender-plans-baseline.png`
- `03-ai-security-settings-baseline.png`
- `13-data-ai-security-lab07-baseline.png`
- `15-foundry-ai-security-posture.png`
- `16-foundry-security-recommendations-filtered.png`

---

# 7. Diagnostic Logging & Telemetry

Diagnostic setting:

```text
diag-foundry-sc500-ai-investigation
```

Categories:

- Audit Logs
- Request and Response Logs
- Azure OpenAI Request Usage
- AllMetrics

### AzureDiagnostics validation

```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Resource =~ "foundry-sc500-ai-investigation"
| summarize Count = count() by Category
| order by Count desc
```

The environment subsequently showed `RequestResponse` telemetry.

### Evidence

- `17-log-analytics-workspace-config.png`
- `18-log-analytics-workspace-created.png`
- `19-diagnostic-settings-config.png`
- `20-diagnostic-settings-created.png`
- `23-foundry-requestresponse-logs-ingested.png`
- `24-foundry-requestresponse-investigation-telemetry.png`
- `27-requestresponse-investigation-details.png`
- `28-requestresponse-investigation-summary.png`

---

# 8. AI Runtime Metrics

`AzureMetrics` was used to validate model request and usage telemetry.

```kql
AzureMetrics
| where TimeGenerated > ago(6h)
| where Resource =~ "foundry-sc500-ai-investigation"
| where MetricName == "ModelRequests"
| project TimeGenerated, Resource, MetricName, Total, Maximum, Minimum, Average
| order by TimeGenerated desc
```

Validated metrics included:

```text
ModelRequests
AzureOpenAIRequests
InputTokens
OutputTokens
TotalTokens
```

### Evidence

- `25-ai-runtime-metrics-ingested.png`
- `26-model-request-metric-validation.png`
- `29-ai-runtime-usage-metrics.png`
- `30-ai-operation-success-failure-summary.png`
- `31-ai-failed-operation-detection-no-results.png`

---

# 9. Investigation Timeline

A unified timeline was created across diagnostics and metrics:

```kql
union
(
    AzureDiagnostics
    | where TimeGenerated > ago(6h)
    | where Resource =~ "foundry-sc500-ai-investigation"
    | project TimeGenerated, Source="Diagnostic", Event=OperationName, Status=ResultSignature
),
(
    AzureMetrics
    | where TimeGenerated > ago(6h)
    | where Resource =~ "foundry-sc500-ai-investigation"
    | where MetricName in ("ModelRequests", "AzureOpenAIRequests")
    | project TimeGenerated, Source="Metric", Event=MetricName, Status=tostring(Total)
)
| order by TimeGenerated desc
```

Saved query:

`AI Runtime Investigation Timeline`

### Evidence

- `32-ai-investigation-timeline.png`
- `33-ai-runtime-investigation-query-saved.png`

---

# 10. Detection Engineering

The controlled detection evaluates model request activity over a five-minute window:

```kql
AzureMetrics
| where TimeGenerated > ago(5m)
| where Resource =~ "foundry-sc500-ai-investigation"
| where MetricName == "ModelRequests"
| summarize
    RequestCount = sum(Total),
    PeakRequests = max(Maximum)
    by bin(TimeGenerated, 5m)
| where RequestCount >= 1
| order by TimeGenerated desc
```

> The threshold is intentionally suitable for deterministic lab validation. A production environment should tune thresholds using historical baselines, workload characteristics and additional identity/network/application context.

Saved query:

`AI Model Request Spike Detection`

### Evidence

- `34-model-request-7day-validation.png`
- `35-ai-model-request-spike-no-trigger.png`
- `36-ai-model-request-spike-query-saved.png`

---

# 11. Microsoft Sentinel Analytics Rule

Rule:

```text
AI Runtime Investigation - XDR Detection
```

Configuration:

```text
Severity          : Medium
Frequency         : Every 5 minutes
Lookup period     : Last 5 minutes
Incident creation : Enabled
Event grouping    : Each event
Status            : Enabled
```

The rule was saved successfully and later generated the controlled security signal.

### Evidence

- `89-analytics-rule-general.png`
- `90-analytics-rule-set-rule-logic.png`
- `91-analytics-rule-incident-settings.png`
- `92-analytics-rule-automated-response.png`
- `93-analytics-rule-review-create.png`
- `94-analytics-rule-saved.png`

---

# 12. Defender XDR Incident Investigation

The generated alert was correlated into Microsoft Defender XDR as:

```text
Incident ID : 2
Name        : AI Runtime Investigation - XDR Detection
Severity    : Medium
Category    : Impact
```

The XDR workflow was reviewed through:

- Attack story
- Alerts
- Activities
- Investigations
- Evidence and Response
- Summary
- Alert details
- Related query results

The incident did not contain associated entity objects or separate evidence objects. That is documented as an outcome of the controlled validation rather than interpreted as proof of malicious behavior.

### Evidence

- `78-xdr-incident-attack-story.png`
- `79-xdr-incident-alerts.png`
- `80-xdr-incident-activities.png`
- `81-xdr-investigations.png`
- `82-xdr-evidence-and-response.png`
- `83-xdr-incident-summary.png`
- `84-xdr-attack-story.png`
- `85-xdr-alert-details.png`
- `86-xdr-related-query-results.png`
- `87-advanced-hunting-query.png`
- `88-advanced-hunting-no-results-window.png`

---

# 13. Incident Response & Resolution

The incident was reviewed as a controlled SC-500 validation event. The investigation did not establish malicious activity, unauthorized access, compromise, data exfiltration or real-world impact.

The incident was resolved with documentation explaining that the alert originated from intentionally generated validation activity.

Final state:

```text
Incident ID      : 2
Status           : Resolved
Severity         : Medium
Active alerts    : 1/1
Tactics          : 0
Other categories : 0
Evidence objects : 0
```

### Final evidence

- `96-xdr-incident-resolution.png`
- `97-xdr-incident-resolved.png`
- `98-xdr-resolved-summary.png`
- `99-xdr-resolved-alert.png`
- `100-xdr-incident-activities.png`
- `101-xdr-incident-attack-story-resolved.png`
- `102-xdr-incident-summary-resolved.png`

---

# 14. Lab Visuals

<p align="center"><img src="Architecture/lab-07-lab-visuals.png" alt="Lab 07 Lab Visuals"></p>

---

## 📸 Evidence Gallery

> **SC-500 Lab 07 — AI Security Investigation & Response with Microsoft Defender XDR**
>
> All screenshots are stored in the `Evidence/` directory. The gallery below uses relative GitHub paths, so the images render directly from the repository.

### Evidence navigation

- **01–20:** Environment, Microsoft Foundry, model deployment and initial runtime validation
- **21–40:** Diagnostic logging, telemetry, KQL investigation and Defender security posture
- **41–60:** Local-auth remediation, Entra ID, Sentinel and XDR preparation
- **61–80:** Detection engineering, incident generation and initial XDR investigation
- **81–102:** Advanced hunting, rule validation, controlled response and final incident closure

<details>
<summary><strong>Evidence 01–20</strong> — click to expand</summary>

**01 — Resource Group Created**

![Evidence 01 — Resource Group Created](./Evidence/01-resource-group-created.png)

**02 — Defender Plans Baseline**

![Evidence 02 — Defender Plans Baseline](./Evidence/02-defender-plans-baseline.png)

**03 — Ai Security Settings Baseline**

![Evidence 03 — Ai Security Settings Baseline](./Evidence/03-ai-security-settings-baseline.png)

**04 — Foundry Resource Review**

![Evidence 04 — Foundry Resource Review](./Evidence/04-foundry-resource-review.png)

**05 — Foundry Resource Created**

![Evidence 05 — Foundry Resource Created](./Evidence/05-foundry-resource-created.png)

**06 — Foundry Resource Overview**

![Evidence 06 — Foundry Resource Overview](./Evidence/06-foundry-resource-overview.png)

**07 — Foundry Project Overview**

![Evidence 07 — Foundry Project Overview](./Evidence/07-foundry-project-overview.png)

**08 — No Model Deployments Baseline**

![Evidence 08 — No Model Deployments Baseline](./Evidence/08-no-model-deployments-baseline.png)

**09 — Gpt56 Luna Model Selection**

![Evidence 09 — Gpt56 Luna Model Selection](./Evidence/09-gpt56-luna-model-selection.png)

**10 — Gpt56 Luna Deployment Playground**

![Evidence 10 — Gpt56 Luna Deployment Playground](./Evidence/10-gpt56-luna-deployment-playground.png)

**11 — Gpt56 Luna Controlled Runtime Test**

![Evidence 11 — Gpt56 Luna Controlled Runtime Test](./Evidence/11-gpt56-luna-controlled-runtime-test.png)

**12 — Gpt56 Luna Runtime Monitoring**

![Evidence 12 — Gpt56 Luna Runtime Monitoring](./Evidence/12-gpt56-luna-runtime-monitoring.png)

**13 — Data Ai Security Lab07 Baseline**

![Evidence 13 — Data Ai Security Lab07 Baseline](./Evidence/13-data-ai-security-lab07-baseline.png)

**14 — Ai Discovery Lab07**

![Evidence 14 — Ai Discovery Lab07](./Evidence/14-ai-discovery-lab07.png)

**15 — Foundry Ai Security Posture**

![Evidence 15 — Foundry Ai Security Posture](./Evidence/15-foundry-ai-security-posture.png)

**16 — Foundry Security Recommendations Filtered**

![Evidence 16 — Foundry Security Recommendations Filtered](./Evidence/16-foundry-security-recommendations-filtered.png)

**17 — Log Analytics Workspace Config**

![Evidence 17 — Log Analytics Workspace Config](./Evidence/17-log-analytics-workspace-config.png)

**18 — Log Analytics Workspace Created**

![Evidence 18 — Log Analytics Workspace Created](./Evidence/18-log-analytics-workspace-created.png)

**19 — Diagnostic Settings Config**

![Evidence 19 — Diagnostic Settings Config](./Evidence/19-diagnostic-settings-config.png)

**20 — Diagnostic Settings Created**

![Evidence 20 — Diagnostic Settings Created](./Evidence/20-diagnostic-settings-created.png)

</details>

<details>
<summary><strong>Evidence 21–40</strong> — click to expand</summary>

**21 — Controlled Runtime Test Post Logging**

![Evidence 21 — Controlled Runtime Test Post Logging](./Evidence/21-controlled-runtime-test-post-logging.png)

**22 — Gpt56 Luna Runtime Monitoring Post Logging**

![Evidence 22 — Gpt56 Luna Runtime Monitoring Post Logging](./Evidence/22-gpt56-luna-runtime-monitoring-post-logging.png)

**23 — Foundry Requestresponse Logs Ingested**

![Evidence 23 — Foundry Requestresponse Logs Ingested](./Evidence/23-foundry-requestresponse-logs-ingested.png)

**24 — Foundry Requestresponse Investigation Telemetry**

![Evidence 24 — Foundry Requestresponse Investigation Telemetry](./Evidence/24-foundry-requestresponse-investigation-telemetry.png)

**25 — Ai Runtime Metrics Ingested**

![Evidence 25 — Ai Runtime Metrics Ingested](./Evidence/25-ai-runtime-metrics-ingested.png)

**26 — Model Request Metric Validation**

![Evidence 26 — Model Request Metric Validation](./Evidence/26-model-request-metric-validation.png)

**27 — Requestresponse Investigation Details**

![Evidence 27 — Requestresponse Investigation Details](./Evidence/27-requestresponse-investigation-details.png)

**28 — Requestresponse Investigation Summary**

![Evidence 28 — Requestresponse Investigation Summary](./Evidence/28-requestresponse-investigation-summary.png)

**29 — Ai Runtime Usage Metrics**

![Evidence 29 — Ai Runtime Usage Metrics](./Evidence/29-ai-runtime-usage-metrics.png)

**30 — Ai Operation Success Failure Summary**

![Evidence 30 — Ai Operation Success Failure Summary](./Evidence/30-ai-operation-success-failure-summary.png)

**31 — Ai Failed Operation Detection No Results**

![Evidence 31 — Ai Failed Operation Detection No Results](./Evidence/31-ai-failed-operation-detection-no-results.png)

**32 — Ai Investigation Timeline**

![Evidence 32 — Ai Investigation Timeline](./Evidence/32-ai-investigation-timeline.png)

**33 — Ai Runtime Investigation Query Saved**

![Evidence 33 — Ai Runtime Investigation Query Saved](./Evidence/33-ai-runtime-investigation-query-saved.png)

**34 — Model Request 7Day Validation**

![Evidence 34 — Model Request 7Day Validation](./Evidence/34-model-request-7day-validation.png)

**35 — Ai Model Request Spike No Trigger**

![Evidence 35 — Ai Model Request Spike No Trigger](./Evidence/35-ai-model-request-spike-no-trigger.png)

**36 — Ai Model Request Spike Query Saved**

![Evidence 36 — Ai Model Request Spike Query Saved](./Evidence/36-ai-model-request-spike-query-saved.png)

**37 — Data Ai Security Posture Updated**

![Evidence 37 — Data Ai Security Posture Updated](./Evidence/37-data-ai-security-posture-updated.png)

**38 — Foundry High Security Recommendation**

![Evidence 38 — Foundry High Security Recommendation](./Evidence/38-foundry-high-security-recommendation.png)

**39 — High Recommendation Disable Local Auth**

![Evidence 39 — High Recommendation Disable Local Auth](./Evidence/39-high-recommendation-disable-local-auth.png)

**40 — Foundry Key Access Before Remediation**

![Evidence 40 — Foundry Key Access Before Remediation](./Evidence/40-foundry-key-access-before-remediation.png)

</details>

<details>
<summary><strong>Evidence 41–60</strong> — click to expand</summary>

**41 — Azure Powershell Device Login**

![Evidence 41 — Azure Powershell Device Login](./Evidence/41-azure-powershell-device-login.png)

**41 — Foundry Local Auth Remediated**

![Evidence 41 — Foundry Local Auth Remediated](./Evidence/41-foundry-local-auth-remediated.png)

**42 — Foundry Local Auth Before Remediation**

![Evidence 42 — Foundry Local Auth Before Remediation](./Evidence/42-foundry-local-auth-before-remediation.png)

**42 — Foundry Local Auth Verification**

![Evidence 42 — Foundry Local Auth Verification](./Evidence/42-foundry-local-auth-verification.png)

**43 — Defender Foundry Recommendations Current State**

![Evidence 43 — Defender Foundry Recommendations Current State](./Evidence/43-defender-foundry-recommendations-current-state.png)

**43 — Foundry Recommendation Pending Refresh**

![Evidence 43 — Foundry Recommendation Pending Refresh](./Evidence/43-foundry-recommendation-pending-refresh.png)

**44 — Foundry Recommendation Remediated**

![Evidence 44 — Foundry Recommendation Remediated](./Evidence/44-foundry-recommendation-remediated.png)

**45 — High Recommendation Details Post Remediation**

![Evidence 45 — High Recommendation Details Post Remediation](./Evidence/45-high-recommendation-details-post-remediation.png)

**46 — Defender Xdr Consumer Account Access Blocked**

![Evidence 46 — Defender Xdr Consumer Account Access Blocked](./Evidence/46-defender-xdr-consumer-account-access-blocked.png)

**47 — Entra Tenant Overview**

![Evidence 47 — Entra Tenant Overview](./Evidence/47-entra-tenant-overview.png)

**48 — Defender Xdr Portal Access**

![Evidence 48 — Defender Xdr Portal Access](./Evidence/48-defender-xdr-portal-access.png)

**49 — Microsoft Sentinel Workspace Enabled**

![Evidence 49 — Microsoft Sentinel Workspace Enabled](./Evidence/49-microsoft-sentinel-workspace-enabled.png)

**50 — Microsoft Sentinel Overview Baseline**

![Evidence 50 — Microsoft Sentinel Overview Baseline](./Evidence/50-microsoft-sentinel-overview-baseline.png)

**51 — Unified Siem Xdr Ready**

![Evidence 51 — Unified Siem Xdr Ready](./Evidence/51-unified-siem-xdr-ready.png)

**52 — Defender Xdr Advanced Hunting Ready**

![Evidence 52 — Defender Xdr Advanced Hunting Ready](./Evidence/52-defender-xdr-advanced-hunting-ready.png)

**53 — Defender Xdr Incidents Baseline**

![Evidence 53 — Defender Xdr Incidents Baseline](./Evidence/53-defender-xdr-incidents-baseline.png)

**54 — Gpt56 Luna Xdr Investigation Playground**

![Evidence 54 — Gpt56 Luna Xdr Investigation Playground](./Evidence/54-gpt56-luna-xdr-investigation-playground.png)

**55 — Controlled Xdr Investigation Runtime Test**

![Evidence 55 — Controlled Xdr Investigation Runtime Test](./Evidence/55-controlled-xdr-investigation-runtime-test.png)

**56 — Defender Xdr No Incident After Benign Test**

![Evidence 56 — Defender Xdr No Incident After Benign Test](./Evidence/56-defender-xdr-no-incident-after-benign-test.png)

**57 — Sentinel Analytics Baseline**

![Evidence 57 — Sentinel Analytics Baseline](./Evidence/57-sentinel-analytics-baseline.png)

**58 — Sentinel Scheduled Rule Wizard**

![Evidence 58 — Sentinel Scheduled Rule Wizard](./Evidence/58-sentinel-scheduled-rule-wizard.png)

**59 — Sentinel Mitre T1499 002 Selected**

![Evidence 59 — Sentinel Mitre T1499 002 Selected](./Evidence/59-sentinel-mitre-t1499-002-selected.png)

**60 — Xdr Incident Settings**

![Evidence 60 — Xdr Incident Settings](./Evidence/60-xdr-incident-settings.png)

</details>

<details>
<summary><strong>Evidence 61–80</strong> — click to expand</summary>

**61 — Sentinel Automated Response Baseline**

![Evidence 61 — Sentinel Automated Response Baseline](./Evidence/61-sentinel-automated-response-baseline.png)

**62 — Sentinel Rule Schedule 5Min**

![Evidence 62 — Sentinel Rule Schedule 5Min](./Evidence/62-sentinel-rule-schedule-5min.png)

**63 — Sentinel Xdr Incident Creation Enabled**

![Evidence 63 — Sentinel Xdr Incident Creation Enabled](./Evidence/63-sentinel-xdr-incident-creation-enabled.png)

**64 — Sentinel Automated Response Empty**

![Evidence 64 — Sentinel Automated Response Empty](./Evidence/64-sentinel-automated-response-empty.png)

**65 — Xdr Analytics Rule Review Create**

![Evidence 65 — Xdr Analytics Rule Review Create](./Evidence/65-xdr-analytics-rule-review-create.png)

**66 — Xdr Analytics Rule Created**

![Evidence 66 — Xdr Analytics Rule Created](./Evidence/66-xdr-analytics-rule-created.png)

**67 — Xdr Detection Rule Enabled**

![Evidence 67 — Xdr Detection Rule Enabled](./Evidence/67-xdr-detection-rule-enabled.png)

**68 — Xdr Advanced Hunting Runtime Telemetry**

![Evidence 68 — Xdr Advanced Hunting Runtime Telemetry](./Evidence/68-xdr-advanced-hunting-runtime-telemetry.png)

**69 — Xdr Incidents No Incident Yet**

![Evidence 69 — Xdr Incidents No Incident Yet](./Evidence/69-xdr-incidents-no-incident-yet.png)

**70 — Xdr Controlled Runtime Validation**

![Evidence 70 — Xdr Controlled Runtime Validation](./Evidence/70-xdr-controlled-runtime-validation.png)

**71 — Xdr Incident Created**

![Evidence 71 — Xdr Incident Created](./Evidence/71-xdr-incident-created.png)

**72 — Xdr Incident Investigation Overview**

![Evidence 72 — Xdr Incident Investigation Overview](./Evidence/72-xdr-incident-investigation-overview.png)

**73 — Xdr Alert Details Overview**

![Evidence 73 — Xdr Alert Details Overview](./Evidence/73-xdr-alert-details-overview.png)

**74 — Xdr Alert Investigation Details**

![Evidence 74 — Xdr Alert Investigation Details](./Evidence/74-xdr-alert-investigation-details.png)

**75 — Xdr Alert Evidence No Related Evidence**

![Evidence 75 — Xdr Alert Evidence No Related Evidence](./Evidence/75-xdr-alert-evidence-no-related-evidence.png)

**76 — Xdr Alert Classification Options**

![Evidence 76 — Xdr Alert Classification Options](./Evidence/76-xdr-alert-classification-options.png)

**77 — Xdr Alert Security Testing Classification**

![Evidence 77 — Xdr Alert Security Testing Classification](./Evidence/77-xdr-alert-security-testing-classification.png)

**78 — Xdr Incident Investigation Overview**

![Evidence 78 — Xdr Incident Investigation Overview](./Evidence/78-xdr-incident-investigation-overview.png)

**79 — Xdr Incident Alert Details**

![Evidence 79 — Xdr Incident Alert Details](./Evidence/79-xdr-incident-alert-details.png)

**80 — Xdr Incident Activity Details**

![Evidence 80 — Xdr Incident Activity Details](./Evidence/80-xdr-incident-activity-details.png)

</details>

<details>
<summary><strong>Evidence 81–100</strong> — click to expand</summary>

**81 — Xdr Investigation Status**

![Evidence 81 — Xdr Investigation Status](./Evidence/81-xdr-investigation-status.png)

**82 — Xdr Evidence Response Status**

![Evidence 82 — Xdr Evidence Response Status](./Evidence/82-xdr-evidence-response-status.png)

**83 — Xdr Incident Summary**

![Evidence 83 — Xdr Incident Summary](./Evidence/83-xdr-incident-summary.png)

**84 — Xdr Attack Story Overview**

![Evidence 84 — Xdr Attack Story Overview](./Evidence/84-xdr-attack-story-overview.png)

**85 — Xdr Alert Details**

![Evidence 85 — Xdr Alert Details](./Evidence/85-xdr-alert-details.png)

**86 — Xdr Alert Investigation Details**

![Evidence 86 — Xdr Alert Investigation Details](./Evidence/86-xdr-alert-investigation-details.png)

**87 — Xdr Alert Kql Query**

![Evidence 87 — Xdr Alert Kql Query](./Evidence/87-xdr-alert-kql-query.png)

**88 — Xdr Kql No Results Current Window**

![Evidence 88 — Xdr Kql No Results Current Window](./Evidence/88-xdr-kql-no-results-current-window.png)

**89 — Sentinel Analytics Rule Details**

![Evidence 89 — Sentinel Analytics Rule Details](./Evidence/89-sentinel-analytics-rule-details.png)

**90 — Sentinel Analytics Rule Logic**

![Evidence 90 — Sentinel Analytics Rule Logic](./Evidence/90-sentinel-analytics-rule-logic.png)

**91 — Sentinel Incident Settings**

![Evidence 91 — Sentinel Incident Settings](./Evidence/91-sentinel-incident-settings.png)

**92 — Sentinel Automated Response Status**

![Evidence 92 — Sentinel Automated Response Status](./Evidence/92-sentinel-automated-response-status.png)

**93 — Xdr Detection Rule Review**

![Evidence 93 — Xdr Detection Rule Review](./Evidence/93-xdr-detection-rule-review.png)

**94 — Xdr Detection Rule Updated**

![Evidence 94 — Xdr Detection Rule Updated](./Evidence/94-xdr-detection-rule-updated.png)

**95 — Xdr Incident Investigation Final View**

![Evidence 95 — Xdr Incident Investigation Final View](./Evidence/95-xdr-incident-investigation-final-view.png)

**96 — Xdr Incident Resolve Ready**

![Evidence 96 — Xdr Incident Resolve Ready](./Evidence/96-xdr-incident-resolve-ready.png)

**97 — Xdr Incident Resolved Final**

![Evidence 97 — Xdr Incident Resolved Final](./Evidence/97-xdr-incident-resolved-final.png)

**98 — Xdr Incident Summary Resolved**

![Evidence 98 — Xdr Incident Summary Resolved](./Evidence/98-xdr-incident-summary-resolved.png)

**99 — Xdr Resolved Alert List**

![Evidence 99 — Xdr Resolved Alert List](./Evidence/99-xdr-resolved-alert-list.png)

**100 — Xdr Automated Correlation Activity**

![Evidence 100 — Xdr Automated Correlation Activity](./Evidence/100-xdr-automated-correlation-activity.png)

</details>

<details>
<summary><strong>Evidence 101–102</strong> — click to expand</summary>

**101 — Xdr Incident Attack Story Resolved**

![Evidence 101 — Xdr Incident Attack Story Resolved](./Evidence/101-xdr-incident-attack-story-resolved.png)

**102 — Xdr Incident Summary Resolved**

![Evidence 102 — Xdr Incident Summary Resolved](./Evidence/102-xdr-incident-summary-resolved.png)

</details>

<details>
<summary><strong>Additional Evidence Files</strong> — click to expand</summary>

**Sentinel Mitre T1499 002 Selected**

![Sentinel Mitre T1499 002 Selected](./Evidence/sentinel-mitre-t1499-002-selected.png)

</details>


# 15. Engineer-Level SOC Model

```text
OBSERVE
   ↓
COLLECT
   ↓
NORMALIZE
   ↓
DETECT
   ↓
CORRELATE
   ↓
INVESTIGATE
   ↓
VALIDATE
   ↓
RESPOND
   ↓
DOCUMENT
   ↓
IMPROVE
```

A security alert is a **signal requiring investigation**, not automatic proof of compromise. The investigation should connect telemetry, identity, workload context and supporting evidence before making a final classification.

## 16. Real-World Investigation Questions

1. What workload generated the activity?
2. Which identity initiated the request?
3. Was the activity expected?
4. Which model or endpoint was involved?
5. Did request volume deviate from the normal baseline?
6. Were there failed operations?
7. Were suspicious prompts or instruction-override attempts observed?
8. Were there related identity, endpoint or network alerts?
9. Was sensitive data involved?
10. What evidence supports the final classification?
11. What response action is justified?
12. What detection improvement should follow the investigation?

## 17. Skills Demonstrated

```text
Microsoft Foundry
Azure AI Security
Microsoft Defender for Cloud
Microsoft Sentinel
Microsoft Defender XDR
KQL
Azure Monitor
Log Analytics
Detection Engineering
Security Monitoring
Incident Investigation
Incident Response
XDR Correlation
Evidence Collection
SOC Operations
AI Runtime Security
Security Documentation
```

## 18. Final Outcome

<p align="center"><img src="Architecture/lab-07-lab-visuals.png" alt="Lab 07 Final Outcome"></p>

The lab validated an end-to-end AI security operations workflow:

```text
AI Runtime Activity
        ↓
Telemetry Collection
        ↓
KQL Detection
        ↓
Microsoft Sentinel
        ↓
Security Alert
        ↓
Microsoft Defender XDR
        ↓
Incident Correlation
        ↓
Investigation
        ↓
Evidence-Based Classification
        ↓
Resolution
```

## 19. Repository Structure

```text
SC-500-Lab-07-AI-Security-Investigation-Response-Microsoft-Defender-XDR/
│
├── README.md
├── KQL/
│   └── ai-runtime-investigation-xdr-detection.kql
│
├── Architecture/
│   ├── lab-07-banner.png
│   ├── lab-07-architecture-diagram.png
│   └── lab-07-lab-visuals.png
│
└── Evidence/
    ├── 01–102 evidence screenshots
    ├── additional evidence files
    └── README.md
```

## Author

**Amal Udayanga Basnayake**  
Cybersecurity Engineer | Azure Security | Microsoft Security | SIEM & Threat Detection

- GitHub: https://github.com/AmalUBasnayake
- Portfolio: https://amalcyberlab.vercel.app/
- LinkedIn: https://www.linkedin.com/in/amal-udayanga-basnayake/

---

<p align="center"><b>Build. Learn. Detect. Investigate. Respond. Grow.</b></p>
<p align="center">Security is a journey, not a destination.</p>
