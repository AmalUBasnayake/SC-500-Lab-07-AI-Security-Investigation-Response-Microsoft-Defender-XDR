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
