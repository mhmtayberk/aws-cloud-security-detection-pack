# Detection Philosophy

## Core Principles

Good detections find real threats. Bad detections waste your time. This repository is built on a "high-fidelity, low-noise" philosophy designed for real-world security operations centers (SOCs) and incident response teams.

### 1. Attack-Informed Defense
These rules focus on what attackers actually do, not compliance checkboxes. We prioritize TTPs (Tactics, Techniques, and Procedures) observed in actual cloud compromises over theoretical misconfigurations. 

We reference frameworks like **MITRE ATT&CK for Cloud** not as a buzzword, but as a checklist of legitimate adversary goals: persistence, privilege escalation, defense evasion, and exfiltration.

### 2. Signal-to-Noise Ratio
If a rule fires 100 times/day on normal activity, it's broken. Period. 
*   **Actionable:** If an alert fires, a human should investigate it.
*   **Contextual:** Alerts must imply *intent*, not just *capability*. For example, identifying `ConsoleLogin` is noise; identifying `ConsoleLogin` without MFA on a root account is a critical signal.

### 3. Resilience
Attackers adapt. Our rules aim to detect the *outcome* of an action rather than just the specific API call used to achieve it, whenever possible. While AWS CloudTrail is our primary lens, we structure logic to be robust against slight variations in tool usage.

## Methodology

### The Lifecycle of a Rule
1.  **Hypothesis:** Based on new threat intel or a known attack vector (e.g., "Attackers disable CloudTrail to hide tracks").
2.  **Development:** Crafting the SQL/JSON logic to detect this specific API pattern.
3.  **Tuning:** Excluding known system accounts (`AWS Service Roles`) and common administrative patterns that mimic attacks.
4.  **Validation:** Verifying against actual AWS event structures.

### Why JSON and SQL?
*   **JSON:** Provides a structured, platform-agnostic definition that can be ingested by custom automation, SOAR playbooks, or simplistic log parsers.
*   **SQL:** Ready-to-use queries for data lakes (Amazon Athena, Snowflake) and SIEMs that support SQL-like syntax. This reduces the "time-to-value" for engineers.
