# AWS Cloud Security Detection Pack

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Type](https://img.shields.io/badge/Type-Security%20Detection-green) ![Data](https://img.shields.io/badge/Data-AWS%20CloudTrail-orange) ![Rules](https://img.shields.io/badge/Rules-30%2B-red) ![PRs](https://img.shields.io/badge/PRs-Welcome-brightgreen)

## Table of Contents
- [Project Scope](#project-scope)
- [Directory Structure](#directory-structure)
- [Detection Coverage](#detection-coverage)
- [Documentation](#documentation)
- [Usage](#usage)
- [Quick Example](#quick-example)
- [False Positives](#false-positives)
- [Contributing](#contributing)

This repository contains a collection of 30 threat detection rules for AWS environments, written in **SQL** (Athena/Snowflake) and **JSON** (SIGMA-compatible).

The rules focus on identifying high-risk actions in **AWS CloudTrail**, such as unauthorized IAM deviations, defense evasion techniques, and resource exposure.

## Project Scope

- **Data Source:** AWS CloudTrail Management Events.
- **Formats:**
    - `detections/json`: Structured logic for SIEM ingestion or custom parsers.
    - `detections/sql`: Standard SQL queries for Amazon Athena.
- **Philosophy:** Detect behavior, not just configuration.

## Directory Structure

```text
├── detections/      # The core logic
│   ├── json/        # SIGMA-compatible JSON definitions
│   └── sql/         # Athena-ready SQL queries
├── docs/            # Runbooks and guides
├── examples/        # Sample CloudTrail events for testing
├── athena_setup.sql # Table definition
```

## Detection Coverage

The rules cover the following tactic categories:

-   **IAM & Privilege Escalation** (e.g., `Admin Policy Attach`, `Unusual Role Assumption`)
-   **Defense Evasion** (e.g., `Stop CloudTrail`, `Disable GuardDuty`)
-   **Persistence** (e.g., `Create Access Key`, `EC2 UserData Modification`)
-   **Exfiltration** (e.g., `EBS Snapshot Shared`, `S3 Public Access`)
-   **Discovery** (e.g., `Root Account Usage`, `Unauthorized API Spikes`)

See [docs/rule_overview.md](docs/rule_overview.md) for a summary of checks.

## Documentation

-   **[Rule Catalog & Runbook](docs/rule_catalog.md):** Detailed investigation guides for every rule.
-   **[Detection Philosophy](docs/detection_philosophy.md):** Our "high-fidelity" approach to security.
-   **[Simulation Cheat Sheet](docs/simulation_cheat_sheet.md):** AWS CLI commands to safely trigger these rules.
-   **[Troubleshooting](docs/troubleshooting.md):** Solutions for Athena errors and missing alerts.
-   **[False Positive Guidance](docs/false_positive_guidance.md):** How to tune rules for your environment.

## Usage

### 1. Amazon Athena
You can run the `.sql` files directly against your CloudTrail table in Athena.
See [athena_setup.sql](athena_setup.sql) for table creation.

### 2. SIEM Integration
The `.json` files provide a platform-agnostic definition of the logic.
- `tags`: Includes MITRE ATT&CK mapping (e.g., `mitre_t1562`).
- `query`: Boolean logic mapping to CloudTrail fields.

## Quick Example

Detecting **Root Account Usage** (which should be rare):

```sql
SELECT
  eventTime,
  eventName,
  sourceIPAddress,
  userAgent,
  userIdentity.arn
FROM
  cloudtrail_logs
WHERE
  userIdentity.type = 'Root'
  AND userIdentity.invokedBy IS NULL
  AND eventTime > current_timestamp - interval '1' hour;
```

## False Positives

These rules are designed to alert on **significant security events**, but they require tuning.
A `delete_trail` event is a critical alert in a stable production account, but it is expected behavior in a developer sandbox.

See [docs/false_positive_guidance.md](docs/false_positive_guidance.md) for tuning advice.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for rule standards and PR guidelines.

## Disclaimer

This is an open-source project and is not affiliated with Amazon Web Services (AWS). These rules are provided "as is" without warranty. Users should test and validate rules in non-production environments before deploying them.

 MIT License. See [LICENSE](LICENSE) for details.
