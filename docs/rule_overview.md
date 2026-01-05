# Detection Rule Overview

This repository contains 30 detection rules focused on high-impact cloud threats. The logic is derived from observed attacker tradecraft, not compliance benchmarks.

## Identity & Access Management (IAM)
Focuses on privilege escalation, persistence, and credential theft.
- **Privilege Escalation:** Detects `Attach*Policy` to admin roles or bypassing policy restrictions.
- **Credential Exfiltration:** Monitors for `CreateAccessKey` on other users.
- **Trust Policy Manipulation:** Alerts on modifications to `AssumeRole` trust relationships (e.g., allowing external accounts).

## Discovery & Reconnaissance
Detects the "enumeration" phase of a compromise.
- **Unauthorized API Spikes:** Aggregated tracking of `AccessDenied` errors.
- **Pre-Attack API Calls:** Monitoring for `GetCallerIdentity` from unusual sources.

## Defense Evasion
Detects attempts to blind security teams.
- **Logging Disruption:** `StopLogging`, `DeleteTrail`, or `UpdateTrail` to disable global recording.
- **Security Tool Tampering:** Disabling GuardDuty detectors or deleting VPC Flow Logs.
- **Config Drift:** Stopping AWS Config recording.

## Data Exfiltration & Impact
Focuses on resource exposure and data theft.
- **Snapshot Sharing:** Public or external sharing of EBS/RDS snapshots.
- **S3 Exposure:** Removing "Public Access Block" or modifying bucket policies to allow wide access.
- **Ransomware Precursors:** Rapid modification of S3 lifecycle policies to expire objects.

## Network Security
- **Security Group Ingress:** Alerts on rules allowing `0.0.0.0/0` ingress on sensitive ports.
- **Route53 Lock Removal:** Detects disabling of domain transfer locks.

## Compute & Infrastructure
- **EC2 UserData Modification:** Detects injection of malicious scripts into instance userdata.
- **System Manager Abuse:** Suspicious `StartSession` calls.
