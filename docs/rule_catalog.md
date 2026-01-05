# Rule Catalog & Investigation Guide

This document acts as a runbook for security analysts. It details the intent behind each rule and provides specific steps for investigation (Triage) and remediation.

## Identity & Access Management (IAM)

### `root_account_usage`
*   **Why it matters:** The Root account has unrestricted access and cannot be limited by IAM policies. Its use violates the "Principle of Least Privilege" and indicates a gap in administrative process or a compromise.
*   **Investigation:**
    1.  Check `userIdentity.arn`.
    2.  Verify if the action corresponds to a support plan change or account closure.
    3.  Contact the account owner immediately.
*   **Severity:** Critical

### `iam_admin_policy_attach`
*   **Why it matters:** Attaching `AdministratorAccess` grants full control over the AWS account. Attackers often do this to escalate privileges of a compromised low-level user.
*   **Investigation:**
    1.  Identify *who* attached the policy (`userIdentity`) and *who* received it.
    2.  Check if this was part of a Terraform/CloudFormation deployment.
    3.  If manual, verify with the DevOps lead.
*   **Severity:** High

### `iam_create_access_key_for_other_user`
*   **Why it matters:** A user creating keys for *someone else* is a classic persistence technique. It allows the attacker to access the victim's account later using a backdoor key.
*   **Investigation:**
    1.  Review the `userName` parameter to see whose key was created.
    2.  Check if the actor is a Federation Role or an automated tool.
*   **Severity:** High

### `iam_update_assume_role_policy_trust`
*   **Why it matters:** This is a "Trust Policy" modification. If an attacker adds their own external AWS Account ID here, they can assume this role from outside your environment anytime.
*   **Investigation:**
    1.  **CRITICAL:** Look at the `policyDocument` for new `AWS: "arn:aws:iam::..."` principals.
    2.  If the number is unknown/external, revoke immediately.
*   **Severity:** Critical

### `console_login_without_mfa`
*   **Why it matters:** Password-only access is vulnerable to phishing and credential stuffing.
*   **Investigation:**
    1.  Reach out to the user to enable MFA.
    2.  Enforce an IAM Policy that denies all actions unless `aws:MultiFactorAuthPresent` is true.
*   **Severity:** Medium

### `sts_decode_authorization_message`
*   **Why it matters:** Legitimate users almost never manually decode error messages. Attackers do this to map out permissions (Reconnaissance).
*   **Investigation:**
    1.  Check the user's history for prior `AccessDenied` events.
    2.  Strong indicator of a human adversary or pentest tool.
*   **Severity:** Medium

### `iam_policy_changes`
*   **Why it matters:** Broad detection for any IAM policy modification or deletion. Can be noisy but useful for spotting stealthy persistence.
*   **Investigation:**
    1.  Was this a `DetachUserPolicy` or `DeletePolicy`?
    2.  Did it remove a security guardrail (e.g., `DenyAllOutsideEU`)?
*   **Severity:** Low (High Activity)

### `suspicious_role_assumption`
*   **Why it matters:** Detects cross-account role assumption from unknown or untrusted external accounts.
*   **Investigation:**
    1.  Who owns the `userIdentity.accountId` assuming the role?
    2.  Is it a vendor or partner? Use `aws organizations describe-account` if internal.
*   **Severity:** High

### `aws_access_key_exposure`
*   **Why it matters:** Detects `GetCallerIdentity` calls from unusual IPs immediately after key creation.
*   **Investigation:**
    1.  Is the source IP part of your known infrastructure?
    2.  If not, the key was likely leaked (e.g., committed to GitHub). Revoke immediately.
*   **Severity:** Critical

### `lambda_privilege_escalation`
*   **Why it matters:** Detects passing an Admin role to a Lambda function, allowing the function (and its author) to become Admin.
*   **Investigation:**
    1.  Inspect the code of the Lambda function.
    2.  Does it need `AdministratorAccess`? (Spoiler: No).
*   **Severity:** High

---

## Defense Evasion (Hiding Tracks)

### `cloudtrail_stop_logging`
*   **Why it matters:** The first thing a sophisticated attacker does is blind the security team.
*   **Investigation:**
    1.  Check if the actor is a rigorous automation tool.
    2.  Re-enable logging instantly.
*   **Severity:** Critical

### `guardduty_detector_delete`
*   **Why it matters:** Disabling the primary threat detection service.
*   **Investigation:**
    1.  Confirm if the account is being decommissioned.
    2.  If not, this is a hostile action.
*   **Severity:** High

### `config_recorder_stop`
*   **Why it matters:** Stops resource inventory tracking.
*   **Investigation:**
    1.  Verify intent immediately.
*   **Severity:** Medium

### `vpc_flow_logs_delete`
*   **Why it matters:** Removes network traffic visibility. Often done before data exfiltration.
*   **Investigation:**
    1.  Check if the VPC itself was deleted (valid cleanup).
    2.  If VPC exists but logs are gone, investigate.
*   **Severity:** High

### `organization_leave_account`
*   **Why it matters:** An account leaving the Organization escapes all Service Control Policies (SCPs).
*   **Investigation:**
    1.  Contact the account owner and AWS Support to reclaim the account.
*   **Severity:** Critical

### `route53_domain_transfer_lock_disable`
*   **Why it matters:** Precursor to domain hijacking. Allows the attacker to transfer your domain to another registrar.
*   **Investigation:**
    1.  Is the domain expiring or being sold?
    2.  If not, re-lock immediately.
*   **Severity:** High

---

## Critical Data Security & Exfiltration

### `s3_bucket_public_access_put`
*   **Why it matters:** Disabling "Block Public Access" is the prerequisite for making a bucket entirely public.
*   **Investigation:**
    1.  Check the bucket name.
    2.  If sensitive, re-enable the block immediately.
*   **Severity:** High

### `s3_bucket_policy_changes`
*   **Why it matters:** Changing a bucket policy to allow `Principal: "*"` or similar wide access.
*   **Investigation:**
    1.  Read the new policy JSON. Does it allow public access?
*   **Severity:** Medium

### `s3_replication_rule_external`
*   **Why it matters:** Automates data theft. New files are automatically copied to an attacker-controlled bucket.
*   **Investigation:**
    1.  Review the destination bucket account ID.
*   **Severity:** High

### `ebs_snapshot_shared_externally`
*   **Why it matters:** Allows an outsider to mount your server's disk and read data.
*   **Investigation:**
    1.  Check `createVolumePermission`.
    2.  If `userId` is not a known Disaster Recovery account, revoke it.
*   **Severity:** Critical

### `rds_snapshot_shared_externally`
*   **Why it matters:** Database snapshot sharing (SQL Dump exposure).
*   **Investigation:**
    1.  Identify the target account ID.
*   **Severity:** Critical

### `secrets_manager_access`
*   **Why it matters:** Retrieval of secrets (API keys, DB passwords) from an unusual source.
*   **Investigation:**
    1.  Check `sourceIPAddress`. Is it a known VPN/Office IP?
    2.  Rotate the secret if the access is unverified.
*   **Severity:** Low (Context Dependent)

---

## Persistence & Impact

### `kms_key_schedule_deletion`
*   **Why it matters:** Destructive (Ransomware). If a key is deleted, encrypted data is lost forever.
*   **Investigation:**
    1.  Cancel the deletion (`CancelKeyDeletion`).
    2.  Investigate why it was scheduled.
*   **Severity:** Critical

### `kms_key_policy_changes`
*   **Why it matters:** Modifying the key policy to grant external access or deny the root user (locking you out).
*   **Investigation:**
    1.  Review the `PutKeyPolicy` document.
*   **Severity:** High

### `ec2_modify_user_data`
*   **Why it matters:** `UserData` scripts run as root on boot. Persistence mechanism.
*   **Investigation:**
    1.  Inspect the script content for reverse shells.
*   **Severity:** High

### `security_group_ingress_open_world`
*   **Why it matters:** Opening SSH (22) or RDP (3389) to `0.0.0.0/0`.
*   **Investigation:**
    1.  Is this a Honeypot?
    2.  If not, restrict to VPN IP immediately.
*   **Severity:** Critical

### `ssm_session_abuse`
*   **Why it matters:** Interactive shell access via the browser (no SSH keys needed). Harder to monitor than SSH.
*   **Investigation:**
    1.  Check which user started the session.
    2.  Verify the reason.
*   **Severity:** Medium

### `unauthorized_api_calls`
*   **Why it matters:** High volume of Access Denied errors indicates a confused script or a recon scan.
*   **Investigation:**
    1.  Identify the `userIdentity`.
    2.  Check if they are bruteforcing permissions.
*   **Severity:** Medium

### `s3_lifecycle_expiration_ransomware`
*   **Why it matters:** Attackers set a lifecycle rule to expire (delete) all objects in 1 day.
*   **Investigation:**
    1.  Check the `ExpirationInDays` parameter.
    2.  Disable the rule immediately.
*   **Severity:** Critical
