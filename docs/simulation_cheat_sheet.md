# Simulation Cheat Sheet (Testing Guide)

Use these AWS CLI commands to safely trigger the detection rules in a **Sandbox/Non-Production** environment. 
**WARNING:** Do NOT run these in Production without explicit authorization.

## IAM & Identity

### Trigger: `iam_create_access_key_for_other_user`
Create a dummy user and generate a key for them.
```bash
aws iam create-user --user-name SimulationVictim
aws iam create-access-key --user-name SimulationVictim
# Clean up
aws iam delete-access-key --user-name SimulationVictim --access-key-id <KEY_ID>
aws iam delete-user --user-name SimulationVictim
```

### Trigger: `iam_admin_policy_attach`
Attach Admin access to a role.
```bash
aws iam attach-role-policy --role-name <YOUR_TEST_ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
# Clean up
aws iam detach-role-policy --role-name <YOUR_TEST_ROLE> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

## Defense Evasion

### Trigger: `guardduty_detector_delete`
**Note:** Requires GuardDuty to be enabled first.
```bash
# Get Detector ID
aws guardduty list-detectors
# Delete (Simulated)
aws guardduty delete-detector --detector-id <DETECTOR_ID>
```

### Trigger: `cloudtrail_stop_logging`
```bash
aws cloudtrail stop-logging --name <TRAIL_NAME>
# Clean up
aws cloudtrail start-logging --name <TRAIL_NAME>
```

## Data & Network

### Trigger: `security_group_ingress_open_world`
Open Port 22 to the world.
```bash
aws ec2 authorize-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0
# Clean up
aws ec2 revoke-security-group-ingress --group-id <SG_ID> --protocol tcp --port 22 --cidr 0.0.0.0/0
```

### Trigger: `s3_bucket_public_access_put`
Disable Block Public Access.
```bash
aws s3api delete-public-access-block --bucket <BUCKET_NAME>
```

## Advanced Verification

### Trigger: `sts_decode_authorization_message`
Run an action you don't have permission for, then try to decode the error.
```bash
# 1. Run forbidden command
aws s3 ls s3://production-secret-bucket
# 2. Decode the encoded message from the error
aws sts decode-authorization-message --encoded-message <BASE64_STRING>
```
