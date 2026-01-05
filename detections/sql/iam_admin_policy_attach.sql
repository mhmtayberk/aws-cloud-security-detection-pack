-- Rule: AdministratorAccess Policy Attached
-- Description: Detects attachment of the widespread AdministratorAccess policy.
-- Severity: High
-- MITRE: T1098

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.policyArn') AS policy_arn,
  json_extract_scalar(requestParameters, '$.userName') AS target_user,
  json_extract_scalar(requestParameters, '$.roleName') AS target_role,
  json_extract_scalar(requestParameters, '$.groupName') AS target_group,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName IN ('AttachUserPolicy', 'AttachGroupPolicy', 'AttachRolePolicy')
  AND json_extract_scalar(requestParameters, '$.policyArn') LIKE '%:iam::aws:policy/AdministratorAccess'
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '') -- Exclude AWS Service actions
ORDER BY
  eventTime DESC;
