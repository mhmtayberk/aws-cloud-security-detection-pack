-- Rule: IAM Policy Modification or Detachment
-- Description: Detects removal of IAM policies (potential defense evasion or impact)
-- Severity: Medium

SELECT
  eventTime,
  eventName,
  requestParameters,
  userIdentity.arn AS actor_arn,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName IN (
    'PutUserPolicy', 'PutGroupPolicy', 'PutRolePolicy',
    'AttachUserPolicy', 'AttachGroupPolicy', 'AttachRolePolicy',
    'DetachUserPolicy', 'DetachGroupPolicy', 'DetachRolePolicy',
    'DeleteUserPolicy', 'DeleteGroupPolicy', 'DeleteRolePolicy',
    'DeletePolicy', 'DeletePolicyVersion'
  )
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '')
ORDER BY
  eventTime DESC;
