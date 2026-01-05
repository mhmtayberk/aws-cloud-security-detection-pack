-- Rule: IAM Role Trust Policy Updated
-- Description: Detects modification of role trust relationships (potential backdoor).
-- Severity: Critical
-- MITRE: T1098

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.roleName') AS role_name,
  json_extract_scalar(requestParameters, '$.policyDocument') AS new_policy_document,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'UpdateAssumeRolePolicy'
ORDER BY
  eventTime DESC;
