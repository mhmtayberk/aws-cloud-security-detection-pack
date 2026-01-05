-- Rule: Security Group Ingress Opened to World (SSH/RDP)
-- Description: Detects exposure of RDP or SSH ports to the entire internet.
-- Severity: Critical
-- MITRE: T1190

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.groupId') AS security_group_id,
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'AuthorizeSecurityGroupIngress'
  AND requestParameters LIKE '%0.0.0.0/0%' 
  AND (
      requestParameters LIKE '%fromPort": 22,%' 
      OR requestParameters LIKE '%toPort": 22,%'
      OR requestParameters LIKE '%fromPort": 3389,%'
      OR requestParameters LIKE '%toPort": 3389,%'
  )
  -- Note: Correlation with 'RevokeSecurityGroupIngress' by same user within 1 minute
  -- would suggest automated testing (e.g. Terraform validation), but for safety we alert on OPEN.
ORDER BY
  eventTime DESC;
