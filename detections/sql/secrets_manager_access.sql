-- Rule: Secrets Manager Access from Unusual Source
-- Description: GetSecretValue by IAM Users (not service roles)
-- Severity: Low (escalate if from external IP)
-- Tuning: Add sourceIPAddress whitelist for known VPN/office IPs

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  userIdentity.type AS identity_type,
  sourceIPAddress,
  userAgent,
  json_extract_scalar(requestParameters, '$.secretId') AS secret_id
FROM
  cloudtrail_logs
WHERE
  eventSource = 'secretsmanager.amazonaws.com'
  AND eventName = 'GetSecretValue'
  AND errorCode IS NULL
  AND userIdentity.type = 'IAMUser'
  -- Optional: Add IP whitelist
  -- AND sourceIPAddress NOT IN ('203.0.113.0', '198.51.100.0')
ORDER BY
  eventTime DESC;
