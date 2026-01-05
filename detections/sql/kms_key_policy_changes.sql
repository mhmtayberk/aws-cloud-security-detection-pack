-- Rule: KMS Key Policy Modification
-- Description: Detects critical changes to encryption key access policies.
-- Severity: Critical

SELECT
  eventTime,
  eventName,
  eventSource,
  userIdentity.arn AS actor_arn,
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventSource = 'kms.amazonaws.com'
  AND eventName = 'PutKeyPolicy'
ORDER BY
  eventTime DESC;
