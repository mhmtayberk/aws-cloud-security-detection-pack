-- Rule: STS Decode Authorization Message
-- Description: Detects an actor attempting to understand IAM permission failures (Reconnaissance).
-- Severity: Medium
-- MITRE: T1087

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  -- encodedMessage is usually in parameters, but we just need to know they called the API
  sourceIPAddress,
  userAgent,
  errorMessage -- Should be null for success
FROM
  cloudtrail_logs
WHERE
  eventName = 'DecodeAuthorizationMessage'
ORDER BY
  eventTime DESC;
