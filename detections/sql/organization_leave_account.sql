-- Rule: Account Left AWS Organization
-- Description: Detects an account removing itself from Organization management (and SCPs).
-- Severity: Critical
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'LeaveOrganization'
ORDER BY
  eventTime DESC;
