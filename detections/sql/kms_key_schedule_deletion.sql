-- Rule: KMS Key Scheduled for Deletion
-- Description: Detects destructive action against encryption keys.
-- Severity: Critical
-- MITRE: T1485

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.keyId') AS key_id,
  json_extract_scalar(requestParameters, '$.pendingWindowInDays') AS pending_window,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'ScheduleKeyDeletion'
ORDER BY
  eventTime DESC;
