-- Rule: CloudTrail Logging Disabled or Deleted
-- Description: Detects critical defense evasion where audit logs are disabled.
-- Severity: Critical
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.name') AS trail_name,
  sourceIPAddress,
  userAgent,
  requestParameters
FROM
  cloudtrail_logs
WHERE
  eventSource = 'cloudtrail.amazonaws.com'
  AND (
    eventName IN ('StopLogging', 'DeleteTrail')
    OR (
      eventName = 'UpdateTrail'
      AND json_extract_scalar(requestParameters, '$.isLogging') = 'false'
    )
  )
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '') -- Exclude AWS Service actions
ORDER BY
  eventTime DESC;
