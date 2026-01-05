-- Rule: GuardDuty Detector Deleted
-- Description: Detects the deletion of the primary GuardDuty detection engine.
-- Severity: High
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.detectorId') AS detector_id,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventSource = 'guardduty.amazonaws.com'
  AND (
    eventName = 'DeleteDetector'
    OR (
      eventName = 'UpdateDetector'
      AND json_extract_scalar(requestParameters, '$.enable') = 'false'
    )
  )
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '') -- Exclude AWS Service actions
ORDER BY
  eventTime DESC;
