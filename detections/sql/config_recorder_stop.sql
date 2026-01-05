-- Rule: AWS Config Configuration Recorder Stopped
-- Description: Detects disabling of resource history tracking.
-- Severity: Medium
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.configurationRecorderName') AS recorder_name,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName IN ('StopConfigurationRecorder', 'DeleteConfigurationRecorder')
ORDER BY
  eventTime DESC;
