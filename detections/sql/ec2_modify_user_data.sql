-- Rule: EC2 Instance UserData Modified
-- Description: Detects injection of malicious scripts into EC2 startup configuration.
-- Severity: High
-- MITRE: T1059.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.instanceId') AS instance_id,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'ModifyInstanceAttribute'
  AND json_extract_scalar(requestParameters, '$.attribute') = 'userData'
ORDER BY
  eventTime DESC;
