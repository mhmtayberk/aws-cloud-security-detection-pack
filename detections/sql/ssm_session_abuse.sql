-- Rule: Suspicious SSM Session Manager Connection
-- Description: Detects interactive shell sessions via SSM (SSH replacement)
-- Severity: Medium

SELECT
  eventTime,
  eventName,
  eventSource,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.target') AS instance_id,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventSource = 'ssm.amazonaws.com'
  AND eventName = 'StartSession'
ORDER BY
  eventTime DESC;
