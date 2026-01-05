-- Rule: IAM Access Key Created for Another User
-- Description: Detects creation of access keys where a specific target user is defined.
-- Severity: High
-- MITRE: T1098

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.userName') AS target_user,
  responseElements,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'CreateAccessKey'
  AND json_extract_scalar(requestParameters, '$.userName') IS NOT NULL
  -- Optional: Exclude if the actor name matches the target (requires complex string parsing in SQL)
  -- Generally, providing the userName parameter explicitly is rare for self-service
ORDER BY
  eventTime DESC;
