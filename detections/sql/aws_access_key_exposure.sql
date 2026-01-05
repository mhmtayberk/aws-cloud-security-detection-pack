-- Rule: Potential AWS Access Key Exposure
-- Description: Detects GetCallerIdentity from potential attackers
-- Severity: High

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'GetCallerIdentity'
  AND userIdentity.type = 'IAMUser'
  -- Filter out internal IPs if possible
  -- AND sourceIPAddress NOT LIKE '10.%'
ORDER BY
  eventTime DESC;
