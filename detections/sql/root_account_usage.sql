-- Rule: Root Account Usage Detected
-- Description: Identifies any activity performed by the AWS Root account.
-- Severity: Critical
-- MITRE: T1078.001

SELECT
  eventTime,
  eventName,
  eventSource,
  awsRegion,
  sourceIPAddress,
  userAgent,
  userIdentity.arn AS user_arn,
  requestParameters,
  responseElements
FROM
  cloudtrail_logs
WHERE
  userIdentity.type = 'Root'
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '') -- Exclude AWS service-on-behalf actions
  AND eventType != 'AwsServiceEvent' -- Exclude internal AWS service events
  AND sourceIPAddress != 'DNS Resolver' 
  AND eventName NOT IN ('ConsoleLogin') -- Handled by separate rule
ORDER BY
  eventTime DESC;
