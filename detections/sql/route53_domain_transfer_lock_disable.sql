-- Rule: Route53 Domain Transfer Lock Disabled
-- Description: Detects potential domain hijacking attempts.
-- Severity: Critical
-- MITRE: T1496

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.domainName') AS domain_name,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'DisableDomainTransferLock'
ORDER BY
  eventTime DESC;
