-- Rule: Security Group Modification (Broad)
-- Description: Tracks lifecycle events for Security Groups (Create/Delete/Egress)
-- Severity: Low/Informational

SELECT
  eventTime,
  eventName,
  requestParameters,
  userIdentity.arn AS actor_arn,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventSource = 'ec2.amazonaws.com'
  AND eventName IN ('AuthorizeSecurityGroupIngress', 'CreateSecurityGroup')
  AND (
    requestParameters LIKE '%0.0.0.0/0%'
    OR requestParameters LIKE '%::/0%'
  )
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '')
ORDER BY
  eventTime DESC;
