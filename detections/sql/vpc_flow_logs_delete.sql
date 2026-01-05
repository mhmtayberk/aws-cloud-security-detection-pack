-- Rule: VPC Flow Logs Deleted
-- Description: Detects deletion of network visibility logs.
-- Severity: High
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.flowLogIds') AS flow_log_ids,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'DeleteFlowLogs'
ORDER BY
  eventTime DESC;
