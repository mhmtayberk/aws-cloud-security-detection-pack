-- Rule: Unauthorized API Calls (Access Denied)
-- IMPORTANT: This query returns individual events. In production, aggregate by userIdentity.arn
-- and alert only if COUNT(*) > 10 within a 5-minute window. Example:
--   SELECT userIdentity.arn, COUNT(*) as denial_count
--   FROM cloudtrail_logs
--   WHERE errorCode IN ('AccessDenied', 'Client.UnauthorizedOperation')
--   AND eventTime > current_timestamp - interval '5' minute
--   GROUP BY userIdentity.arn
--   HAVING COUNT(*) > 10
-- Description: Detects high volume of Access Denied errors (Reconnaissance)
-- Severity: Medium
-- Note: This rule requires aggregation/thresholding in a SIEM. 
-- The SQL below lists individual events but normally you'd want COUNT(*) > X

SELECT
  eventTime,
  eventName,
  eventSource,
  errorCode,
  errorMessage,
  userIdentity.arn AS actor_arn,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  (errorCode = 'AccessDenied' OR errorCode = 'Client.UnauthorizedOperation')
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '')
ORDER BY
  eventTime DESC;
