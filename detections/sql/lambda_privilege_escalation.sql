-- Rule: Lambda Privilege Escalation via PassRole
-- Description: Detects attaching high-privilege roles to Lambda
-- Severity: Critical

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.role') AS passed_role,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName IN ('CreateFunction20150331', 'UpdateFunctionConfiguration20150331v2', 'CreateFunction', 'UpdateFunctionConfiguration')
  AND requestParameters LIKE '%"role":%' 
  -- Optional: Filter for known admin roles
  -- AND json_extract_scalar(requestParameters, '$.role') LIKE '%Admin%'
ORDER BY
  eventTime DESC;
