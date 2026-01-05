-- Rule: Suspicious Cross-Account Role Assumption
-- Description: Detects Assumed Role calls from untrusted external accounts
-- Severity: High

SELECT
  eventTime,
  eventName,
  userIdentity.accountId AS source_account_id,
  userIdentity.arn AS source_arn,
  requestParameters, -- Contains roleArn being assumed
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'AssumeRole'
  AND eventSource = 'sts.amazonaws.com'
  AND errorCode IS NULL
  AND userIdentity.type = 'AWSAccount'
  -- TRUSTED ACCOUNT WHITELIST
  AND userIdentity.accountId NOT IN ('123456789012') 
ORDER BY
  eventTime DESC;
