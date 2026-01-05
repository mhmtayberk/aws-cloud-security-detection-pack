-- Rule: Console Login without MFA
-- Description: Identifies single-factor authentication to the AWS Console.
-- Severity: Medium
-- MITRE: T1078

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS user_arn,
  json_extract_scalar(additionalEventData, '$.MFAUsed') AS mfa_used,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'ConsoleLogin'
  AND json_extract_scalar(responseElements, '$.ConsoleLogin') = 'Success'
  AND json_extract_scalar(additionalEventData, '$.MFAUsed') = 'No'
  -- Exclude SSO/Saml logins as MFA is handled by the IdP (e.g. Okta/AzureAD)
  -- We strictly target local IAM Users where MFA should be enforced by AWS
  AND userIdentity.type = 'IAMUser' 
ORDER BY
  eventTime DESC;
