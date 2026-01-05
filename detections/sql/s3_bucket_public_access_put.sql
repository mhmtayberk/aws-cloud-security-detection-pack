-- Rule: S3 Bucket Public Access Block Removed
-- Description: Detects disabling of the account or bucket-level Public Access Block.
-- Severity: High
-- MITRE: T1562.001

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'DeleteBucketPublicAccessBlock'
  OR (
    eventName = 'PutBucketPublicAccessBlock'
    AND requestParameters LIKE '%false%' -- Quick check for disabling any of the 4 boolean flags
  )
ORDER BY
  eventTime DESC;
