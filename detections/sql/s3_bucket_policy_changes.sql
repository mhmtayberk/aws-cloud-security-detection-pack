-- Rule: S3 Bucket Policy or ACL Modification
-- Description: Detects potentially dangerous changes to bucket permissions
-- Severity: High

SELECT
  eventTime,
  eventName,
  eventSource,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventSource = 's3.amazonaws.com'
  AND eventName IN (
    'PutBucketPolicy',
    'DeleteBucketPolicy',
    'PutBucketAcl',
    'DeleteBucketAcl'
  )
  AND (userIdentity.invokedBy IS NULL OR userIdentity.invokedBy = '')
ORDER BY
  eventTime DESC;
