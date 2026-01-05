-- Rule: S3 Data Destruction via Lifecycle Rule
-- Description: Detects "Time-bomb" deletion rules on buckets.
-- Severity: Critical
-- MITRE: T1485

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS bucket_name,
  -- The lifecycle config is complex XML/JSON, manual review of the payload is often needed
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'PutBucketLifecycle'
ORDER BY
  eventTime DESC;
