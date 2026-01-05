-- Rule: S3 Replication Rule Created
-- Description: Detects potential bulk exfiltration via S3 Replication features.
-- Severity: High
-- MITRE: T1537

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.bucketName') AS source_bucket,
  json_extract_scalar(requestParameters, '$.replicationConfiguration.Role') AS replication_role,
  -- Note: Destination details are deep in the XML/JSON structure of replicationConfiguration
  requestParameters,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'PutBucketReplication'
ORDER BY
  eventTime DESC;
