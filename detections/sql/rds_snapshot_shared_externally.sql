-- Rule: RDS Snapshot Shared Externally
-- Description: Detects exfiltration of database backups via permission changes.
-- Severity: Critical
-- MITRE: T1537

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.dBSnapshotIdentifier') AS snapshot_id,
  -- valuesToAdd contains the account IDs the snapshot is shared with
  json_extract(requestParameters, '$.valuesToAdd') AS shared_with_accounts,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'ModifyDBSnapshotAttribute'
  AND json_extract_scalar(requestParameters, '$.attributeName') = 'restore'
  AND requestParameters LIKE '%"valuesToAdd"%'
  -- 'all' check for public sharing, though RDS often prevents this via other controls, API allows it
  AND (
      requestParameters LIKE '%"all"%' 
      OR json_array_length(json_extract(requestParameters, '$.valuesToAdd')) > 0
  )
ORDER BY
  eventTime DESC;
