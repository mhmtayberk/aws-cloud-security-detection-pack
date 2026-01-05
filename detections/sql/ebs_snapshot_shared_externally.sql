-- Rule: EBS Snapshot Shared Externally
-- Description: Detects exfiltration of disk images via permission changes.
-- Severity: Critical
-- MITRE: T1537

SELECT
  eventTime,
  eventName,
  userIdentity.arn AS actor_arn,
  json_extract_scalar(requestParameters, '$.snapshotId') AS snapshot_id,
  -- Extracting who it was shared with (Account ID or 'all' for public)
  json_extract(requestParameters, '$.createVolumePermission') AS permissions_changes,
  sourceIPAddress,
  userAgent
FROM
  cloudtrail_logs
WHERE
  eventName = 'ModifySnapshotAttribute'
  AND (
    requestParameters LIKE '%"add":%' 
    AND (
       requestParameters LIKE '%"group": "all"%' -- Shared Publicly
       OR requestParameters LIKE '%"userId":%'   -- Shared with specific account
    )
  )
  -- Filter: Add 'AND requestParameters NOT LIKE "%TRUSTED_ACCOUNT_ID%"' to suppress known DR accounts
ORDER BY
  eventTime DESC;
