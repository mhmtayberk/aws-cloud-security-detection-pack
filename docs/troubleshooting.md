# Troubleshooting Guide

## Athena & SQL Errors

### `HIVE_PARTITION_SCHEMA_MISMATCH`
*   **Cause:** The schema in your Athena table definition differs from the actual Parquet/JSON data in S3.
*   **Fix:** Drop and recreate the table. Ensure your `CREATE TABLE` statement matches the CloudTrail version you are using.
*   **Check:** Run `MSCK REPAIR TABLE cloudtrail_logs` to ensure partitions are loaded.

### Queries Timing Out
*   **Cause:** Scanning too much data (Full Table Scan).
*   **Fix:**
    *   **Always** use partitions: `WHERE year = '2024' AND month = '01'`.
    *   **Limit Scopes:** Add `AND region = 'us-east-1'` if you only care about one region.
    *   **Test Small:** Use `LIMIT 10` when developing new queries.

## JSON & Logic Issues

### "Invalid JSON" Validation Error
*   **Cause:** Trailing commas or missing brackets in `.json` files.
*   **Fix:** Use a linter. `cat detections/json/my_rule.json | jq .`
    *   If `jq` fails, the JSON is invalid.

### `readOnly` Field Confusion
*   **Context:** CloudTrail has `readOnly=true` (Get/List/Describe) and `readOnly=false` (Create/Modify/Delete).
*   **Trap:** Some "Read" actions can be dangerous (e.g., `GetSecretValue`). Do not blindly filter out all `readOnly=true` events unless you are sure.

## Data Latency vs. Event Time

*   **Observation:** You ran a simulation at 10:00 AM, but the alert appeared at 10:15 AM.
*   **Explanation:**
    *   **eventTime:** The actual time the API call happened (10:00).
    *   **deliveryTime:** When CloudTrail delivered the log file to S3 (typically +5 to +15 mins).
    *   **Query Time:** When you ran the Athena query.
*   **Impact:** Real-time alerting on CloudTrail has a hard floor of ~5 minutes latency. Design your response SLAs accordingly.

## False Positives & Tuning

### No Alerts Triggering?
1.  **Check Scope:** Did the event happen in the Region you are querying?
2.  **Filter Logic:** Did you filter out `userIdentity.type = 'AssumedRole'`? Terraform often runs as an Assumed Role.
3.  **Raw Data Check:**
    ```sql
    SELECT * FROM cloudtrail_logs
    WHERE eventName = 'YourTargetEvent'
    ORDER BY eventTime DESC LIMIT 1;
    ```
    Compare the raw JSON structure with your query fields. AWS field names (especially inside `requestParameters`) can vary by API version.
