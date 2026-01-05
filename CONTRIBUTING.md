# Contributing Guide

## Detection Rule Quality Standards
1.  **Real Fields Only:** Use actual CloudTrail field names (verify via AWS docs or `aws cloudtrail lookup-events`). Do not guess field names.
2.  **Logic Parity:** The JSON rule and the SQL query must implement the exact same detection logic.
3.  **False Positive Documentation:** You must explicitly list known false positives (e.g., "Terraform runs", "AWS Service actions") in the rule metadata.
4.  **Sample Events:** Where possible, include a sanitized sample CloudTrail event in the `examples/` directory.

## PR Process
1.  **Fork** the repository and create a feature branch.
2.  Add your detection rule pair (`.json` and `.sql`) to the `detections/` folders.
3.  Add a sample event to `examples/`.
4.  Update the `README.md` rule table if necessary.
5.  Open a Pull Request with a clear description of the threat scenario.
