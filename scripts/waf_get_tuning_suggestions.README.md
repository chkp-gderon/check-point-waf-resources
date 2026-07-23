# WAF Get Tuning Suggestions

This script retrieves and lists all Web Application Firewall (WAF) tuning suggestions for each asset in your Check Point CloudGuard environment.

## Purpose
The goal of the script is to list all tuning suggestions per asset, helping you identify recommended actions for improving your WAF configuration.

## Usage
Run the script using Python:

```
python waf_get_tuning_suggestions.py
```

## Expected Output
For each asset (except "Any Service"), the script prints its name and ID, followed by a list of tuning suggestions. Each suggestion includes:
- Event Title
- Severity
- Decision
- Attack Types
- Log Query
- Policy Version
- Event Type

Example output:

```
Asset: Juiceshop (ID: 0ac8def0-c136-e602-b996-4a7e57a0b0e8)
Tuning Suggestions:
  - Event Title: amp-cache-transform
    Severity: critical
    Decision: undecided
    Attack Types: Path Traversal, SQL Injection
    Log Query: eventseverity:Critical and assetname:"Juiceshop" and matchedparameter:"amp-cache-transform"
    Policy Version: 0
    Event Type: parameterName
```

## Configuration
Update the `CLIENT_ID` and `ACCESS_KEY` variables in the script with your actual credentials before running.

## Requirements
- Python 3.x
- `requests` library (install with `pip install requests`)

## Disclaimer
This script is for demonstration and operational use with Check Point CloudGuard WAF APIs. Handle your credentials securely.
