# NimbusScan

*AWS Cloud Network Security Scanner*

**Repository:** https://github.com/likhitha0208/nimbusScan

A read-only security scanner for an AWS account, built with Python and boto3, with a local web dashboard for reviewing the results.

It runs seven scanners, merges their JSON output, classifies the findings by severity, and shows everything in a dark SOC-style dashboard.

## What it scans

| Scanner | Script | Checks |
|---|---|---|
| VPC & Security Groups | `vpc_scanner.py` | VPCs, security group rules open to the internet |
| Network ACLs | `nacl_scanner.py` | ACL rules allowing all traffic from/to `0.0.0.0/0` |
| IAM | `iam_scanner.py` | Wildcard actions/resources, broad managed policies, MFA, access keys |
| S3 | `S3_scanner.py` | Public access, ACLs, bucket policies, encryption, versioning |
| CloudTrail | `cloudtrail_analyzer.py` | Failed/denied API calls and risky events (last 7 days) |
| GuardDuty | `guardduty_scanner.py` | Threat-detection findings (if GuardDuty is enabled) |
| AWS Config | `config_scanner.py` | Recorder status and rule compliance (if Config is enabled) |

`index.py` merges the reports and `security_analyzer.py` normalises every finding into a severity (Critical / High / Medium / Low / Review / Informational) with a recommendation.

## Setup

```bash
pip install -r requirements.txt
aws configure          # use an IAM identity with the read-only policy below
```

Scan with an IAM user or role that has read-only access (for example the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies, or a custom policy covering the services above). The scanner only makes `Describe*`, `List*` and `Get*` calls and never changes anything in your account.

## Usage

```bash
python run_all.py            # run every scanner and build the analysis report
python dashboard.py          # open the dashboard on existing reports
python dashboard.py --scan   # scan first, then open the dashboard
```

Reports are written to `reports/` (git-ignored).

### Opening the dashboard

The dashboard is not hosted online; it runs on your own machine at `http://127.0.0.1:8000/dashboard.html`. Start it with `python dashboard.py`, which opens your browser through a one-time access link. Opening the address directly (or from a bookmark) shows "Access denied" by design, because the reports contain real account details. Run the command again to get a fresh link.

## Dashboard

Pages: Dashboard, Scan Results, Findings, AWS Services, Reports, Settings / About.

- All numbers are calculated from the generated JSON reports, nothing is hard-coded.
- Filter findings by severity, AWS service and risk category; click a finding for evidence and remediation.
- Export findings as CSV/JSON and download any report.
- Missing reports show "No report available"; services that are not enabled (GuardDuty, Config) are marked **Incomplete**, and reports older than 24 hours trigger a warning.

### Dashboard security

The reports contain real account details, so the local server is locked down: it binds to `127.0.0.1` only, serves an allowlist of files, requires a one-time-token session cookie, checks the Host header, allows GET only, and sends a strict Content-Security-Policy with no third-party resources.

## Limitations

- **REVIEW findings are not confirmed vulnerabilities.** They need manual validation.
- GuardDuty and AWS Config are paid/optional services. If they are not enabled, nothing is scanned for them, which is *not* the same as a clean result.
- Scans cover one region at a time (set in each script).
- The dashboard shows the last scan only; it does not poll AWS live.

## Safety

Never commit `reports/` or any AWS credentials. The `.gitignore` excludes them.
