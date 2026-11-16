
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

INPUT_FILE = REPORT_DIR / "combined_security_report.json"
OUTPUT_FILE = REPORT_DIR / "security_analysis_report.json"


SEVERITY_MAP = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFORMATIONAL",
    "INFORMATIONAL": "INFORMATIONAL",
    "REVIEW": "REVIEW"
}


def get_recommendation(service, finding):
    """Generate a recommendation based on the finding."""

    description = str(finding.get("finding", "")).lower()
    check = str(finding.get("check", "")).lower()

    if service == "nacl":
        return (
            "Inspect the NACL rule, its subnet associations, "
            "and whether this is the default NACL. Restrict "
            "unnecessary inbound traffic if appropriate."
        )

    if service == "iam":
        return (
            "Review the attached IAM policy. Replace broad "
            "permissions with least-privilege actions and "
            "resource scopes where possible."
        )

    if service == "cloudtrail":
        return (
            "Review the event identity, timestamp, source IP, "
            "and API operation. Confirm whether the denied "
            "request was expected."
        )

    if service == "vpc":
        return (
            "Review the affected VPC or security group and "
            "restrict unnecessary network exposure."
        )

    if service == "s3":
        return (
            "Review bucket permissions, public access settings, "
            "encryption and versioning requirements."
        )

    if service == "guardduty":
        return (
            "Investigate the GuardDuty finding and validate "
            "the affected resource and activity."
        )

    if service == "config":
        return (
            "Review the AWS Config rule and the resource's "
            "compliance status. Investigate non-compliant resources."
        )

    return "Manually investigate this finding."


def normalize_finding(service, finding):
    """Convert different scanner findings into one format."""

    if not isinstance(finding, dict):
        finding = {"finding": str(finding)}

    original_risk = str(
        finding.get("risk")
        or finding.get("severity")
        or "REVIEW"
    ).upper()

    severity = SEVERITY_MAP.get(original_risk, "REVIEW")

    # An NACL allow-all finding needs validation because
    # the original report does not identify default/custom ACL.
    validation_required = False

    if service == "nacl" and severity == "HIGH":
        validation_required = True

    description = (
        finding.get("finding")
        or finding.get("reason")
        or finding.get("description")
        or "No description provided"
    )

    return {
        "service": service.upper(),
        "severity": severity,
        "original_risk": original_risk,
        "identity": finding.get("identity"),
        "resource": (
            finding.get("acl_id")
            or finding.get("resource")
            or finding.get("bucket")
        ),
        "description": description,
        "recommendation": get_recommendation(service, finding),
        "validation_required": validation_required,
        "source_finding": finding
    }


def main():

    print("\n====================================")
    print(" AWS SECURITY RISK ANALYSIS ENGINE")
    print("====================================")

    if not INPUT_FILE.exists():
        print("[ERROR] Combined report not found.")
        print("Run index.py first.")
        return

    try:
        with INPUT_FILE.open("r", encoding="utf-8") as file:
            combined_data = json.load(file)
    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Could not read input report: {error}")
        return

    reports = combined_data.get("reports", {})

    analyzed_findings = []
    service_summary = {}

    for filename, report in reports.items():

        service = filename.replace("_report.json", "")
        service = service.replace("_analyzer", "")

        if not isinstance(report, dict):
            continue

        findings = report.get("findings", [])

        if not isinstance(findings, list):
            findings = []

        service_summary[service.upper()] = {
            "findings_count": len(findings),
            "status": (
                "FINDINGS DETECTED"
                if findings
                else "NO FINDINGS REPORTED"
            )
        }

        for finding in findings:
            analyzed = normalize_finding(service, finding)
            analyzed_findings.append(analyzed)

    severity_counts = Counter(
        item["severity"] for item in analyzed_findings
    )

    summary = {
        "total_findings": len(analyzed_findings),
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "review": severity_counts["REVIEW"],
        "informational": severity_counts["INFORMATIONAL"]
    }

    final_report = {
        "project": "AWS Cloud Network Security Scanner",
        "analysis_time": datetime.now(timezone.utc).isoformat(),
        "input_file": INPUT_FILE.name,
        "summary": summary,
        "service_summary": service_summary,
        "findings": analyzed_findings,
        "limitations": [
            "Analysis uses existing scanner reports.",
            "Empty findings do not prove that a service or resource is secure.",
            "NACL findings require default/custom ACL validation.",
            "GuardDuty and AWS Config may be inactive.",
            "Recommendations require human review before remediation."
        ]
    }

    try:
        with OUTPUT_FILE.open("w", encoding="utf-8") as file:
            json.dump(final_report, file, indent=4, default=str)
    except OSError as error:
        print(f"[ERROR] Could not save report: {error}")
        return

    print("\n========== SECURITY SUMMARY ==========")

    for key, value in summary.items():
        print(f"{key.replace('_', ' ').title():22}: {value}")

    print("\n========== SERVICE SUMMARY ==========")

    for service, details in service_summary.items():
        print(
            f"{service:15} | "
            f"{details['findings_count']} findings | "
            f"{details['status']}"
        )

    print("\nAnalysis completed successfully!")
    print(f"Report saved: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
