import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

REGION = "ap-south-1"

guardduty = boto3.client(
    "guardduty",
    region_name=REGION
)

report = {
    "scan_time": datetime.now(timezone.utc).isoformat(),
    "region": REGION,
    "guardduty_enabled": False,
    "findings_scanned": 0,
    "findings": []
}


def scan_guardduty():
    print("Checking GuardDuty detector...")

    response = guardduty.list_detectors()
    detector_ids = response.get("DetectorIds", [])

    if not detector_ids:
        print("GuardDuty is not enabled in this region.")
        print("No detector found. No changes made.")
        return

    report["guardduty_enabled"] = True

    detector_id = detector_ids[0]
    print("Detector found:", detector_id)

    paginator = guardduty.get_paginator("list_findings")

    for page in paginator.paginate(
        DetectorId=detector_id
    ):
        finding_ids = page.get("FindingIds", [])

        if not finding_ids:
            continue

        details = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )

        for finding in details.get("Findings", []):
            report["findings_scanned"] += 1

            severity = finding.get("Severity", {}).get(
                "Label", "UNKNOWN"
            )

            resource = finding.get("Resource", {})
            resource_type = resource.get("ResourceType", "UNKNOWN")

            finding_details = {
                "finding_id": finding.get("Id"),
                "type": finding.get("Type"),
                "title": finding.get("Title"),
                "description": finding.get("Description"),
                "severity": severity,
                "resource_type": resource_type,
                "region": finding.get("Region"),
                "account_id": finding.get("AccountId"),
                "created_at": finding.get("CreatedAt"),
                "updated_at": finding.get("UpdatedAt")
            }

            report["findings"].append(finding_details)


def main():
    try:
        scan_guardduty()

        with open("guardduty_report.json", "w") as file:
            json.dump(report, file, indent=4)

        print("\n========== GUARDDUTY SCAN ==========")
        print("Region:", REGION)
        print("GuardDuty enabled:", report["guardduty_enabled"])
        print("Findings scanned:", report["findings_scanned"])
        print("Report saved as guardduty_report.json")

    except ClientError as error:
        print("\nAWS API error:", error)
        print("Check GuardDuty read permissions.")

        
if __name__ == "__main__":
    main()
