
import boto3
import json
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError

# Connect to CloudTrail in the Mumbai region
cloudtrail = boto3.client(
    "cloudtrail",
    region_name="ap-south-1"
)

# Retrieve the previous seven days
end_time = datetime.now(timezone.utc)
start_time = end_time - timedelta(days=7)

# Events that deserve additional investigation
SENSITIVE_EVENTS = {
    "CreateUser",
    "CreateAccessKey",
    "AttachUserPolicy",
    "AttachRolePolicy",
    "PutUserPolicy",
    "PutRolePolicy",
    "CreateLoginProfile",
    "UpdateAssumeRolePolicy",
    "AuthorizeSecurityGroupIngress",
    "RunInstances",
    "DeleteBucket",
    "StopLogging",
    "DeleteTrail"
}

report = {
    "scan_time": end_time.isoformat(),
    "region": "ap-south-1",
    "period": "Last 7 days",
    "events_scanned": 0,
    "findings": [],
    "events": []
}


def analyze_event(event):
    event_name = event.get("eventName", "Unknown")
    identity = event.get("userIdentity", {})

    username = (
        identity.get("userName")
        or identity.get("principalId")
        or identity.get("arn")
        or identity.get("type")
        or "Unknown"
    )

    # Detect unsuccessful API operations
    error_code = event.get("errorCode")
    failed_login = False

    if event_name == "ConsoleLogin":
        response = event.get("responseElements") or {}
        failed_login = (
            isinstance(response, dict)
            and response.get("ConsoleLogin") == "Failure"
        )

    finding = None

    if error_code:
        finding = {
            "risk": "REVIEW",
            "identity": username,
            "event": event_name,
            "reason": f"API operation failed: {error_code}"
        }

    elif failed_login:
        finding = {
            "risk": "REVIEW",
            "identity": username,
            "event": event_name,
            "reason": "Failed console login detected"
        }

    elif event_name in SENSITIVE_EVENTS:
        finding = {
            "risk": "REVIEW",
            "identity": username,
            "event": event_name,
            "reason": "Sensitive account or infrastructure operation"
        }

    if finding:
        report["findings"].append(finding)

    report["events"].append({
        "event_time": event.get("eventTime"),
        "event_name": event_name,
        "event_source": event.get("eventSource"),
        "username": username,
        "source_ip": event.get("sourceIPAddress"),
        "aws_region": event.get("awsRegion"),
        "error_code": error_code,
        "user_agent": event.get("userAgent"),
        "finding": finding
    })


def scan_events():
    print("Scanning CloudTrail events...")

    paginator = cloudtrail.get_paginator("lookup_events")

    for page in paginator.paginate(
        StartTime=start_time,
        EndTime=end_time,
        PaginationConfig={"PageSize": 50}
    ):
        for record in page.get("Events", []):
            raw_event = record.get("CloudTrailEvent")

            if not raw_event:
                continue

            event = json.loads(raw_event)

            report["events_scanned"] += 1
            analyze_event(event)


def main():
    try:
        scan_events()

        with open("cloudtrail_report.json", "w") as file:
            json.dump(report, file, indent=4)

        print("\n========== CLOUDTRAIL SCAN ==========")
        print("Region:", report["region"])
        print("Events scanned:", report["events_scanned"])
        print("Potential findings:", len(report["findings"]))

        for finding in report["findings"]:
            print(finding)

        print("\nReport saved as cloudtrail_report.json")

    except ClientError as error:
        print("\nAWS API error:", error)
        print("Check CloudTrail permissions and region.")

    except json.JSONDecodeError as error:
        print("\nCould not parse an event:", error)


if __name__ == "__main__":
    main()
