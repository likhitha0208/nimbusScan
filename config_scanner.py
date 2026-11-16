
import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# AWS region
REGION = "ap-south-1"

# Connect to AWS Config
config = boto3.client(
    "config",
    region_name=REGION
)

# Report structure
report = {
    "scan_time": datetime.now(timezone.utc).isoformat(),
    "region": REGION,
    "recorders": [],
    "recording_status": [],
    "rules_scanned": 0,
    "compliance_summary": {
        "COMPLIANT": 0,
        "NON_COMPLIANT": 0,
        "INSUFFICIENT_DATA": 0,
        "OTHER": 0
    },
    "rules": [],
    "findings": []
}


# STEP 1: Check configuration recorders
def scan_recorders():

    print("\nChecking AWS Config recorders...")

    response = config.describe_configuration_recorders()

    recorders = response.get(
        "ConfigurationRecorders", []
    )

    for recorder in recorders:

        report["recorders"].append({
            "name": recorder.get("name"),
            "role_arn": recorder.get("roleARN"),
            "recording_group": recorder.get("recordingGroup")
        })

    if not recorders:

        print("No configuration recorder found.")
        return False

    # Check whether recording is active
    status_response = config.describe_configuration_recorder_status()

    statuses = status_response.get(
        "ConfigurationRecordersStatus", []
    )

    for status in statuses:

        report["recording_status"].append({
            "name": status.get("name"),
            "recording": status.get("recording"),
            "last_status": status.get("lastStatus"),
            "last_error": status.get("lastErrorMessage")
        })

        print(
            "Recorder:",
            status.get("name"),
            "| Recording:",
            status.get("recording")
        )

    return True


# STEP 2: Scan configuration rules
def scan_rules():

    print("\nScanning AWS Config rules...")

    paginator = config.get_paginator(
        "describe_config_rules"
    )

    rules_found = False

    for page in paginator.paginate():

        for rule in page.get("ConfigRules", []):

            rules_found = True

            rule_name = rule.get("ConfigRuleName")

            response = config.describe_compliance_by_config_rule(
                ConfigRuleNames=[rule_name]
            )

            compliance_items = response.get(
                "ComplianceByConfigRules", []
            )

            compliance = "INSUFFICIENT_DATA"

            if compliance_items:

                compliance = compliance_items[0].get(
                    "Compliance", {}
                ).get(
                    "ComplianceType",
                    "OTHER"
                )

            if compliance not in report["compliance_summary"]:
                compliance = "OTHER"

            report["compliance_summary"][compliance] += 1
            report["rules_scanned"] += 1

            rule_details = {
                "rule_name": rule_name,
                "source": rule.get("Source", {}).get("Owner"),
                "state": rule.get("ConfigRuleState"),
                "compliance": compliance
            }

            report["rules"].append(rule_details)

            print(
                "Rule:",
                rule_name,
                "| Compliance:",
                compliance
            )

    if not rules_found:
        print("No AWS Config rules found.")


# STEP 3: Main function
def main():

    try:

        print("========== AWS CONFIG SECURITY SCANNER ==========")

        recorder_exists = scan_recorders()

        if recorder_exists:
            scan_rules()

        else:
            print(
                "\nSkipping rule scan because no recorder exists."
            )

        # Save report
        with open("config_report.json", "w") as file:

            json.dump(
                report,
                file,
                indent=4
            )

        print("\n========== SCAN SUMMARY ==========")

        print("Region:", REGION)

        print(
            "Recorders found:",
            len(report["recorders"])
        )

        print(
            "Rules scanned:",
            report["rules_scanned"]
        )

        print(
            "Compliance summary:",
            report["compliance_summary"]
        )

        print("\nReport saved as config_report.json")

    except ClientError as error:

        print("\nAWS API ERROR:", error)

        print(
            "Check whether your IAM user has AWS Config read permissions."
        )


if __name__ == "__main__":
    main()
