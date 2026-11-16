
import boto3
import json
from pathlib import Path
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError

REGION = "ap-south-1"

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = REPORT_DIR / "nacl_report.json"


def get_protocol_name(protocol):
    protocols = {
        "-1": "ALL",
        "6": "TCP",
        "17": "UDP",
        "1": "ICMP",
        "58": "ICMPv6"
    }
    return protocols.get(str(protocol), str(protocol))


def scan_network_acls():

    ec2 = boto3.client("ec2", region_name=REGION)
    paginator = ec2.get_paginator("describe_network_acls")

    acls = []

    for page in paginator.paginate():
        acls.extend(page["NetworkAcls"])

    findings = []
    rules_checked = 0

    print("\n========== NETWORK ACL SECURITY SCAN ==========")

    for acl in acls:

        acl_id = acl["NetworkAclId"]
        vpc_id = acl["VpcId"]
        is_default = acl["IsDefault"]

        subnet_ids = [
            association.get("SubnetId")
            for association in acl.get("Associations", [])
        ]

        print(f"\nACL ID: {acl_id}")
        print(f"VPC ID: {vpc_id}")
        print(f"Default ACL: {is_default}")
        print(f"Associated subnets: {subnet_ids}")

        for entry in acl["Entries"]:

            rules_checked += 1

            direction = (
                "OUTBOUND" if entry["Egress"] else "INBOUND"
            )

            action = entry["RuleAction"]
            protocol = str(entry.get("Protocol", "-1"))

            source = entry.get("CidrBlock")
            ipv6 = entry.get("Ipv6CidrBlock")

            public_range = (
                source == "0.0.0.0/0"
                or ipv6 == "::/0"
            )

            port_range = entry.get("PortRange", {})
            start_port = port_range.get("From")
            end_port = port_range.get("To")

            protocol_name = get_protocol_name(protocol)

            # Only investigate rules allowing public traffic.
            if action != "allow" or not public_range:
                continue

            description = None
            risk = None

            if direction == "INBOUND":

                if protocol == "-1":

                    description = (
                        "All inbound traffic allowed from the internet"
                    )

                    # Default NACLs commonly allow all traffic.
                    risk = "REVIEW" if is_default else "HIGH"

                elif protocol == "6" and start_port is not None:

                    if start_port <= 22 <= end_port:
                        description = (
                            "SSH inbound access allowed from the internet"
                        )
                        risk = "HIGH"

                    elif start_port <= 3389 <= end_port:
                        description = (
                            "RDP inbound access allowed from the internet"
                        )
                        risk = "HIGH"

                elif protocol in ("6", "17"):
                    description = (
                        f"Public inbound {protocol_name} access allowed"
                    )
                    risk = "REVIEW"

            else:

                if protocol == "-1":
                    description = (
                        "All outbound traffic allowed to the internet"
                    )
                    risk = "REVIEW"

            if description is None:
                continue

            result = {
                "acl_id": acl_id,
                "vpc_id": vpc_id,
                "is_default": is_default,
                "associated_subnets": subnet_ids,
                "rule_number": entry["RuleNumber"],
                "direction": direction,
                "action": action,
                "protocol": protocol,
                "protocol_name": protocol_name,
                "port_range": {
                    "from": start_port,
                    "to": end_port
                },
                "source": source or ipv6,
                "risk": risk,
                "finding": description
            }

            findings.append(result)

            print(f"\n[{risk}] {description}")
            print(json.dumps(result, indent=2))

    print("\n========== NACL SCAN SUMMARY ==========")
    print(f"Network ACLs scanned: {len(acls)}")
    print(f"Rules inspected: {rules_checked}")
    print(f"Potential findings: {len(findings)}")

    return {
        "scan_time_utc": datetime.now(timezone.utc).isoformat(),
        "region": REGION,
        "network_acl_count": len(acls),
        "rules_checked": rules_checked,
        "findings": findings
    }


if __name__ == "__main__":

    try:
        report = scan_network_acls()

        with OUTPUT_FILE.open("w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print(f"\nReport saved: {OUTPUT_FILE}")

    except (ClientError, BotoCoreError) as error:
        print("\nAWS API error:", error)

    except OSError as error:
        print("\nFile error:", error)
