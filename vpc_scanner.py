
# import boto3
# from botocore.exceptions import ClientError, BotoCoreError

# def scan_vpcs():
#     print("=" * 55)
#     print("AWS CLOUD NETWORK SECURITY SCANNER")
#     print("=" * 55)

#     try:
#         # Connect to AWS EC2 in Mumbai region
#         ec2 = boto3.client("ec2", region_name="ap-south-1")

#         # Retrieve existing VPC information
#         response = ec2.describe_vpcs()

#         vpcs = response["Vpcs"]

#         if not vpcs:
#             print("No VPCs found in this region.")
#             return

#         print(f"\nTotal VPCs found: {len(vpcs)}\n")

#         for vpc in vpcs:
#             print("-" * 45)
#             print(f"VPC ID       : {vpc['VpcId']}")
#             print(f"CIDR Block   : {vpc['CidrBlock']}")
#             print(f"State        : {vpc['State']}")
#             print(f"Is Default   : {vpc['IsDefault']}")

#         print("\nVPC discovery completed successfully.")

#     except ClientError as error:
#         print("AWS API error:", error)

#     except BotoCoreError as error:
#         print("AWS connection error:", error)


# if __name__ == "__main__":
#     scan_vpcs()



import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError, BotoCoreError

REGION = "ap-south-1"


def main():
    print("AWS CLOUD NETWORK SECURITY SCANNER")
    print(f"Region: {REGION}")

    try:
        ec2 = boto3.client("ec2", region_name=REGION)

        # Collect VPC information
        vpc_response = ec2.describe_vpcs()
        vpcs = []

        for vpc in vpc_response["Vpcs"]:
            vpcs.append({
                "vpc_id": vpc["VpcId"],
                "cidr": vpc["CidrBlock"],
                "state": vpc["State"],
                "is_default": vpc["IsDefault"]
            })

        # Collect Security Group information
        sg_response = ec2.describe_security_groups()
        security_groups = []
        findings = []

        for sg in sg_response["SecurityGroups"]:
            security_groups.append({
                "group_id": sg["GroupId"],
                "group_name": sg["GroupName"],
                "vpc_id": sg.get("VpcId"),
                "inbound_rule_count": len(sg["IpPermissions"])
            })

            for rule in sg["IpPermissions"]:
                protocol = rule.get("IpProtocol")
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                sources = [
                    item["CidrIp"]
                    for item in rule.get("IpRanges", [])
                ]

                sources += [
                    item["CidrIpv6"]
                    for item in rule.get("Ipv6Ranges", [])
                ]

                public_sources = [
                    source for source in sources
                    if source in ["0.0.0.0/0", "::/0"]
                ]

                if not public_sources:
                    continue

                if protocol == "-1":
                    risk = "HIGH"
                    description = "All traffic publicly allowed"

                elif (
                    protocol == "tcp"
                    and from_port is not None
                    and to_port is not None
                    and from_port <= 22 <= to_port
                ):
                    risk = "HIGH"
                    description = "SSH publicly accessible"

                elif (
                    protocol == "tcp"
                    and from_port is not None
                    and to_port is not None
                    and from_port <= 3389 <= to_port
                ):
                    risk = "HIGH"
                    description = "RDP publicly accessible"

                else:
                    continue

                findings.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "risk": risk,
                    "description": description,
                    "public_sources": public_sources,
                    "protocol": protocol,
                    "from_port": from_port,
                    "to_port": to_port
                })

        # Build report
        report = {
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "region": REGION,
            "vpc_count": len(vpcs),
            "security_group_count": len(security_groups),
            "high_risk_findings": len(findings),
            "vpcs": vpcs,
            "security_groups": security_groups,
            "findings": findings
        }

        # Save JSON report
        with open("scan_report.json", "w") as file:
            json.dump(report, file, indent=4)

        print("\n========== SCAN SUMMARY ==========")
        print(f"VPCs found: {len(vpcs)}")
        print(f"Security Groups found: {len(security_groups)}")
        print(f"High-risk findings: {len(findings)}")
        print("Report saved: scan_report.json")
        print("Scan completed successfully.")

    except ClientError as error:
        print("AWS API error:", error)

    except BotoCoreError as error:
        print("AWS connection error:", error)

    except OSError as error:
        print("Report file error:", error)


if __name__ == "__main__":
    main()
