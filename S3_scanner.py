
import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

REGION = "ap-south-1"

s3 = boto3.client("s3", region_name=REGION)


def scan_s3():
    report = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "region": REGION,
        "buckets_scanned": 0,
        "findings": [],
        "bucket_details": []
    }

    buckets = s3.list_buckets()["Buckets"]

    for bucket in buckets:
        name = bucket["Name"]
        report["buckets_scanned"] += 1

        details = {
            "bucket": name,
            "public_access_block": "UNKNOWN",
            "encryption": "UNKNOWN",
            "versioning": "UNKNOWN",
            "public_policy": "UNKNOWN",
            "public_acl": "UNKNOWN"
        }

        def finding(check, risk, message):
            report["findings"].append({
                "bucket": name,
                "check": check,
                "risk": risk,
                "finding": message
            })

        # 1. Public access block
        try:
            config = s3.get_public_access_block(Bucket=name)
            settings = config["PublicAccessBlockConfiguration"]

            blocked = all([
                settings.get("BlockPublicAcls", False),
                settings.get("IgnorePublicAcls", False),
                settings.get("BlockPublicPolicy", False),
                settings.get("RestrictPublicBuckets", False)
            ])

            details["public_access_block"] = (
                "ENABLED" if blocked else "PARTIALLY_DISABLED"
            )

            if not blocked:
                finding(
                    "Public Access Block", "HIGH",
                    "One or more public access protections are disabled"
                )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                details["public_access_block"] = "NOT_CONFIGURED"
                finding(
                    "Public Access Block", "HIGH",
                    "Public access block configuration is missing"
                )
            else:
                details["public_access_block"] = "CHECK_FAILED"

        # 2. Encryption
        try:
            encryption = s3.get_bucket_encryption(Bucket=name)
            rules = encryption["ServerSideEncryptionConfiguration"]["Rules"]

            details["encryption"] = "ENABLED" if rules else "NOT_ENABLED"

        except ClientError as e:
            if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
                details["encryption"] = "NOT_CONFIGURED"
                finding(
                    "Encryption", "MEDIUM",
                    "No explicit bucket encryption configuration found"
                )
            else:
                details["encryption"] = "CHECK_FAILED"

        # 3. Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")
            details["versioning"] = status

            if status != "Enabled":
                finding(
                    "Versioning", "LOW",
                    "Bucket versioning is not enabled"
                )

        except ClientError:
            details["versioning"] = "CHECK_FAILED"

        # 4. Bucket policy
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            policy_data = json.loads(policy["Policy"])

            public_policy = any(
                statement.get("Principal") == "*"
                for statement in policy_data.get("Statement", [])
            )

            details["public_policy"] = (
                "REVIEW_REQUIRED" if public_policy else "NO_WILDCARD_PRINCIPAL"
            )

            if public_policy:
                finding(
                    "Bucket Policy", "HIGH",
                    "Policy contains a wildcard Principal; review conditions and actions"
                )

        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchBucketPolicy":
                details["public_policy"] = "NO_POLICY"
            else:
                details["public_policy"] = "CHECK_FAILED"

        # 5. Bucket ACL
        try:
            acl = s3.get_bucket_acl(Bucket=name)

            public_acl = any(
                grant.get("Grantee", {}).get("URI", "").endswith(
                    ("AllUsers", "AuthenticatedUsers")
                )
                for grant in acl.get("Grants", [])
            )

            details["public_acl"] = (
                "PUBLIC_GRANT_FOUND" if public_acl else "NO_PUBLIC_GRANT"
            )

            if public_acl:
                finding(
                    "Bucket ACL", "HIGH",
                    "ACL contains a public or authenticated-users grant"
                )

        except ClientError:
            details["public_acl"] = "CHECK_FAILED"

        report["bucket_details"].append(details)

    with open("s3_report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\n========== S3 SECURITY SCAN ==========")
    print("Buckets scanned:", report["buckets_scanned"])
    print("Potential findings:", len(report["findings"]))

    for item in report["findings"]:
        print(item)

    print("\nReport saved as s3_report.json")


if __name__ == "__main__":
    scan_s3()
