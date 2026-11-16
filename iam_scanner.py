
import boto3
import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# IAM is a global AWS service.
iam = boto3.client("iam")

# Change this value if you want a different review threshold.
MAX_KEY_AGE_DAYS = 90

report = {
    "scan_time": datetime.now(timezone.utc).isoformat(),
    "users_scanned": 0,
    "roles_scanned": 0,
    "findings": [],
    "users": [],
    "roles": []
}


def add_finding(identity, check, risk, message):
    report["findings"].append({
        "identity": identity,
        "check": check,
        "risk": risk,
        "finding": message
    })


def inspect_policy(policy, identity, policy_name):
    """Look for broad permissions in a policy document."""

    statements = policy.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue

        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]

        if isinstance(resources, str):
            resources = [resources]

        # Check for full action wildcard.
        if "*" in actions:
            add_finding(
                identity,
                "Wildcard permissions",
                "HIGH",
                f"{policy_name} allows all actions"
            )

        # Check for service-wide wildcards such as s3:*.
        for action in actions:
            if isinstance(action, str) and action.endswith(":*"):
                add_finding(
                    identity,
                    "Service-wide permissions",
                    "REVIEW",
                    f"{policy_name} contains broad action {action}"
                )

        # Check for unrestricted resource scope.
        if "*" in resources:
            add_finding(
                identity,
                "Wildcard resource",
                "REVIEW",
                f"{policy_name} applies to all resources"
            )


def inspect_managed_policy(policy_reference, identity):
    """Retrieve and inspect an AWS managed or customer managed policy."""

    policy_arn = policy_reference["PolicyArn"]

    try:
        policy_info = iam.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = policy_info["DefaultVersionId"]

        document = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )["PolicyVersion"]["Document"]

        inspect_policy(
            document,
            identity,
            policy_info["PolicyName"]
        )

        # Heuristic check for administrator policy names.
        if policy_info["PolicyName"] == "AdministratorAccess":
            add_finding(
                identity,
                "Administrator policy",
                "HIGH",
                "AdministratorAccess is attached; verify business need"
            )

    except ClientError as error:
        print(f"Could not inspect policy {policy_arn}: {error}")


def scan_users():
    print("\nScanning IAM users...")

    paginator = iam.get_paginator("list_users")

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            report["users_scanned"] += 1

            user_details = {
                "username": username,
                "created": user["CreateDate"].isoformat(),
                "mfa_enabled": False,
                "access_keys": [],
                "managed_policies": [],
                "inline_policies": []
            }

            # 1. Check MFA devices.
            mfa_devices = iam.list_mfa_devices(
                UserName=username
            )["MFADevices"]

            user_details["mfa_enabled"] = len(mfa_devices) > 0

            if not user_details["mfa_enabled"]:
                add_finding(
                    username,
                    "MFA",
                    "HIGH",
                    "No MFA device is configured for this IAM user"
                )

            # 2. Check access keys.
            keys = iam.list_access_keys(
                UserName=username
            )["AccessKeyMetadata"]

            for key in keys:
                age_days = (
                    datetime.now(timezone.utc) -
                    key["CreateDate"]
                ).days

                key_details = {
                    "access_key_id": key["AccessKeyId"],
                    "status": key["Status"],
                    "age_days": age_days
                }

                user_details["access_keys"].append(key_details)

                if key["Status"] == "Active" and age_days > MAX_KEY_AGE_DAYS:
                    add_finding(
                        username,
                        "Access key age",
                        "REVIEW",
                        f"Active access key is {age_days} days old"
                    )

            # 3. Inspect attached managed policies.
            attached = iam.list_attached_user_policies(
                UserName=username
            )["AttachedPolicies"]

            for policy in attached:
                policy_name = policy["PolicyName"]
                user_details["managed_policies"].append(policy_name)

                inspect_managed_policy(policy, username)

            # 4. Inspect inline policies.
            inline_names = iam.list_user_policies(
                UserName=username
            )["PolicyNames"]

            for policy_name in inline_names:
                document = iam.get_user_policy(
                    UserName=username,
                    PolicyName=policy_name
                )["PolicyDocument"]

                user_details["inline_policies"].append(policy_name)

                inspect_policy(
                    document,
                    username,
                    policy_name
                )

            report["users"].append(user_details)


def scan_roles():
    print("\nScanning IAM roles...")

    paginator = iam.get_paginator("list_roles")

    for page in paginator.paginate():
        for role in page["Roles"]:
            role_name = role["RoleName"]
            report["roles_scanned"] += 1

            role_details = {
                "role_name": role_name,
                "created": role["CreateDate"].isoformat(),
                "attached_policies": [],
                "trust_policy_review": "NOT_REVIEWED"
            }

            # 1. Inspect the trust policy.
            trust_policy = role["AssumeRolePolicyDocument"]
            trust_statements = trust_policy.get("Statement", [])

            if isinstance(trust_statements, dict):
                trust_statements = [trust_statements]

            for statement in trust_statements:
                principal = statement.get("Principal", {})

                if principal == "*":
                    role_details["trust_policy_review"] = (
                        "WILDCARD_PRINCIPAL_FOUND"
                    )

                    add_finding(
                        role_name,
                        "Role trust policy",
                        "HIGH",
                        "Role trust policy contains a wildcard principal; review conditions"
                    )

                elif isinstance(principal, dict):
                    if principal.get("AWS") == "*":
                        role_details["trust_policy_review"] = (
                            "WILDCARD_AWS_PRINCIPAL_FOUND"
                        )

                        add_finding(
                            role_name,
                            "Role trust policy",
                            "HIGH",
                            "Role trust policy trusts any AWS principal; review conditions"
                        )

            # 2. Inspect attached managed policies.
            attached = iam.list_attached_role_policies(
                RoleName=role_name
            )["AttachedPolicies"]

            for policy in attached:
                role_details["attached_policies"].append(
                    policy["PolicyName"]
                )

                inspect_managed_policy(policy, role_name)

            # 3. Inspect inline role policies.
            inline_names = iam.list_role_policies(
                RoleName=role_name
            )["PolicyNames"]

            for policy_name in inline_names:
                document = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )["PolicyDocument"]

                inspect_policy(
                    document,
                    role_name,
                    policy_name
                )

            report["roles"].append(role_details)


def main():
    try:
        scan_users()
        scan_roles()

        # Save report.
        with open("iam_report.json", "w") as file:
            json.dump(report, file, indent=4)

        print("\n========== IAM SECURITY SCAN ==========")
        print("Users scanned:", report["users_scanned"])
        print("Roles scanned:", report["roles_scanned"])
        print("Potential findings:", len(report["findings"]))

        for finding in report["findings"]:
            print(finding)

        print("\nReport saved as iam_report.json")

    except ClientError as error:
        print("\nAWS API error:", error)
        print("Check the IAM permissions of your AWS identity.")


if __name__ == "__main__":
    main()
