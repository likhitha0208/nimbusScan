
import json
from pathlib import Path
from datetime import datetime, timezone

# Project directories
BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

# Individual scanner reports
REPORT_FILES = [
    "scan_report.json",
    "nacl_report.json",
    "s3_report.json",
    "iam_report.json",
    "cloudtrail_report.json",
    "guardduty_report.json",
    "config_report.json"
]


def load_report(filename):
    """Load an individual scanner report."""
    report_path = REPORT_DIR / filename

    if not report_path.exists():
        print(f"[WARNING] Missing report: {filename}")
        return None

    try:
        with report_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        print(f"[SUCCESS] Loaded {filename}")
        return data

    except (json.JSONDecodeError, OSError) as error:
        print(f"[ERROR] Could not read {filename}: {error}")
        return None


def main():
    print("\n===================================")
    print(" AWS CLOUD SECURITY SCANNER")
    print("===================================\n")

    combined_report = {
        "project": "AWS Cloud Network Security Scanner",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "reports": {}
    }

    successful = 0
    failed = 0

    for filename in REPORT_FILES:
        report = load_report(filename)

        if report is not None:
            combined_report["reports"][filename] = report
            successful += 1
        else:
            failed += 1

    output_file = REPORT_DIR / "combined_security_report.json"

    with output_file.open("w", encoding="utf-8") as file:
        json.dump(combined_report, file, indent=4, default=str)

    print("\n===================================")
    print(" SCAN INTEGRATION SUMMARY")
    print("===================================")
    print(f"Reports loaded : {successful}")
    print(f"Reports missing/failed : {failed}")
    print(f"Combined report : {output_file}")

    print("\nIntegration completed!")


if __name__ == "__main__":
    main()
