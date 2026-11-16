
import subprocess
import sys
import shutil
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_DIR = BASE_DIR / "reports"

REPORT_DIR.mkdir(exist_ok=True)

# Scanner filenames and their expected reports
SCANNERS = [
    ("vpc_scanner.py", "scan_report.json"),
    ("nacl_scanner.py", "nacl_report.json"),
    ("S3_scanner.py", "s3_report.json"),
    ("iam_scanner.py", "iam_report.json"),
    ("cloudtrail_analyzer.py", "cloudtrail_report.json"),
    ("guardduty_scanner.py", "guardduty_report.json"),
    ("config_scanner.py", "config_report.json")
]


def run_script(filename):
    script_path = BASE_DIR / filename

    if not script_path.exists():
        print(f"\n[ERROR] Missing script: {filename}")
        return False

    print(f"\n{'=' * 55}")
    print(f" RUNNING: {filename}")
    print(f"{'=' * 55}")

    result = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=BASE_DIR
    )

    if result.returncode != 0:
        print(f"[FAILED] {filename}")
        return False

    print(f"[SUCCESS] {filename}")
    return True


def organize_report(report_name):
    root_report = BASE_DIR / report_name
    report_folder = REPORT_DIR / report_name

    # Some scanners already save directly into reports/
    if root_report.exists():
        if report_folder.exists():
            root_report.unlink()
        else:
            shutil.move(str(root_report), str(report_folder))

    if report_folder.exists():
        print(f"[REPORT READY] {report_name}")
        return True

    print(f"[WARNING] Report not generated: {report_name}")
    return False


def main():

    print("\n==========================================")
    print(" AWS CLOUD SECURITY SCANNER - FULL RUN")
    print("==========================================")

    scanner_success = 0
    scanner_failed = 0

    for script, report in SCANNERS:

        success = run_script(script)

        if success:
            scanner_success += 1
        else:
            scanner_failed += 1

        organize_report(report)

    print("\n==========================================")
    print(" BUILDING CONSOLIDATED REPORT")
    print("==========================================")

    if not run_script("index.py"):
        print("[ERROR] Report integration failed.")
        return

    print("\n==========================================")
    print(" RUNNING SECURITY ANALYSIS")
    print("==========================================")

    if not run_script("security_analyzer.py"):
        print("[ERROR] Security analysis failed.")
        return

    print("\n==========================================")
    print(" FINAL EXECUTION SUMMARY")
    print("==========================================")

    print(f"Scanners successful: {scanner_success}")
    print(f"Scanners failed: {scanner_failed}")
    print(f"Reports directory: {REPORT_DIR}")

    print("\nFull security scan workflow completed.")


if __name__ == "__main__":
    main()
