from datetime import datetime, timezone, date
import subprocess
from pathlib import Path


def upload_results(
    output_file: str,
    last_upload_date: date | None,
):
    """
    Uploads output_file if we are past midnight UTC and haven't uploaded today.
    Returns updated last_upload_date.
    """
    today = datetime.now(timezone.utc).date()

    if last_upload_date == today:
        return last_upload_date  # already uploaded today

    if not Path(output_file).exists():
        print("No output file to upload yet")
        return last_upload_date

    print(f"Uploading daily results for {today.isoformat()}")

    result = subprocess.run(
        [
            "./mc",
            "cp",
            output_file,
            "storage/shakerim-gdns/daily-results/",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("Upload failed:", result.stderr)
        return last_upload_date
    
    results = subprocess.run(
        [
            "./mc",
            "cp",
            output_file.replace(".warts", ".csv"),
            "storage/shakerim-gdns/daily-results/",
        ],
        capture_output=True,
        text=True,
    )


    print("Upload successful")
    return today
