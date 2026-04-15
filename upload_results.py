from datetime import datetime, timedelta, timezone, date
import subprocess
from pathlib import Path
import glob


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
    
    # aggregate the warts files into a single file for the day
   
    warts_files = sorted(
        glob.glob(f"./results/warts{today - timedelta(days=1)}/*.warts.gz")
    )

    if not warts_files:
        raise RuntimeError("No WARTS files found to merge")

    cmd = [
        "sc_wartscat",
        *warts_files,
        "-o",
        output_file.replace(".csv", ".warts"),
    ]

    subprocess.run(cmd, check=True)

        


    print(f"Uploading daily results for {today.isoformat()}")
    
    # gzip the files before uploading
    subprocess.run(["gzip", "-f", output_file], check=True)
    subprocess.run(["gzip", "-f", output_file.replace(".csv", ".warts")], check=True)

    result = subprocess.run(
        [
            "./mc",
            "mv",
            output_file.replace(".csv", ".warts.gz"),
            "storage/shakerim-gdns/daily-results/",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("Upload failed:", result.stderr)
        return last_upload_date
    
    result = subprocess.run(
        [
            "./mc",
            "mv",
            output_file.replace(".csv", ".csv.gz"),
            "storage/shakerim-gdns/daily-results/",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print("Upload failed:", result.stderr)
        return last_upload_date
    


    print("Upload successful")
    return today
