import os
import time
from datetime import datetime
import logging

# Folder to monitor
folder = r"D:\Pictures"

# Suspicious file extensions
suspicious_extensions = [".exe", ".bat", ".vbs", ".ps1", ".zip", ".7zip", ".RAR",".py", ".html", ".db"]

# Log file
log_file = "security_alert.log"

# Configure logging
logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

# Keep track of files already detected
detected_files = set()

print("==============================================")
print("        PROTO SECURITY MONITOR")
print("==============================================")
print(f"Pictures: {folder}")
print(f"Log file: {os.path.abspath(log_file)}")
print("Waiting for suspicious files...\n")

while True:

    try:
        # Check whether monitoring folder exists
        if not os.path.exists(folder):
            print(f"WARNING: Folder does not exist: {folder}")
            logging.warning(f"Monitoring folder does not exist: {folder}")
            time.sleep(5)
            continue

        # Get files in folder
        files = os.listdir(folder)

        for filename in files:

            filepath = os.path.join(folder, filename)

            # Make sure it is a file
            if os.path.isfile(filepath):

                # Get extension
                extension = os.path.splitext(filename)[1].lower()

                print(f"Checking: {filename}")

                # Check suspicious extension
                if extension in suspicious_extensions:

                    # Avoid creating the same alert every 5 seconds
                    if filepath not in detected_files:

                        # Get current date and time
                        current_time = datetime.now()

                        date = current_time.strftime("%Y-%m-%d")
                        clock = current_time.strftime("%H:%M:%S")

                        # Security alert
                        print("\n🚨 SECURITY ALERT 🚨")
                        print(f"Date: {date}")
                        print(f"Time: {clock}")
                        print(f"Suspicious file: {filename}")
                        print(f"File type: {extension}")
                        print(f"Location: {filepath}")
                        print("----------------------------------------------")

                        # Write alert to log file
                        logging.warning(
                            f"SECURITY ALERT | "
                            f"Date={date} | "
                            f"Time={clock} | "
                            f"File={filename} | "
                            f"Type={extension} | "
                            f"Location={filepath}"
                        )

                        # Remember this file
                        detected_files.add(filepath)

        # Check every 5 seconds
        time.sleep(5)

    except KeyboardInterrupt:

        print("\nSecurity monitor stopped.")

        logging.info("Security monitor stopped by user.")

        break

    except Exception as e:

        print(f"ERROR: {e}")

        logging.error(f"Program error: {e}")

        time.sleep(5)