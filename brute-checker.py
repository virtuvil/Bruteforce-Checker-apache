import sys
import re
from collections import defaultdict

def detect_brute_force(log_file_path):
    # Dictionary to store failed login attempts per IP address
    failed_attempts = defaultdict(int)

    # Regular expression pattern to match Apache log entries
    apache_log_pattern = r'^(\S+) \S+ \S+ \[([^:]+):(\d+:\d+:\d+) .*\] "POST /login HTTP/1.\d" 401'

    # Read the log file
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.match(apache_log_pattern, line)
            if match:
                ip_address = match.group(1)
                timestamp = match.group(2) + ':' + match.group(3)
                failed_attempts[(ip_address, timestamp)] += 1

    # Check for potential brute force attacks
    for (ip_address, timestamp), attempts in failed_attempts.items():
        if attempts > 5:
            print(f"Potential brute force attack detected from {ip_address} at {timestamp}: {attempts} failed attempts.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python brute_force_detection.py <apache_access_log>")
        sys.exit(1)

    log_file_path = sys.argv[1]
    detect_brute_force(log_file_path)

