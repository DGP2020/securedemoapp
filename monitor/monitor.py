import time
from collections import defaultdict

from monitor.app import SUSPICIOUS_PATHS, block_ip, blocked_ips

LOG_FILE = "/logs/nginx/access.log"

THRESHOLD = 5
WINDOW = 10

seen_scans = set()

# ---------------- PARSER ----------------
def parse_line(line):
    try:
        parts = line.split()

        ip = parts[0]

        # validate IP
        if ip.count('.') != 3:
            return None, None, None

        request = parts[5] + " " + parts[6]   # "GET /login"
        status = parts[8]

        return ip, request, status
    except:
        return None, None, None

# ---------------- MONITOR ----------------
def monitor():
    ip_requests = defaultdict(list)

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-500:]

            current_time = time.time()

            for line in lines:
                ip, request, status = parse_line(line)

                if not ip:
                    continue

                # 🔍 SCAN DETECTION (clean, no spam)
                for path in SUSPICIOUS_PATHS:
                    if path in request:
                        if ip not in blocked_ips and ip not in seen_scans:
                            print(f"[SCAN] {ip} -> {path}")
                            seen_scans.add(ip)
                            block_ip(ip, "scan")

                # 🔍 FAILED REQUEST TRACKING
                if status.startswith("4") or status.startswith("5"):
                    ip_requests[ip].append(current_time)

            # 🔥 BRUTE FORCE DETECTION
            for ip in list(ip_requests.keys()):
                ip_requests[ip] = [
                    t for t in ip_requests[ip]
                    if current_time - t < WINDOW
                ]

                if len(ip_requests[ip]) > THRESHOLD:
                    if ip not in blocked_ips:
                        print(f"[ALERT] Brute force from {ip}")
                        block_ip(ip, "brute-force")

                    ip_requests[ip].clear()

        except Exception as e:
            print("Error:", e)

        time.sleep(2)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    monitor()