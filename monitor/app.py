import time
import os
import shutil
from collections import defaultdict

# ---------------- CONFIG ----------------
LOG_FILE = "/logs/nginx/access.log"
BLOCK_FILE = "/logs/blocked_ips.conf"
TEMP_FILE = "/logs/blocked_ips.conf.tmp"

THRESHOLD = 10
WINDOW = 10
BLOCK_DURATION = 300  # 5 minutes

SUSPICIOUS_PATHS = ["/wp-admin", "/login"]

NGINX_CONTAINER = "secure-dockerapp-nginx-1"  # change if needed

# ---------------- STATE ----------------
blocked_ips = {}  
# { ip: { "time": timestamp, "reason": "brute-force" } }

last_reload = 0

# ---------------- NGINX CONTROL ----------------
def reload_nginx():
    global last_reload
    if time.time() - last_reload < 3:
        return
    os.system(f"docker exec {NGINX_CONTAINER} nginx -s reload")
    last_reload = time.time()

def test_nginx():
    return os.system(f"docker exec {NGINX_CONTAINER} nginx -t")

# ---------------- SAFE CONFIG UPDATE ----------------
def update_nginx_config():
    try:
        with open(TEMP_FILE, "w") as f:
            f.write("# blocked IPs\n")
            for ip in blocked_ips:
                f.write(f"deny {ip};\n")

        shutil.copy(TEMP_FILE, BLOCK_FILE)

        if test_nginx() != 0:
            print("[ERROR] Invalid nginx config. Skipping reload.")
            return

        reload_nginx()

    except Exception as e:
        print("[ERROR updating config]", e)

# ---------------- BLOCK / UNBLOCK ----------------
def block_ip(ip, reason="unknown"):
    if ip in blocked_ips:
        return

    if not ip or ip.count('.') != 3:
        print(f"[SKIP] Invalid IP: {ip}")
        return

    print(f"[BLOCK] {ip} ({reason})")

    blocked_ips[ip] = {
        "time": time.time(),
        "reason": reason
    }

    update_nginx_config()

def cleanup_blocks():
    current_time = time.time()
    removed = []

    for ip in list(blocked_ips.keys()):
        if current_time - blocked_ips[ip]["time"] > BLOCK_DURATION:
            removed.append(ip)
            del blocked_ips[ip]

    if removed:
        print(f"[UNBLOCK] {removed}")
        update_nginx_config()

# ---------------- LOG PARSING ----------------
def parse_line(line):
    try:
        parts = line.split()
        ip = parts[0]
        request = parts[5] + " " + parts[6]
        status = parts[8]
        return ip, request, status
    except:
        return None, None, None

# ---------------- STATS ----------------
last_print = 0

def print_stats():
    global last_print
    if time.time() - last_print < 5:
        return

    last_print = time.time()

    print("\n===== SYSTEM STATUS =====")
    print(f"Active blocked IPs: {len(blocked_ips)}")

    for ip, data in blocked_ips.items():
        print(f" - {ip} ({data['reason']})")

    print("=========================\n")

# ---------------- MAIN MONITOR ----------------
def monitor():
    ip_requests = defaultdict(list)

    while True:
        try:
            with open(LOG_FILE, "r") as f:
                lines = f.readlines()[-100:]

            current_time = time.time()

            for line in lines:
                ip, request, status = parse_line(line)

                if not ip:
                    continue

                # 🔍 Detect scans
                for path in SUSPICIOUS_PATHS:
                    if path in request:
                        print(f"[SCAN] {ip} -> {path}")
                        block_ip(ip, "scan")

                # 🔍 Detect failed requests
                if status.startswith("4") or status.startswith("5"):
                    ip_requests[ip].append(current_time)

            # 🔥 Brute-force detection
            for ip in list(ip_requests.keys()):
                ip_requests[ip] = [
                    t for t in ip_requests[ip]
                    if current_time - t < WINDOW
                ]

                if len(ip_requests[ip]) > THRESHOLD:
                    print(f"[ALERT] Brute force from {ip}")
                    block_ip(ip, "brute-force")
                    ip_requests[ip].clear()

            cleanup_blocks()
            print_stats()

        except Exception as e:
            print("Error:", e)

        time.sleep(5)

# ---------------- ENTRY ----------------
if __name__ == "__main__":
    monitor()