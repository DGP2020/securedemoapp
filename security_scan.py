import requests

BASE_URL = "http://localhost"

def run_scan():
    print("🚀 Starting Security Scan...")
    
    # Test 1: Unauthorized Access
    res = requests.get(f"{BASE_URL}/secure")
    print(f"[1] Auth Check: {'PASS' if res.status_code == 401 else 'FAIL'}")

    # Test 2: Brute Force Simulation
    print("[2] Brute Force Check: Sending 10 requests...")
    codes = []
    for _ in range(10):
        r = requests.post(f"{BASE_URL}/login", json={"u":"a","p":"a"})
        codes.append(r.status_code)
    
    if 429 in codes or 503 in codes:
        print("    RESULT: Rate Limiting Active! (PASS)")
    else:
        print("    RESULT: No Rate Limiting Detected! (FAIL)")

if __name__ == "__main__":
    run_scan()