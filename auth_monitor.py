from datetime import datetime
import time
import os

# ================= CONFIG =================
RATE_LIMIT_WINDOW = 10          # seconds
MAX_ATTEMPTS_PER_WINDOW = 3
MAX_RATE_LIMIT_STRIKES = 3
RATE_LIMIT_BLOCK_TIME = 30      # seconds
LOG_FILE = "logs.txt"

# ================= STATE =================
attempt_timestamps = {}         # ip -> [timestamps]
rate_limit_strikes = {}         # ip -> count
blocked_ips = set()             # permanently blocked IPs
temp_blocked_at = {}            # ip -> timestamp

# ================= LOGGING =================
def log_attempt(username, ip, status):
    if not os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} | {username} | {ip} | {status}\n")

# ================= HELPERS =================
def is_temp_blocked(ip):
    if ip not in temp_blocked_at:
        return False

    if time.time() - temp_blocked_at[ip] < RATE_LIMIT_BLOCK_TIME:
        return True

    # unblock after timeout
    del temp_blocked_at[ip]
    attempt_timestamps.pop(ip, None)
    return False

# ================= MAIN LOGIN =================
def login(username, password, ip):

    # 1️⃣ PERMANENT BLOCK CHECK
    if ip in blocked_ips:
        print(f"⛔ BLOCKED: Access denied for IP {ip}")
        log_attempt(username, ip, "BLOCKED")
        return

    # 2️⃣ TEMP RATE-LIMIT CHECK
    if is_temp_blocked(ip):
        print(f"⏳ TEMP BLOCK: IP {ip}")
        log_attempt(username, ip, "TEMP_BLOCKED")
        return

    # 3️⃣ RATE LIMIT TRACKING
    now = time.time()
    attempts = attempt_timestamps.get(ip, [])
    attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    attempts.append(now)
    attempt_timestamps[ip] = attempts

    if len(attempts) > MAX_ATTEMPTS_PER_WINDOW:
        strikes = rate_limit_strikes.get(ip, 0) + 1
        rate_limit_strikes[ip] = strikes

        if strikes >= MAX_RATE_LIMIT_STRIKES:
            blocked_ips.add(ip)
            print(f"🚫 PERMANENT BAN TRIGGERED for IP {ip}")
            log_attempt(username, ip, "PERMANENT_BLOCK")
        else:
            temp_blocked_at[ip] = now
            print(f"⏳ RATE LIMIT: IP {ip} blocked ({strikes}/{MAX_RATE_LIMIT_STRIKES})")
            log_attempt(username, ip, "RATE_LIMIT")

        return

    # 4️⃣ PASSWORD CHECK
    REAL_PASSWORD = "admin123"

    if password == REAL_PASSWORD:
        print("✅ Login successful")
        log_attempt(username, ip, "SUCCESS")
    else:
        print("❌ Login failed")
        log_attempt(username, ip, "FAILED_PASSWORD")


# ================= TEST DRIVER =================
if __name__ == "__main__":

    print("\n--- Attack round 1 ---")
    for _ in range(5):
        login("admin", "wrong", "5.5.5.5")

    time.sleep(2)

    print("\n--- Attack round 2 ---")
    for _ in range(5):
        login("admin", "wrong", "5.5.5.5")

    time.sleep(2)

    print("\n--- Attack round 3 ---")
    for _ in range(5):
        login("admin", "wrong", "5.5.5.5")

    print("\n--- Legit login ---")
    login("admin", "admin123", "9.9.9.9")
