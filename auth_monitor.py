from datetime import datetime
import time

# ================= CONFIG =================
RATE_LIMIT_WINDOW = 10          # seconds
MAX_ATTEMPTS_PER_WINDOW = 3     # rate limit
MAX_FAILED_ATTEMPTS = 10         # brute-force limit
LOG_FILE = "logs.txt"

# ================= STATE =================
attempt_timestamps = {}         # rate-limit tracking
failed_attempts = {}            # brute-force tracking
blocked_ips = set()

# ================= HELPERS =================
def log_attempt(username, ip, success):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} | {username} | {ip} | {status}\n")

def is_suspicious(ip):
    return failed_attempts.get(ip, 0) >= MAX_FAILED_ATTEMPTS

def is_blocked(ip):
    return ip in blocked_ips

def login(username, password, ip):
    now = time.time()

    # ===== RATE LIMIT CHECK =====
    attempts = attempt_timestamps.get(ip, [])
    attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]

    if len(attempts) >= MAX_ATTEMPTS_PER_WINDOW:
        print(f"⏱️ RATE LIMIT TRIGGERED for IP {ip}")
        blocked_ips.add(ip)
        log_attempt(username, ip, False)
        return

    attempts.append(now)
    attempt_timestamps[ip] = attempts


# ================= MAIN LOGIN =================
def login(username, password, ip):
    
    # 1️⃣ BLOCKED IP CHECK
    if is_blocked(ip):
        print(f"🚫 BLOCKED: Access denied for IP {ip}")
        log_attempt(username, ip, False)
        return

    # 2️⃣ RATE LIMIT CHECK
    now = time.time()
    attempts = attempt_timestamps.get(ip, [])

    # keep only recent attempts
    attempts = [t for t in attempts if now - t < RATE_LIMIT_WINDOW]
    attempts.append(now)
    attempt_timestamps[ip] = attempts

    if len(attempts) > MAX_ATTEMPTS_PER_WINDOW:
        blocked_ips.add(ip)
        print(f"⏱️ RATE LIMIT: IP {ip} temporarily BLOCKED")
        log_attempt(username, ip, False)
        return

    # 3️⃣ PASSWORD CHECK
    REAL_PASSWORD = "admin123"

    if password == REAL_PASSWORD:
        log_attempt(username, ip, True)
        failed_attempts[ip] = 0
        print("Login successful ✅")
    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        log_attempt(username, ip, False)

        if is_suspicious(ip):
            blocked_ips.add(ip)
            print(f"🚫 IP {ip} has been BLOCKED due to repeated failures")
        else:
            print("Login failed ❌")

# ================= TEST SIMULATION =================
login("admin", "123", "1.1.1.1")
login("admin", "123", "1.1.1.1")
login("admin", "123", "1.1.1.1")
login("admin", "123", "1.1.1.1")

