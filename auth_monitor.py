from datetime import datetime

# Track failed attempts per IP
failed_attempts = {}

LOG_FILE = "logs.txt"
MAX_FAILED_ATTEMPTS = 3

def log_attempt(username, ip, success):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = "SUCCESS" if success else "FAILED"

    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} | {username} | {ip} | {status}\n")

def is_suspicious(ip):
    return failed_attempts.get(ip, 0) >= MAX_FAILED_ATTEMPTS

def login(username, password, ip):
    REAL_PASSWORD = "admin123"

    if password == REAL_PASSWORD:
        log_attempt(username, ip, True)
        failed_attempts[ip] = 0
        print("Login successful ✅")
    else:
        failed_attempts[ip] = failed_attempts.get(ip, 0) + 1
        log_attempt(username, ip, False)

        if is_suspicious(ip):
            print(f"⚠️ ALERT: Suspicious activity detected from IP {ip}")
        else:
            print("Login failed ❌")

# ---- Test Simulation ----
login("admin", "1234", "192.168.1.10")
login("admin", "password", "192.168.1.10")
login("admin", "letmein", "192.168.1.10")

