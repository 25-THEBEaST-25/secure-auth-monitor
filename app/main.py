# ================================
# Configuration Constants
# ================================
# These values control rate limiting,
# lockout thresholds, and penalty escalation.
# Tweaking them changes system behavior.
from fastapi import FastAPI

app = FastAPI()
import time
import bcrypt
from datetime import datetime

# ================= CONFIGURATION =================
RATE_LIMIT_WINDOW = 60  # seconds
MAX_ATTEMPTS_PER_WINDOW = 5
MAX_RATE_LIMIT_STRIKES = 3
TEMP_BLOCK_DURATION = 300  # seconds

# Global state tracking
rate_limit_strikes = {}
blocked_ips = set()
attempt_timestamps = {}
temp_blocked_at = {}
ACCOUNT_LOCK_THRESHOLD = 5
ACCOUNT_LOCK_DURATION = 300  # seconds

account_failures = {}
account_locked_at = {}


# User credentials (password hashes generated with bcrypt)
USERS = {
    "admin": {"password_hash": bcrypt.hashpw(b"admin123", bcrypt.gensalt())},
    "alice": {"password_hash": bcrypt.hashpw(b"user123", bcrypt.gensalt())},
}

# Helper functions
def log_attempt(username, ip, status):
    """Log authentication attempts"""
    print(f"[LOG] {datetime.now()} - User: {username}, IP: {ip}, Status: {status}")

def is_temp_blocked(ip):
    """Check if IP is temporarily blocked"""
    if ip not in temp_blocked_at:
        return False
    if time.time() - temp_blocked_at[ip] > TEMP_BLOCK_DURATION:
        del temp_blocked_at[ip]
        return False
    return True

def authorize(username, role):
    """Check if user has the required role"""
    return username == "admin" and role == "admin"
    """
    Handles user authentication with layered security checks.
    Applies rate limiting, IP blocking, account lockout,
    and authorization before granting access.
    """

def failure_delay(ip):
    strikes = rate_limit_strikes.get(ip, 0)
    delay = min(2 + strikes, 5)  # max 5 seconds
    time.sleep(delay)

def is_account_locked(username):
    if username not in account_locked_at:
        return False

    if time.time() - account_locked_at[username] > ACCOUNT_LOCK_DURATION:
        del account_locked_at[username]
        account_failures.pop(username, None)
        return False

    return True

def login(username, password, ip):

    # 1️⃣ PERMANENT BLOCK CHECK
    if ip in blocked_ips:
        print(f"⛔ BLOCKED: Access denied for IP {ip}")
        log_attempt(username, ip, "PERMANENT_BLOCK")
        return

    # 2️⃣ TEMP BLOCK CHECK
    if is_temp_blocked(ip):
        print(f"⏳ TEMP BLOCK: IP {ip}")
        log_attempt(username, ip, "TEMP_BLOCK")
        return
    # 🔐 ACCOUNT LOCK CHECK
    if is_account_locked(username):
        print(f"🔒 ACCOUNT LOCKED: {username}")
        log_attempt(username, ip, "ACCOUNT_LOCKED")
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

    # 4️⃣ AUTHENTICATION (bcrypt)
    # If authentication succeeds:
# - reset failure counters
# - remove temporary blocks
# - allow access

# If authentication fails:
# - increment failure count
# - apply delay / temporary block
# - escalate penalties if needed
    user = USERS.get(username)
    # Escalate penalties only after repeated failures


    if not user:
        print("❌ Unknown user")
        log_attempt(username, ip, "UNKNOWN_USER")
        return

    if bcrypt.checkpw(password.encode(), user["password_hash"]):
        account_failures.pop(username, None)
        account_locked_at.pop(username, None)

        attempt_timestamps.pop(ip, None)
        rate_limit_strikes.pop(ip, None)

        print("✅ Login successful")
        log_attempt(username, ip, "SUCCESS")

        # 5️⃣ AUTHORIZATION (RBAC)
        if authorize(username, "admin"):
            print("👑 Admin access granted")
        else:
            print("🔒 User access granted")
    else:
        print("❌ Login failed")
        log_attempt(username, ip, "FAILED_PASSWORD")

        account_failures[username] = account_failures.get(username, 0) + 1

        if account_failures[username] >= ACCOUNT_LOCK_THRESHOLD:
            account_locked_at[username] = time.time()
            print(f"🔒 ACCOUNT LOCKED due to failures: {username}")
            log_attempt(username, ip, "ACCOUNT_LOCKED")

        failure_delay(ip)

@app.get("/")
def home():
    return {"message": "SecureAuth Monitor is running 🔐"}



# ================= TEST DRIVER =================
login("admin", "admin123", "9.9.9.9")   # 👑 Admin
login("alice", "user123", "8.8.8.8")    # 🔒 User
login("alice", "wrong", "8.8.8.8")      # ❌ Fail

