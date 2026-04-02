from fastapi import FastAPI
from pydantic import BaseModel
import time
import bcrypt
from datetime import datetime

app = FastAPI()

# ================= REQUEST MODEL =================
class LoginRequest(BaseModel):
    username: str
    password: str
    ip: str

# ================= CONFIGURATION =================
RATE_LIMIT_WINDOW = 60
MAX_ATTEMPTS_PER_WINDOW = 5
MAX_RATE_LIMIT_STRIKES = 3
TEMP_BLOCK_DURATION = 300

rate_limit_strikes = {}
blocked_ips = set()
attempt_timestamps = {}
temp_blocked_at = {}

ACCOUNT_LOCK_THRESHOLD = 5
ACCOUNT_LOCK_DURATION = 300

account_failures = {}
account_locked_at = {}

# ================= USERS =================
USERS = {
    "admin": {"password_hash": bcrypt.hashpw(b"admin123", bcrypt.gensalt())},
    "alice": {"password_hash": bcrypt.hashpw(b"user123", bcrypt.gensalt())},
}

# ================= HELPERS =================
def log_attempt(username, ip, status):
    print(f"[LOG] {datetime.now()} - User: {username}, IP: {ip}, Status: {status}")

def is_temp_blocked(ip):
    if ip not in temp_blocked_at:
        return False
    if time.time() - temp_blocked_at[ip] > TEMP_BLOCK_DURATION:
        del temp_blocked_at[ip]
        return False
    return True

def authorize(username, role):
    return username == "admin" and role == "admin"

def failure_delay(ip):
    strikes = rate_limit_strikes.get(ip, 0)
    delay = min(2 + strikes, 5)
    time.sleep(delay)

def is_account_locked(username):
    if username not in account_locked_at:
        return False

    if time.time() - account_locked_at[username] > ACCOUNT_LOCK_DURATION:
        del account_locked_at[username]
        account_failures.pop(username, None)
        return False

    return True

# ================= CORE LOGIN =================
def login(username, password, ip):

    if ip in blocked_ips:
        log_attempt(username, ip, "PERMANENT_BLOCK")
        return "blocked"

    if is_temp_blocked(ip):
        log_attempt(username, ip, "TEMP_BLOCK")
        return "temp_blocked"

    if is_account_locked(username):
        log_attempt(username, ip, "ACCOUNT_LOCKED")
        return "account_locked"

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
            log_attempt(username, ip, "PERMANENT_BLOCK")
            return "blocked"
        else:
            temp_blocked_at[ip] = now
            log_attempt(username, ip, "RATE_LIMIT")
            return "rate_limited"

    user = USERS.get(username)

    if not user:
        log_attempt(username, ip, "UNKNOWN_USER")
        return "unknown_user"

    if bcrypt.checkpw(password.encode(), user["password_hash"]):
        account_failures.pop(username, None)
        account_locked_at.pop(username, None)
        attempt_timestamps.pop(ip, None)
        rate_limit_strikes.pop(ip, None)

        log_attempt(username, ip, "SUCCESS")

        if authorize(username, "admin"):
            return "admin_success"
        return "user_success"

    else:
        log_attempt(username, ip, "FAILED_PASSWORD")

        account_failures[username] = account_failures.get(username, 0) + 1

        if account_failures[username] >= ACCOUNT_LOCK_THRESHOLD:
            account_locked_at[username] = time.time()
            log_attempt(username, ip, "ACCOUNT_LOCKED")
            return "account_locked"

        failure_delay(ip)
        return "failed"

# ================= API ROUTES =================
@app.post("/login")
def login_api(request: LoginRequest):
    result = login(request.username, request.password, request.ip)

    response = {
        "username": request.username,
        "status": result,
        "risk_score": 0,
        "reason": "Normal activity"
    }

    # 🔥 Add intelligence layer
    if result in ["blocked", "rate_limited"]:
        response["risk_score"] = 90
        response["reason"] = "Too many requests / brute-force detected"

    elif result == "account_locked":
        response["risk_score"] = 85
        response["reason"] = "Multiple failed login attempts"

    elif result == "failed":
        response["risk_score"] = 60
        response["reason"] = "Incorrect credentials"

    elif result == "unknown_user":
        response["risk_score"] = 70
        response["reason"] = "User does not exist"

    elif result in ["admin_success", "user_success"]:
        response["risk_score"] = 10
        response["reason"] = "Legitimate login"

    return response
@app.get("/dashboard")
def dashboard():
    return {
        "blocked_ips": list(blocked_ips),
        "temp_blocked_ips": list(temp_blocked_at.keys()),
        "rate_limit_strikes": rate_limit_strikes,
        "account_failures": account_failures
    }