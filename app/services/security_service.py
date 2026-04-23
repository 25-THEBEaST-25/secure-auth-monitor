import time

FAILED_ATTEMPTS = {}
BLOCKED_IPS = {}

MAX_ATTEMPTS = 5
BLOCK_TIME = 60

def is_ip_allowed(ip: str):
    if ip in BLOCKED_IPS:
        if time.time() < BLOCKED_IPS[ip]:
            return False
        else:
            del BLOCKED_IPS[ip]
    return True

def record_failure(ip: str):
    FAILED_ATTEMPTS[ip] = FAILED_ATTEMPTS.get(ip, 0) + 1

    if FAILED_ATTEMPTS[ip] >= MAX_ATTEMPTS:
        BLOCKED_IPS[ip] = time.time() + BLOCK_TIME
        FAILED_ATTEMPTS[ip] = 0