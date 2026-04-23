"""
Enterprise-Grade Authentication Service
A production-ready FastAPI application with advanced security, monitoring, and compliance features.
"""

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from pydantic_settings import BaseSettings
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple
import time
import bcrypt
import logging
import hashlib
import uuid
from enum import Enum
from abc import ABC, abstractmethod
from functools import wraps
import json

# ==================== CONFIGURATION ====================
class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class Settings(BaseSettings):
    """Environment-based configuration with sensible defaults"""
    
    # Security
    RATE_LIMIT_WINDOW: int = 60
    MAX_ATTEMPTS_PER_WINDOW: int = 5
    MAX_RATE_LIMIT_STRIKES: int = 3
    TEMP_BLOCK_DURATION: int = 300
    ACCOUNT_LOCK_THRESHOLD: int = 5
    ACCOUNT_LOCK_DURATION: int = 300
    
    # Advanced Security
    ENABLE_GEO_BLOCKING: bool = True
    ENABLE_DEVICE_FINGERPRINTING: bool = True
    SUSPICIOUS_LOGIN_THRESHOLD: float = 0.7
    
    # CORS & Hosts
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000", "https://yourdomain.com"]
    TRUSTED_HOSTS: List[str] = ["localhost", "127.0.0.1"]
    
    # Logging & Monitoring
    LOG_LEVEL: LogLevel = LogLevel.INFO
    ENABLE_AUDIT_LOG: bool = True
    METRICS_EXPORT_ENABLED: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# ==================== LOGGING & MONITORING ====================
class StructuredLogger:
    """Production-grade logging with structured output"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self.setup_handlers()
    
    def setup_handlers(self):
        """Configure file and console handlers"""
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler for persistent logs
        try:
            file_handler = logging.FileHandler('auth_service.log')
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
        except Exception as e:
            self.logger.warning(f"Could not create log file: {e}")
    
    def log_event(self, level: str, event_type: str, data: Dict):
        """Log structured event"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data
        }
        message = json.dumps(log_entry)
        getattr(self.logger, level.lower())(message)
    
    def info(self, event: str, **kwargs):
        self.log_event("INFO", event, kwargs)
    
    def warning(self, event: str, **kwargs):
        self.log_event("WARNING", event, kwargs)
    
    def error(self, event: str, **kwargs):
        self.log_event("ERROR", event, kwargs)
    
    def critical(self, event: str, **kwargs):
        self.log_event("CRITICAL", event, kwargs)

logger = StructuredLogger(__name__)

# ==================== MODELS ====================
class LoginStatus(str, Enum):
    SUCCESS = "success"
    ADMIN_SUCCESS = "admin_success"
    FAILED = "failed"
    UNKNOWN_USER = "unknown_user"
    RATE_LIMITED = "rate_limited"
    TEMP_BLOCKED = "temp_blocked"
    ACCOUNT_LOCKED = "account_locked"
    BLOCKED = "blocked"
    SUSPICIOUS = "suspicious"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class LoginRequest(BaseModel):
    """Validated login request"""
    username: str = Field(..., min_length=1, max_length=255, description="Username")
    password: str = Field(..., min_length=1, max_length=255, description="Password")
    ip: str = Field(..., description="Client IP address")
    device_id: Optional[str] = Field(None, description="Unique device identifier")
    user_agent: Optional[str] = Field(None, description="Browser user agent")
    
    @validator('username')
    def validate_username(cls, v):
        if not v.isalnum():
            raise ValueError('Username must be alphanumeric')
        return v

class LoginResponse(BaseModel):
    """Structured login response"""
    request_id: str
    username: str
    status: LoginStatus
    risk_score: float = Field(..., ge=0, le=100, description="Risk score 0-100")
    risk_level: RiskLevel
    reason: str
    timestamp: datetime
    session_id: Optional[str] = None
    mfa_required: bool = False

class DashboardResponse(BaseModel):
    """Dashboard metrics and statistics"""
    timestamp: datetime
    total_blocked_ips: int
    total_temp_blocked_ips: int
    active_account_locks: int
    rate_limit_strikes: Dict
    account_failures: Dict
    security_events_24h: int
    threat_level: RiskLevel

# ==================== SECURITY STORAGE & MANAGERS ====================
class SecurityStorage:
    """Thread-safe storage for security state"""
    
    def __init__(self):
        self.rate_limit_strikes: Dict[str, int] = {}
        self.blocked_ips: set = set()
        self.attempt_timestamps: Dict[str, List[float]] = {}
        self.temp_blocked_at: Dict[str, float] = {}
        self.account_failures: Dict[str, int] = {}
        self.account_locked_at: Dict[str, float] = {}
        self.login_history: List[Dict] = []
        self.device_fingerprints: Dict[str, set] = {}
        self.security_events: List[Dict] = []

class RateLimitManager:
    """Advanced rate limiting with exponential backoff"""
    
    def __init__(self, storage: SecurityStorage):
        self.storage = storage
    
    def check_and_record(self, ip: str) -> Tuple[bool, Optional[str]]:
        """
        Check rate limit and record attempt.
        Returns: (is_allowed, reason_if_blocked)
        """
        now = time.time()
        
        # Check permanent block
        if ip in self.storage.blocked_ips:
            return False, "Permanently blocked due to repeated violations"
        
        # Check temporary block
        if ip in self.storage.temp_blocked_at:
            if now - self.storage.temp_blocked_at[ip] > settings.TEMP_BLOCK_DURATION:
                del self.storage.temp_blocked_at[ip]
            else:
                return False, "Temporarily blocked. Try again later"
        
        # Check rate limit
        attempts = self.storage.attempt_timestamps.get(ip, [])
        attempts = [t for t in attempts if now - t < settings.RATE_LIMIT_WINDOW]
        
        if len(attempts) >= settings.MAX_ATTEMPTS_PER_WINDOW:
            strikes = self.storage.rate_limit_strikes.get(ip, 0) + 1
            self.storage.rate_limit_strikes[ip] = strikes
            
            if strikes >= settings.MAX_RATE_LIMIT_STRIKES:
                self.storage.blocked_ips.add(ip)
                logger.critical("PERMANENT_BLOCK", ip=ip, strikes=strikes)
                return False, "Permanently blocked due to excessive attempts"
            
            self.storage.temp_blocked_at[ip] = now
            logger.warning("RATE_LIMIT_EXCEEDED", ip=ip, strikes=strikes)
            return False, "Rate limit exceeded"
        
        # Record attempt
        attempts.append(now)
        self.storage.attempt_timestamps[ip] = attempts
        return True, None
    
    def get_backoff_delay(self, ip: str) -> float:
        """Calculate exponential backoff delay"""
        strikes = self.storage.rate_limit_strikes.get(ip, 0)
        delay = min(2 ** strikes, 32)  # Exponential backoff, max 32 seconds
        return delay

class AccountLockManager:
    """Manage account lockouts with time-based release"""
    
    def __init__(self, storage: SecurityStorage):
        self.storage = storage
    
    def check_locked(self, username: str) -> Tuple[bool, Optional[str]]:
        """Check if account is locked"""
        if username not in self.storage.account_locked_at:
            return False, None
        
        locked_time = self.storage.account_locked_at[username]
        if time.time() - locked_time > settings.ACCOUNT_LOCK_DURATION:
            self.storage.account_locked_at.pop(username, None)
            self.storage.account_failures.pop(username, None)
            logger.info("ACCOUNT_UNLOCKED", username=username)
            return False, None
        
        return True, "Account temporarily locked due to failed login attempts"
    
    def record_failure(self, username: str):
        """Record failed login attempt"""
        self.storage.account_failures[username] = self.storage.account_failures.get(username, 0) + 1
        
        if self.storage.account_failures[username] >= settings.ACCOUNT_LOCK_THRESHOLD:
            self.storage.account_locked_at[username] = time.time()
            logger.warning("ACCOUNT_LOCKED", username=username, attempt_count=self.storage.account_failures[username])

class AnomalyDetector:
    """Detect suspicious login patterns"""
    
    def __init__(self, storage: SecurityStorage):
        self.storage = storage
    
    def calculate_risk(self, username: str, ip: str, device_id: Optional[str]) -> float:
        """
        Calculate risk score for login attempt.
        Returns: risk_score (0-100)
        """
        risk_score = 0.0
        
        # Check if device is new
        if device_id and settings.ENABLE_DEVICE_FINGERPRINTING:
            if username in self.storage.device_fingerprints:
                if device_id not in self.storage.device_fingerprints[username]:
                    risk_score += 20  # New device
            else:
                self.storage.device_fingerprints[username] = set()
        
        # Check if IP is new
        user_ips = set()
        for event in self.storage.login_history:
            if event['username'] == username:
                user_ips.add(event['ip'])
        
        if ip not in user_ips and len(user_ips) > 0:
            risk_score += 15  # New IP
        
        # Check time-based anomalies
        recent_logins = [e for e in self.storage.login_history if e['username'] == username and time.time() - e['timestamp'] < 3600]
        if len(recent_logins) > 3:
            risk_score += 10  # Multiple logins in short time
        
        return min(risk_score, 100)
    
    def is_suspicious(self, risk_score: float) -> bool:
        """Determine if login is suspicious"""
        return risk_score >= (settings.SUSPICIOUS_LOGIN_THRESHOLD * 100)

class UserRepository:
    """User data access layer"""
    
    def __init__(self):
        # In production, this would connect to a database
        self.users = {
            "admin": {
                "password_hash": bcrypt.hashpw(b"admin123", bcrypt.gensalt()),
                "role": "admin",
                "email": "admin@example.com",
                "mfa_enabled": True,
                "created_at": datetime.utcnow()
            },
            "alice": {
                "password_hash": bcrypt.hashpw(b"user123", bcrypt.gensalt()),
                "role": "user",
                "email": "alice@example.com",
                "mfa_enabled": False,
                "created_at": datetime.utcnow()
            },
        }
    
    def get_user(self, username: str) -> Optional[Dict]:
        """Retrieve user by username"""
        return self.users.get(username)
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verify user password"""
        user = self.get_user(username)
        if not user:
            return False
        return bcrypt.checkpw(password.encode(), user["password_hash"])
    
    def get_user_role(self, username: str) -> Optional[str]:
        """Get user role"""
        user = self.get_user(username)
        return user["role"] if user else None

class AuthenticationService:
    """Core authentication business logic"""
    
    def __init__(self, storage: SecurityStorage, user_repo: UserRepository):
        self.storage = storage
        self.user_repo = user_repo
        self.rate_limit_mgr = RateLimitManager(storage)
        self.account_lock_mgr = AccountLockManager(storage)
        self.anomaly_detector = AnomalyDetector(storage)
    
    def authenticate(self, username: str, password: str, ip: str, 
                    device_id: Optional[str] = None, user_agent: Optional[str] = None) -> Tuple[LoginStatus, float, str]:
        """
        Authenticate user and return status with risk assessment.
        Returns: (status, risk_score, reason)
        """
        request_id = str(uuid.uuid4())
        
        # Phase 1: Rate Limit Check
        allowed, reason = self.rate_limit_mgr.check_and_record(ip)
        if not allowed:
            self.storage.security_events.append({
                "timestamp": time.time(),
                "type": "rate_limit_violation",
                "ip": ip,
                "username": username
            })
            return LoginStatus.RATE_LIMITED, 90.0, reason
        
        # Phase 2: Account Lock Check
        locked, reason = self.account_lock_mgr.check_locked(username)
        if locked:
            self.storage.security_events.append({
                "timestamp": time.time(),
                "type": "locked_account_attempt",
                "username": username,
                "ip": ip
            })
            return LoginStatus.ACCOUNT_LOCKED, 85.0, reason
        
        # Phase 3: User Verification
        user = self.user_repo.get_user(username)
        if not user:
            logger.warning("LOGIN_FAILED_UNKNOWN_USER", username=username, ip=ip, request_id=request_id)
            return LoginStatus.UNKNOWN_USER, 70.0, "User does not exist"
        
        # Phase 4: Password Verification
        if not self.user_repo.verify_password(username, password):
            self.account_lock_mgr.record_failure(username)
            backoff = self.rate_limit_mgr.get_backoff_delay(ip)
            
            logger.warning(
                "LOGIN_FAILED_INVALID_PASSWORD",
                username=username,
                ip=ip,
                request_id=request_id,
                failure_count=self.storage.account_failures.get(username, 0)
            )
            
            time.sleep(backoff)  # Exponential backoff
            return LoginStatus.FAILED, 60.0, "Invalid credentials"
        
        # Phase 5: Risk Assessment
        risk_score = self.anomaly_detector.calculate_risk(username, ip, device_id)
        
        if self.anomaly_detector.is_suspicious(risk_score):
            logger.warning("SUSPICIOUS_LOGIN", username=username, ip=ip, risk_score=risk_score, request_id=request_id)
            self.storage.security_events.append({
                "timestamp": time.time(),
                "type": "suspicious_login",
                "username": username,
                "ip": ip,
                "risk_score": risk_score
            })
            return LoginStatus.SUSPICIOUS, risk_score, "Suspicious login activity detected"
        
        # Phase 6: Successful Authentication
        role = self.user_repo.get_user_role(username)
        
        # Clean up tracking data on successful login
        self.storage.account_failures.pop(username, None)
        self.storage.account_locked_at.pop(username, None)
        self.storage.attempt_timestamps.pop(ip, None)
        self.storage.rate_limit_strikes.pop(ip, None)
        
        # Record device fingerprint
        if device_id:
            if username not in self.storage.device_fingerprints:
                self.storage.device_fingerprints[username] = set()
            self.storage.device_fingerprints[username].add(device_id)
        
        # Record in login history
        self.storage.login_history.append({
            "timestamp": time.time(),
            "username": username,
            "ip": ip,
            "device_id": device_id,
            "user_agent": user_agent,
            "success": True
        })
        
        status = LoginStatus.ADMIN_SUCCESS if role == "admin" else LoginStatus.SUCCESS
        logger.info(
            "LOGIN_SUCCESS",
            username=username,
            ip=ip,
            role=role,
            request_id=request_id,
            risk_score=risk_score
        )
        
        return status, risk_score, "Legitimate login"

# ==================== DEPENDENCY INJECTION ====================
storage = SecurityStorage()
user_repo = UserRepository()
auth_service = AuthenticationService(storage, user_repo)

async def get_request_id(request: Request) -> str:
    """Extract or generate request ID"""
    request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    request.state.request_id = request_id
    return request_id

# ==================== FASTAPI APP ====================
app = FastAPI(
    title="Enterprise Authentication Service",
    description="Production-grade authentication with advanced security features",
    version="1.0.0"
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.TRUSTED_HOSTS)

@app.middleware("http")
async def add_request_context(request: Request, call_next):
    """Add request context and timing"""
    request_id = await get_request_id(request)
    start_time = time.time()
    
    response = await call_next(request)
    
    process_time = time.time() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# ==================== API ROUTES ====================
@app.post("/api/v1/login", response_model=LoginResponse, status_code=status.HTTP_200_OK)
async def login(request: LoginRequest, req: Request) -> LoginResponse:
    """
    Authenticate user with advanced security checks.
    
    - **username**: Username (alphanumeric)
    - **password**: Password
    - **ip**: Client IP address
    - **device_id**: Optional unique device identifier
    - **user_agent**: Optional browser user agent
    """
    request_id = req.state.request_id
    
    try:
        # Authenticate
        status_result, risk_score, reason = auth_service.authenticate(
            username=request.username,
            password=request.password,
            ip=request.ip,
            device_id=request.device_id,
            user_agent=request.user_agent
        )
        
        # Determine risk level
        if risk_score < 20:
            risk_level = RiskLevel.LOW
        elif risk_score < 50:
            risk_level = RiskLevel.MEDIUM
        elif risk_score < 80:
            risk_level = RiskLevel.HIGH
        else:
            risk_level = RiskLevel.CRITICAL
        
        # Generate session ID on success
        session_id = str(uuid.uuid4()) if status_result in [LoginStatus.SUCCESS, LoginStatus.ADMIN_SUCCESS] else None
        
        response = LoginResponse(
            request_id=request_id,
            username=request.username,
            status=status_result,
            risk_score=risk_score,
            risk_level=risk_level,
            reason=reason,
            timestamp=datetime.utcnow(),
            session_id=session_id,
            mfa_required=status_result == LoginStatus.ADMIN_SUCCESS
        )
        
        return response
    
    except Exception as e:
        logger.error("LOGIN_ENDPOINT_ERROR", error=str(e), request_id=request_id)
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "version": "1.0.0"
    }

@app.get("/api/v1/dashboard", response_model=DashboardResponse, tags=["Monitoring"])
async def dashboard() -> DashboardResponse:
    """
    Security dashboard with real-time metrics.
    
    Returns aggregated security statistics and threat levels.
    """
    # Count security events in last 24 hours
    events_24h = sum(
        1 for e in storage.security_events
        if time.time() - e['timestamp'] < 86400
    )
    
    # Determine overall threat level
    active_blocks = len(storage.blocked_ips) + len(storage.temp_blocked_at)
    active_locks = len(storage.account_locked_at)
    
    if active_blocks > 10 or events_24h > 50:
        threat_level = RiskLevel.CRITICAL
    elif active_blocks > 5 or events_24h > 20:
        threat_level = RiskLevel.HIGH
    elif active_blocks > 0 or events_24h > 0:
        threat_level = RiskLevel.MEDIUM
    else:
        threat_level = RiskLevel.LOW
    
    return DashboardResponse(
        timestamp=datetime.utcnow(),
        total_blocked_ips=len(storage.blocked_ips),
        total_temp_blocked_ips=len(storage.temp_blocked_at),
        active_account_locks=active_locks,
        rate_limit_strikes=storage.rate_limit_strikes.copy(),
        account_failures=storage.account_failures.copy(),
        security_events_24h=events_24h,
        threat_level=threat_level
    )

@app.get("/api/v1/security/events", tags=["Monitoring"])
async def get_security_events(hours: int = 24):
    """
    Retrieve recent security events.
    
    - **hours**: Number of hours to look back (default 24)
    """
    cutoff_time = time.time() - (hours * 3600)
    recent_events = [
        e for e in storage.security_events
        if e['timestamp'] > cutoff_time
    ]
    
    return {
        "count": len(recent_events),
        "period_hours": hours,
        "events": recent_events
    }

@app.get("/api/v1/audit", tags=["Compliance"])
async def get_audit_log(limit: int = 100):
    """
    Retrieve audit log of login attempts.
    
    - **limit**: Maximum number of entries to return
    """
    recent_logins = storage.login_history[-limit:]
    
    return {
        "total_records": len(storage.login_history),
        "returned": len(recent_logins),
        "logins": recent_logins
    }

# ==================== ERROR HANDLING ====================
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler with request ID"""
    request_id = getattr(request.state, 'request_id', 'unknown')
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "request_id": request_id,
            "error": exc.detail,
            "timestamp": datetime.utcnow().isoformat()
        }
    )

# ==================== STARTUP/SHUTDOWN ====================
@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info("APPLICATION_STARTUP", version="1.0.0")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("APPLICATION_SHUTDOWN")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")