# SecureAuth Monitor 🔐

SecureAuth Monitor is a Python-based authentication security system
that defends against brute-force attacks, credential abuse, and
automated login threats using a layered, defense-in-depth approach.

It simulates how real-world systems monitor authentication behavior,
detect abuse patterns, and apply escalating protections.

---

## 🧠 Problem

Authentication endpoints are among the most targeted components of
modern applications. Attackers commonly use brute-force attempts,
credential stuffing, and IP rotation to bypass weak defenses.

Single-layer protections are insufficient against these threats.

---

## 🛡️ Solution

SecureAuth Monitor combines multiple defensive controls to protect
authentication systems while remaining fair to legitimate users.

The system tracks login behavior, applies rate limits, escalates
penalties for abusive sources, and resets state after successful
authentication.

---

## 🚀 Key Features
- Sliding-window rate limiting per IP
- Temporary and permanent IP blocking with escalation
- Account-level lockout independent of IP
- Progressive delay on repeated failures
- Secure password verification using bcrypt
- Automatic state reset after successful login
- Detailed logging of authentication events

---

## 🔁 Authentication Flow

1. Login request received
2. Permanent and temporary IP block checks
3. Account-level lock check
4. Sliding-window rate limit evaluation
5. Password verification (bcrypt)
6. Authorization check (RBAC)
7. State reset or escalation based on outcome
8. Event logging

--- 

## 🎯 Why This Project Exists

Most authentication demos stop at password checks.
Real-world systems fail because attackers exploit **rate limits, IP rotation,
credential stuffing, and weak escalation logic**.

This project was built to simulate **how production-grade authentication systems
actually defend themselves**, using layered controls, progressive penalties,
and clear observability — not just happy-path logins.

---

## 🧱 Architecture & Attack Flow

The system is designed with layered security checks to handle both
legitimate users and hostile traffic fairly.

**Request lifecycle:**

1. Incoming request is checked against permanent IP bans
2. Temporary IP blocks are evaluated
3. Account lock status is verified
4. Sliding-window rate limiting is applied per IP
5. Password verification using bcrypt
6. Authorization check (RBAC)
7. Security state is reset on success or escalated on failure
8. All events are logged for audit and analysis

This layered approach prevents single-point failures and makes common
attack techniques such as brute-force, IP rotation, and credential
stuffing ineffective.

 ---

 ## Documentation
- [Threat Model](docs/THREAT_MODEL.md)

---

### 🔄 Authentication Flow (High-Level)
```mermaid
flowchart TD
    A["Client / Attacker"] --> B["IP Block Check"]
    B --> C["Account Lock Check"]
    C --> D["Rate Limiter"]
    D --> E["Password Verification"]
    E --> F["Authorization (RBAC)"]
    F --> G["Logging & State Update"]

    G -->|Success| H["Reset State"]
    G -->|Failure| I["Escalate Penalties"]
```
---

## 🧠 Threat Model

This project defends against:
- **Brute-force attacks** — rapid password guessing
- **Credential stuffing** — reused leaked credentials
- **Automated abuse** — scripted login attempts
- **IP rotation attacks** — bypassing IP-only defenses

---

## 🔐 Security Design Principles

This project follows core security engineering principles:

- **Defense in Depth** – Multiple layered controls instead of a single point of failure
- **Fail Securely** – Failed authentication increases restrictions, never access
- **Least Privilege** – Authorization enforced after authentication (RBAC)
- **Rate Limiting & Abuse Resistance** – Prevents brute-force and automated attacks
- **Observability** – All attempts are logged for detection and analysis

---

## 🛠️ Tech Stack
- Python 3
- bcrypt for secure password hashing
- Time-based sliding window algorithms
- Defensive security logic
- Git & GitHub

---

## 🎯 Why This Project Matters

This project reflects how production systems in SaaS platforms,
financial services, and enterprise applications approach
authentication security.

It emphasizes **resilience, layered defenses, and user fairness**
rather than relying on a single blocking mechanism.

---
## Design Philosophy
This project follows a defense-in-depth approach.
Each authentication layer is designed to fail safely,
limit attacker progress, and protect legitimate users
without relying on a single control.

---

## Limitations
- This is a simulated authentication system, not production-ready
- No MFA or CAPTCHA implemented
- Uses in-memory state instead of persistent storage

---

## 📌 Future Improvements
- External persistent storage (Redis / database)
- REST API integration
- Alerting via email or webhooks
- Distributed rate limiting
- Visualization dashboard
