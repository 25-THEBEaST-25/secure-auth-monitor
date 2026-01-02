# System Architecture

SecureAuth Monitor is a layered authentication defense system designed
to evaluate login requests through progressive security controls.

The system prioritizes abuse detection, escalation logic, and
observability over simple allow/deny decisions.

---

## High-Level Flow

1. Incoming authentication request
2. Permanent IP block check
3. Temporary IP block check
4. Account-level lock verification
5. Sliding-window rate limiting
6. Password verification (bcrypt)
7. Authorization check (RBAC)
8. State reset or penalty escalation
9. Structured event logging

---

## Design Rationale

The architecture follows a **defense-in-depth** model:

- Early rejection of known malicious sources
- Progressive penalties instead of immediate hard blocks
- Independent IP-level and account-level controls
- Automatic recovery for legitimate users

This prevents single-point failure and reduces false positives.

---

## Trust Boundaries

- Client input is always untrusted
- Authentication logic is centralized
- State tracking is isolated per IP and account
- Successful authentication resets all penalties
