# Threat Model – Secure Auth Monitor

## Assets
- User credentials
- Authentication endpoints
- User accounts and sessions

## Threats
- Brute-force login attempts
- Credential stuffing attacks
- Automated bot attacks
- IP rotation to bypass rate limits

## Attacker Goals
- Gain unauthorized account access
- Enumerate valid usernames
- Bypass authentication controls

## Mitigations Implemented
- Rate limiting on login attempts
- Temporary IP blocking
- Progressive delay after failures
- Account-level lockout mechanisms

## Out of Scope (for now)
- CAPTCHA challenges
- MFA / OTP-based authentication
- Device fingerprinting
