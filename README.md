# SecureAuth Monitor 🔐

SecureAuth Monitor is a Python-based authentication monitoring tool
that detects brute-force login attempts and logs suspicious activity.
It simulates how real-world systems track and respond to repeated
failed login attempts.

---

## 🚀 Features
- Logs every login attempt with timestamp, IP address, and status
- Detects repeated failed login attempts from the same IP
- Raises alerts for suspicious (brute-force-like) behavior
- Uses persistent logging similar to real authentication systems

---

## 🧠 How It Works
- Each login attempt is recorded in a log file
- Failed attempts are counted per IP address
- If failures exceed a threshold (default: 3), an alert is triggered
- A successful login resets the failure counter for that IP

---

## ▶️ Example Output

# SecureAuth Monitor 🔐

SecureAuth Monitor is a Python-based authentication monitoring tool
that detects brute-force login attempts and logs suspicious activity.
It simulates how real-world systems track and respond to repeated
failed login attempts.

---

## 🚀 Features
- Logs every login attempt with timestamp, IP address, and status
- Detects repeated failed login attempts from the same IP
- Raises alerts for suspicious (brute-force-like) behavior
- Uses persistent logging similar to real authentication systems

---

## 🧠 How It Works
- Each login attempt is recorded in a log file
- Failed attempts are counted per IP address
- If failures exceed a threshold (default: 3), an alert is triggered
- A successful login resets the failure counter for that IP

---

## ▶️ Example Output

# SecureAuth Monitor 🔐

SecureAuth Monitor is a Python-based authentication monitoring tool
that detects brute-force login attempts and logs suspicious activity.
It simulates how real-world systems track and respond to repeated
failed login attempts.

---

## 🚀 Features
- Logs every login attempt with timestamp, IP address, and status
- Detects repeated failed login attempts from the same IP
- Raises alerts for suspicious (brute-force-like) behavior
- Uses persistent logging similar to real authentication systems

---

## 🧠 How It Works
- Each login attempt is recorded in a log file
- Failed attempts are counted per IP address
- If failures exceed a threshold (default: 3), an alert is triggered
- A successful login resets the failure counter for that IP

---

## ▶️ Example Output

Login failed ❌
Login failed ❌
⚠️ ALERT: Suspicious activity detected from IP 192.168.1.10

---

## 🛠 Tech Stack
- Python 3
- File-based logging
- Git & GitHub for version control

---

## 🎯 Use Case
This project demonstrates core defensive security concepts used in:
- Authentication systems
- Brute-force attack detection
- Security logging and monitoring

## 🧠 Threat Model

This project focuses on defending authentication systems against
common real-world attacks, including:

- **Brute-force attacks** – rapid password guessing
- **Credential stuffing** – reused leaked credentials
- **Abusive login attempts** – automated and scripted abuse
- **IP rotation attacks** – bypassing single-layer IP limits

The goal is not just detection, but **resilient abuse prevention**.

---

## 🛡️ Defense Layers Implemented

This system uses a **defense-in-depth approach**:

1. **Rate Limiting**
   - Sliding window tracking per IP
   - Prevents high-speed automated attacks

2. **Temporary IP Blocking**
   - Cooldown blocks after rate-limit violations
   - Automatically lifted after time window

3. **Permanent IP Ban**
   - Escalation after repeated abuse
   - Stops persistent malicious sources

4. **Account-Level Lockout**
   - Locks user accounts after repeated failed attempts
   - Protects users even when attackers rotate IPs

5. **Progressive Failure Delay**
   - Adds artificial delay on failed logins
   - Makes brute-force attacks impractical

6. **State Reset on Success**
   - Clears penalties after legitimate login
   - Prevents unfair lockouts

## 🎯 Why This Project Matters

Authentication endpoints are one of the most attacked parts of any system.
Relying on a single defense (like rate limiting alone) is not sufficient
against modern attack patterns.

This project demonstrates how **layered security controls work together**
to protect users and infrastructure in real-world systems.

It reflects how production systems in banking, SaaS platforms, and
enterprise applications approach authentication security — focusing on
**resilience, fairness, and abuse prevention**, not just blocking traffic.

---

## 📌 Future Improvements
- IP blocking after repeated failures
- Time-based rate limiting
- Email or webhook alerts
- REST API integration
