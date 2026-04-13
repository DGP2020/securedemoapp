# secure docker app 🐋
# Secure Docker-Based Intrusion Detection & Prevention System

## Overview
A lightweight system that detects and blocks malicious traffic in real-time using log analysis and automated Nginx rule updates.

## Features
- HTTPS reverse proxy (Nginx)
- Real-time log monitoring
- Brute-force & scan detection
- Automatic IP blocking (fail-safe)
- Rate limiting for attack prevention

## How it works
1. Requests hit Nginx
2. Logs are generated
3. Monitor analyzes logs
4. Suspicious IP detected
5. IP added to blacklist
6. Nginx reloads safely


## Tech stack
Docker, Python, Nginx,JWT
