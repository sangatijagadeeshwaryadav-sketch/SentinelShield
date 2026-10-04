"""
SentinelShield Web Server

Main entry point for the SentinelShield
Intrusion Detection and Web Protection System.
"""

from flask import Flask, request, jsonify, render_template

from waf import inspect_request

import os
from collections import Counter


app = Flask(__name__)


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

LOG_FILE = os.path.join(
    PROJECT_ROOT,
    "logs",
    "security.log"
)


# ============================================================
# REQUEST DATA COLLECTION
# ============================================================

def get_request_data():

    return {
        "method": request.method,
        "path": request.path,
        "url": request.url,
        "query_parameters": request.args.to_dict(),
        "form_data": request.form.to_dict(),
        "json_data": request.get_json(silent=True),
        "headers": dict(request.headers),
        "ip_address": request.remote_addr
    }


# ============================================================
# READ SECURITY LOG
# ============================================================

def read_security_logs():

    events = []

    if not os.path.exists(LOG_FILE):
        return events

    with open(
        LOG_FILE,
        "r",
        encoding="utf-8"
    ) as log_file:

        lines = log_file.readlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        try:

            timestamp, event_data = line.split(
                " | ",
                1
            )

            fields = {}

            parts = event_data.split(" | ")

            for part in parts:

                if "=" in part:

                    key, value = part.split(
                        "=",
                        1
                    )

                    fields[key] = value

            events.append({
                "time": timestamp,
                "ip": fields.get(
                    "IP",
                    "Unknown"
                ),
                "attack": fields.get(
                    "Attack",
                    "Unknown"
                ),
                "pattern": fields.get(
                    "Pattern",
                    "Unknown"
                ),
                "path": fields.get(
                    "Path",
                    "Unknown"
                ),
                "action": fields.get(
                    "Action",
                    "Unknown"
                ),
                "severity": fields.get(
                    "Severity",
                    "Unknown"
                )
            })

        except ValueError:

            continue

    return events


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
def dashboard():

    events = read_security_logs()

    total_events = len(events)

    blocked_events = sum(
        1
        for event in events
        if event["action"] == "BLOCK"
    )

    rate_limit_events = sum(
        1
        for event in events
        if event["action"] == "RATE_LIMIT"
    )

    attack_counter = Counter(
        event["attack"]
        for event in events
    )

    recent_events = list(
        reversed(events[-10:])
    )

    return render_template(
        "dashboard.html",
        total_events=total_events,
        blocked_events=blocked_events,
        rate_limit_events=rate_limit_events,
        attack_categories=len(attack_counter),
        attack_distribution=dict(attack_counter),
        recent_events=recent_events
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():

    return jsonify({
        "project": "SentinelShield",
        "status": "running",
        "message": "Advanced Intrusion Detection & Web Protection System",
        "dashboard": "/dashboard"
    })


# ============================================================
# BASIC TEST
# ============================================================

@app.route("/test")
def test():

    return jsonify({
        "message": "SentinelShield test endpoint is working",
        "method": request.method,
        "ip": request.remote_addr
    })


# ============================================================
# REQUEST INSPECTION
# ============================================================

@app.route("/inspect")
def inspect():

    request_data = get_request_data()

    return jsonify({
        "status": "Request inspected",
        "request_information": request_data
    })


# ============================================================
# PROTECTED ENDPOINT
# ============================================================

@app.route("/protected")
def protected():

    request_data = get_request_data()

    waf_result = inspect_request(
        request_data
    )

    # Rate limited
    if waf_result["action"] == "RATE_LIMIT":

        return jsonify({
            "status": "RATE LIMITED",
            "message": "Too many requests from this IP address.",
            "security_event": waf_result
        }), 429

    # Malicious request
    if not waf_result["allowed"]:

        return jsonify({
            "status": "BLOCKED",
            "message": "SentinelShield blocked the request.",
            "security_event": waf_result
        }), 403

    # Allowed request
    return jsonify({
        "status": "ALLOWED",
        "message": "Request passed SentinelShield security inspection.",
        "security_event": waf_result
    })


# ============================================================
# POST ENDPOINT
# ============================================================

@app.route("/submit", methods=["POST"])
def submit():

    request_data = get_request_data()

    waf_result = inspect_request(
        request_data
    )

    # Rate limited
    if waf_result["action"] == "RATE_LIMIT":

        return jsonify({
            "status": "RATE LIMITED",
            "message": "Too many requests from this IP address.",
            "security_event": waf_result
        }), 429

    # Malicious request
    if not waf_result["allowed"]:

        return jsonify({
            "status": "BLOCKED",
            "message": "SentinelShield blocked the POST request.",
            "security_event": waf_result
        }), 403

    # Allowed request
    return jsonify({
        "status": "ALLOWED",
        "message": "POST request passed SentinelShield inspection.",
        "security_event": waf_result
    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )