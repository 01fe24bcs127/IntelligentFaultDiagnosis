# diagnosis/fault_rules.py

"""
Approved fault definitions for the Intelligent Fault Diagnosis System.

These definitions are based on our Fault Catalogue.
This file contains rule configuration, not the detection logic.
"""

FAULT_RULES = {
    "DNS-01": {
        "protocol": "DNS",
        "name": "NXDOMAIN Response",
        "description": "DNS query returned NXDOMAIN, indicating the requested domain does not exist.",
        "source_log": "dns.log",
        "condition": {
            "field": "rcode_name",
            "operator": "equals",
            "value": "NXDOMAIN",
        },
        "trigger": "Any occurrence of NXDOMAIN",
        "escalation": {
            "severity": "High",
            "count": 5,
            "window_seconds": 60,
            "group_by": "client_ip",
        },
    }
}