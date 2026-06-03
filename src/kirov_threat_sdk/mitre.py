import re
from typing import Optional

MITRE_TECHNIQUES: dict[str, dict] = {
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "command-and-control",
        "description": "Adversaries communicate using application layer protocols.",
    },
    "T1566": {
        "name": "Phishing",
        "tactic": "initial-access",
        "description": "Adversaries send phishing messages to gain access.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "description": "Adversaries exploit a public-facing application.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
        "description": "Adversaries abuse command interpreters.",
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "tactic": "persistence",
        "description": "Adversaries configure system settings for persistence.",
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "credential-access",
        "description": "Adversaries dump credentials from the OS.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "description": "Adversaries scan for network services.",
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic": "impact",
        "description": "Adversaries destroy data on target systems.",
    },
}


def get_technique(technique_id: str) -> Optional[dict]:
    return MITRE_TECHNIQUES.get(technique_id.upper())


def get_tactic(tactic_name: str) -> list[dict]:
    return [
        info for info in MITRE_TECHNIQUES.values()
        if info["tactic"] == tactic_name.lower()
    ]


_EVENT_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"phish|spearphish|social.engineer", re.I), "T1566", "initial-access"),
    (re.compile(r"exploit|rce|remote.code", re.I), "T1190", "initial-access"),
    (re.compile(r"cmd|powershell|script|bash|shell", re.I), "T1059", "execution"),
    (re.compile(r"dump|credential|hash|lsass", re.I), "T1003", "credential-access"),
    (re.compile(r"scan|port|service.discover", re.I), "T1046", "discovery"),
    (re.compile(r"ransom|wipe|destroy|delete", re.I), "T1485", "impact"),
    (re.compile(r"c2|beacon|callb?ack|command.control", re.I), "T1071", "command-and-control"),
]


def classify_threat(event_type: str, source_ip: str, pattern: str) -> tuple[Optional[str], Optional[str]]:
    for compiled, technique_id, tactic in _EVENT_PATTERNS:
        if compiled.search(event_type) or compiled.search(pattern):
            return technique_id, tactic
    return None, None
