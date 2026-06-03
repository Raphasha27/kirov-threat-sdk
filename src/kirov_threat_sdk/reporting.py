import json
from datetime import datetime, timezone

from kirov_threat_sdk.models import Finding, ScanResult


def generate_markdown_report(result: ScanResult) -> str:
    lines = [
        f"# Scan Report: {result.target}",
        f"**Scan Type:** {result.scan_type}",
        f"**Date:** {datetime.now(timezone.utc).isoformat()}",
        f"**Risk Score:** {result.risk_score}",
        "",
        "## Summary",
        f"- Critical: {result.critical_count}",
        f"- High: {result.high_count}",
        f"- Medium: {result.medium_count}",
        f"- Low: {result.low_count}",
        "",
        "## Findings",
    ]
    for i, f in enumerate(result.findings, 1):
        lines.extend([
            f"### {i}. [{f.severity.value.upper()}] {f.title}",
            f"- **Type:** {f.type}",
            f"- **File:** {f.file_path}:{f.line_number}",
            f"- **CVE:** {f.cve_id or 'N/A'}",
            f"- **CVSS:** {f.cvss_score or 'N/A'}",
            f"- **Remediation:** {f.remediation or 'N/A'}",
            "",
        ])
    return "\n".join(lines)


def generate_json_report(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def generate_html_report(result: ScanResult) -> str:
    findings_html = ""
    for f in result.findings:
        findings_html += f"""
        <div class="finding severity-{f.severity.value}">
            <h3>[{f.severity.value.upper()}] {f.title}</h3>
            <p><strong>Type:</strong> {f.type}</p>
            <p><strong>File:</strong> {f.file_path}:{f.line_number}</p>
            <p><strong>CVE:</strong> {f.cve_id or 'N/A'} | <strong>CVSS:</strong> {f.cvss_score or 'N/A'}</p>
            <p><strong>Remediation:</strong> {f.remediation or 'N/A'}</p>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Scan Report - {result.target}</title>
<style>
body {{ font-family: sans-serif; margin: 2em; }}
.summary {{ display: flex; gap: 1em; }}
.summary-item {{ padding: 1em; border-radius: 4px; color: #fff; }}
.severity-critical {{ background: #dc3545; }}
.severity-high {{ background: #fd7e14; }}
.severity-medium {{ background: #ffc107; }}
.severity-low {{ background: #6c757d; }}
.finding {{ border: 1px solid #ddd; padding: 1em; margin: 1em 0; border-radius: 4px; }}
h1, h2 {{ color: #333; }}
</style>
</head>
<body>
<h1>Scan Report: {result.target}</h1>
<p><strong>Scan Type:</strong> {result.scan_type}</p>
<p><strong>Date:</strong> {datetime.now(timezone.utc).isoformat()}</p>
<p><strong>Risk Score:</strong> {result.risk_score}</p>
<h2>Summary</h2>
<div class="summary">
<div class="summary-item severity-critical">Critical: {result.critical_count}</div>
<div class="summary-item severity-high">High: {result.high_count}</div>
<div class="summary-item severity-medium">Medium: {result.medium_count}</div>
<div class="summary-item severity-low">Low: {result.low_count}</div>
</div>
<h2>Findings</h2>
{findings_html}
</body>
</html>"""


def generate_sarif_output(findings: list[Finding]) -> dict:
    runs = [
        {
            "tool": {
                "driver": {
                    "name": "Kirov Threat SDK",
                    "informationUri": "https://kirovsecuritylabs.com",
                    "version": "1.0.0",
                }
            },
            "results": [
                {
                    "ruleId": f.cve_id or f.title,
                    "level": f.severity.value,
                    "message": {"text": f.title},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path},
                                "region": {
                                    "startLine": f.line_number,
                                },
                            }
                        }
                    ],
                    "properties": {
                        "type": f.type,
                        "cvss_score": f.cvss_score,
                        "remediation": f.remediation,
                        "description": f.title,
                    },
                }
                for f in findings
            ],
        }
    ]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
