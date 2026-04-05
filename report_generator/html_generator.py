"""
HTML report generation using Jinja2 and Bootstrap.

Creates professional, styled HTML reports.
"""

from jinja2 import Template
import logging
from datetime import datetime

from schema import MergedReport

logger = logging.getLogger(__name__)


class HTMLGenerator:
    """Generate HTML reports from MergedReport."""

    def __init__(self):
        self.template = self._get_template()

    def generate(self, report: MergedReport) -> str:
        """
        Generate HTML report.

        Args:
            report: MergedReport to render

        Returns:
            HTML string
        """
        context = self._build_context(report)
        html = self.template.render(context)
        return html

    def export_file(self, report: MergedReport, file_path: str) -> None:
        """
        Export report to HTML file.

        Args:
            report: MergedReport to export
            file_path: Path to write HTML file
        """
        html = self.generate(report)
        with open(file_path, "w") as f:
            f.write(html)
        logger.info(f"HTML report exported to {file_path}")

    def _build_context(self, report: MergedReport) -> dict:
        """Build template context."""
        return {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "file_name": report.file_name,
            "primary_hash": report.primary_hash,
            "all_hashes": report.all_hashes,
            "consensus_verdict": report.consensus_verdict,
            "verdict_class": self._verdict_class(report.consensus_verdict),
            "risk_score": report.risk.overall_score if report.risk else 0,
            "risk_level": report.risk.threat_level.value if report.risk else "unknown",
            "risk_level_class": self._risk_class(report.risk.threat_level.value if report.risk else ""),
            "risk_reasoning": report.risk.reasoning if report.risk else [],
            "verdicts_by_source": report.verdicts,
            "detections": self._format_detections(report),
            "iocs": report.iocs,
            "ioc_count": len(report.iocs),
            "network_activities": report.network_activities,
            "network_count": len(report.network_activities),
            "processes": report.processes,
            "process_count": len(report.processes),
            "file_operations": report.file_operations,
            "file_ops_count": len(report.file_operations),
            "mitre_techniques": report.mitre_techniques,
            "mitre_count": len(report.mitre_techniques),
            "sources_count": len(report.source_reports),
            "summary": report.summary(),
        }

    def _verdict_class(self, verdict: str) -> str:
        """Get Bootstrap class for verdict."""
        verdict_lower = str(verdict).lower()
        if "malicious" in verdict_lower:
            return "danger"
        elif "suspicious" in verdict_lower:
            return "warning"
        elif "clean" in verdict_lower:
            return "success"
        else:
            return "info"

    def _risk_class(self, risk_level: str) -> str:
        """Get Bootstrap class for risk level."""
        risk_lower = str(risk_level).lower()
        if "critical" in risk_lower:
            return "danger"
        elif "high" in risk_lower:
            return "warning"
        elif "medium" in risk_lower:
            return "warning"
        elif "low" in risk_lower:
            return "info"
        else:
            return "secondary"

    def _format_detections(self, report: MergedReport) -> list:
        """Format detections for display."""
        detections = []
        for source, dets in report.all_detections.items():
            for det in dets:
                detections.append({"source": source.value, "detection": det})
        return detections

    def _get_template(self) -> Template:
        """Get Jinja2 template for HTML report."""
        return Template("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {{ file_name }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        :root {
            --danger-color: #dc3545;
            --warning-color: #ffc107;
            --success-color: #28a745;
            --info-color: #17a2b8;
        }
        body {
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }
        .header h1 {
            margin: 0;
            font-size: 2.5rem;
        }
        .verdict-badge {
            display: inline-block;
            font-size: 1.2rem;
            padding: 10px 20px;
            border-radius: 5px;
            margin-top: 15px;
        }
        .verdict-badge.danger {
            background-color: var(--danger-color);
            color: white;
        }
        .verdict-badge.warning {
            background-color: var(--warning-color);
            color: black;
        }
        .verdict-badge.success {
            background-color: var(--success-color);
            color: white;
        }
        .card {
            margin-bottom: 20px;
            border: none;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
        }
        .card-header {
            background-color: #f8f9fa;
            font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }
        .risk-score-display {
            font-size: 3rem;
            font-weight: bold;
            text-align: center;
            padding: 20px;
        }
        .risk-meter {
            width: 100%;
            height: 30px;
            background-color: #e9ecef;
            border-radius: 15px;
            overflow: hidden;
            margin: 10px 0;
        }
        .risk-meter-fill {
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.8rem;
        }
        table {
            font-size: 0.95rem;
        }
        .ioc-table td {
            padding: 10px;
            word-break: break-all;
        }
        .ioc-type-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .hash-display {
            font-family: monospace;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            word-break: break-all;
            border-left: 4px solid #667eea;
        }
        .mitre-badge {
            display: inline-block;
            background-color: #e7f3ff;
            border: 1px solid #b3d9ff;
            color: #004085;
            padding: 6px 12px;
            border-radius: 4px;
            margin: 5px 5px 5px 0;
            font-size: 0.9rem;
        }
        .network-item {
            background-color: #f8f9fa;
            padding: 12px;
            border-left: 4px solid #667eea;
            margin-bottom: 10px;
            border-radius: 4px;
        }
        .process-tree {
            margin: 10px 0;
            padding: 10px;
            background-color: #f8f9fa;
            border-left: 4px solid #667eea;
            border-radius: 4px;
        }
        .footer {
            text-align: center;
            color: #6c757d;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #dee2e6;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <!-- Header -->
        <div class="header">
            <h1>🔒 Malware Analysis Report</h1>
            <p style="margin: 10px 0;">Generated: {{ timestamp }}</p>
            <div class="verdict-badge {{ verdict_class }}">
                Verdict: {{ consensus_verdict | upper }}
            </div>
        </div>

        <!-- Executive Summary -->
        <div class="row">
            <div class="col-md-8">
                <div class="card">
                    <div class="card-header">
                        📋 File Information
                    </div>
                    <div class="card-body">
                        <p><strong>File Name:</strong> {{ file_name }}</p>
                        <p><strong>Primary Hash (SHA256):</strong></p>
                        <div class="hash-display">{{ primary_hash }}</div>
                        {% if all_hashes %}
                        <p style="margin-top: 15px;"><strong>Additional Hashes:</strong></p>
                        {% for hash_type, hash_value in all_hashes.items() %}
                        <p style="margin: 5px 0;">
                            <strong>{{ hash_type.upper() }}:</strong><br>
                            <span class="hash-display">{{ hash_value }}</span>
                        </p>
                        {% endfor %}
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        ⚠️ Risk Score
                    </div>
                    <div class="card-body">
                        <div class="risk-score-display {{ risk_level_class }}">
                            {{ risk_score | int }}
                        </div>
                        <div class="risk-meter">
                            <div class="risk-meter-fill {{ risk_level_class }}" 
                                 style="width: {{ risk_score }}%; background-color: {% if risk_score > 80 %}#dc3545{% elif risk_score > 60 %}#ffc107{% elif risk_score > 40 %}#ff9800{% else %}#28a745{% endif %};">
                                {{ risk_level | upper }}
                            </div>
                        </div>
                        {% if risk_reasoning %}
                        <p style="margin-top: 15px; font-size: 0.9rem;"><strong>Analysis:</strong></p>
                        <ul style="font-size: 0.9rem; margin: 0;">
                            {% for reason in risk_reasoning %}
                            <li>{{ reason }}</li>
                            {% endfor %}
                        </ul>
                        {% endif %}
                    </div>
                </div>
            </div>
        </div>

        <!-- Verdict Summary -->
        <div class="card">
            <div class="card-header">
                🔍 Analysis Verdict
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>Source</th>
                                <th>Verdict</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for source, verdict in verdicts_by_source.items() %}
                            <tr>
                                <td>{{ source.value }}</td>
                                <td>
                                    <span class="badge bg-{{ 'danger' if 'malicious' in verdict.lower() else 'warning' if 'suspicious' in verdict.lower() else 'success' }}">
                                        {{ verdict }}
                                    </span>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- Detections -->
        {% if detections %}
        <div class="card">
            <div class="card-header">
                🛡️ AV Detections ({{ detections | length }})
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm table-hover">
                        <thead>
                            <tr>
                                <th>Engine</th>
                                <th>Detection</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for det in detections %}
                            <tr>
                                <td><small>{{ det.source }}</small></td>
                                <td><small>{{ det.detection }}</small></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {% endif %}

        <!-- IOCs -->
        {% if iocs %}
        <div class="card">
            <div class="card-header">
                🎯 Indicators of Compromise ({{ ioc_count }})
            </div>
            <div class="card-body">
                <div class="table-responsive">
                    <table class="table table-sm ioc-table">
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Value</th>
                                <th>Confidence</th>
                                <th>Sources</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for ioc in iocs %}
                            <tr>
                                <td>
                                    <span class="ioc-type-badge" style="
                                        background-color: {% if ioc.ioc_type.value == 'ip' %}#b3e5fc{% elif ioc.ioc_type.value == 'domain' %}#c8e6c9{% elif ioc.ioc_type.value == 'url' %}#ffe0b2{% else %}#d1c4e9{% endif %};
                                        color: {% if ioc.ioc_type.value == 'ip' %}#01579b{% elif ioc.ioc_type.value == 'domain' %}#1b5e20{% elif ioc.ioc_type.value == 'url' %}#e65100{% else %}#311b92{% endif %};
                                    ">
                                        {{ ioc.ioc_type.value | upper }}
                                    </span>
                                </td>
                                <td><code style="font-size: 0.85rem;">{{ ioc.value }}</code></td>
                                <td>{{ (ioc.confidence * 100) | int }}%</td>
                                <td>
                                    {% for source in ioc.source %}
                                    <small class="badge bg-info">{{ source.value }}</small>
                                    {% endfor %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        {% endif %}

        <!-- Network Activity -->
        {% if network_activities %}
        <div class="card">
            <div class="card-header">
                🌐 Network Activity ({{ network_count }})
            </div>
            <div class="card-body">
                {% for activity in network_activities %}
                <div class="network-item">
                    <strong>{{ activity.protocol | upper }}</strong>
                    {% if activity.domain %}
                    → <code>{{ activity.domain }}</code>
                    {% endif %}
                    {% if activity.destination_ip %}
                    → <code>{{ activity.destination_ip }}:{{ activity.destination_port or 'N/A' }}</code>
                    {% endif %}
                    {% if activity.url %}
                    <br><small><code>{{ activity.url }}</code></small>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Processes -->
        {% if processes %}
        <div class="card">
            <div class="card-header">
                ⚙️ Process Execution ({{ process_count }})
            </div>
            <div class="card-body">
                {% for process in processes %}
                <div class="process-tree">
                    <strong>{{ process.name }}</strong> (PID: {{ process.pid or 'N/A' }})
                    {% if process.command_line %}
                    <br><small><code>{{ process.command_line }}</code></small>
                    {% endif %}
                    {% if process.parent_pid %}
                    <br><small>Parent PID: {{ process.parent_pid }}</small>
                    {% endif %}
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- MITRE ATT&CK -->
        {% if mitre_techniques %}
        <div class="card">
            <div class="card-header">
                🗂️ MITRE ATT&CK Techniques ({{ mitre_count }})
            </div>
            <div class="card-body">
                {% for technique in mitre_techniques %}
                <div class="mitre-badge" title="{{ technique.description or '' }}">
                    <strong>{{ technique.technique_id }}</strong>: {{ technique.technique_name }}
                    <br><small>Tactic: {{ technique.tactic }}</small>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}

        <!-- Metadata -->
        <div class="card">
            <div class="card-header">
                ℹ️ Analysis Metadata
            </div>
            <div class="card-body">
                <p><strong>Total Sources:</strong> {{ sources_count }}</p>
                <p><strong>Total IOCs:</strong> {{ ioc_count }}</p>
                <p><strong>Network Connections:</strong> {{ network_count }}</p>
                <p><strong>Processes:</strong> {{ process_count }}</p>
                <p><strong>MITRE Techniques:</strong> {{ mitre_count }}</p>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Generated by <strong>Malware Analysis Automation Pipeline</strong></p>
            <p><small>All timestamps in UTC. Report generated {{ timestamp }}</small></p>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
""")
