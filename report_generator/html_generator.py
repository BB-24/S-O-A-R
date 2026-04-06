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
            "source_reports": self._build_source_reports(report),
            "summary": report.summary(),
        }

    def _build_source_reports(self, report: MergedReport) -> list:
        """Build per-source dashboard cards for side-by-side presentation."""
        source_cards = []
        present_sources = set()

        for source_report in report.source_reports:
            source_name = source_report.source.value
            present_sources.add(source_name)
            source_cards.append(
                {
                    "source": source_name,
                    "title": source_name.replace("_", " ").title(),
                    "verdict": source_report.verdict or "unknown",
                    "verdict_class": self._verdict_class(source_report.verdict or "unknown"),
                    "risk_score": source_report.risk.overall_score if source_report.risk else 0,
                    "threat_level": source_report.risk.threat_level.value if source_report.risk else "informational",
                    "detections": source_report.detections or [],
                    "detection_count": len(source_report.detections or []),
                    "ioc_count": len(source_report.iocs or []),
                    "network_count": len(source_report.network_activities or []),
                    "process_count": len(source_report.processes or []),
                    "sample_iocs": [ioc.value for ioc in (source_report.iocs or [])[:5]],
                }
            )

        # Always show the two primary sources as separate panels on dashboard
        for source_name in ["hybrid_analysis", "virustotal"]:
            if source_name in present_sources:
                continue
            source_cards.append(
                {
                    "source": source_name,
                    "title": source_name.replace("_", " ").title(),
                    "verdict": "no_data",
                    "verdict_class": "secondary",
                    "risk_score": 0,
                    "threat_level": "not_available",
                    "detections": [],
                    "detection_count": 0,
                    "ioc_count": 0,
                    "network_count": 0,
                    "process_count": 0,
                    "sample_iocs": [],
                }
            )

        source_cards.sort(key=lambda card: card["source"])
        return source_cards

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

        <!-- Source-Wise Presentation -->
        {% if source_reports %}
        <div class="card">
            <div class="card-header">
                🧩 Source-Wise Dashboard View
            </div>
            <div class="card-body">
                <div class="row">
                    {% for source_report in source_reports %}
                    <div class="col-md-6 mb-3">
                        <div class="card h-100 border-{{ source_report.verdict_class }}">
                            <div class="card-header d-flex justify-content-between align-items-center">
                                <strong>{{ source_report.title }}</strong>
                                <span class="badge bg-{{ source_report.verdict_class }}">{{ source_report.verdict | upper }}</span>
                            </div>
                            <div class="card-body">
                                <p><strong>Risk Score:</strong> {{ source_report.risk_score | int }}</p>
                                <p><strong>Threat Level:</strong> {{ source_report.threat_level | upper }}</p>
                                <p><strong>Detections:</strong> {{ source_report.detection_count }}</p>
                                <p><strong>IOCs:</strong> {{ source_report.ioc_count }}</p>
                                <p><strong>Network Activities:</strong> {{ source_report.network_count }}</p>
                                <p><strong>Processes:</strong> {{ source_report.process_count }}</p>

                                {% if source_report.detections %}
                                <p class="mb-1"><strong>Top Detections:</strong></p>
                                <ul class="mb-2" style="font-size: 0.9rem;">
                                    {% for detection in source_report.detections[:5] %}
                                    <li>{{ detection }}</li>
                                    {% endfor %}
                                </ul>
                                {% endif %}

                                {% if source_report.sample_iocs %}
                                <p class="mb-1"><strong>Sample IOCs:</strong></p>
                                <ul class="mb-0" style="font-size: 0.9rem; word-break: break-all;">
                                    {% for ioc_value in source_report.sample_iocs %}
                                    <li>{{ ioc_value }}</li>
                                    {% endfor %}
                                </ul>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        {% endif %}

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

        <!-- IOCs with MISP Enrichment -->
        {% if iocs %}
        <div class="card">
            <div class="card-header">
                🎯 Indicators of Compromise ({{ ioc_count }})
            </div>
            <div class="card-body">
                <ul class="nav nav-tabs mb-3" id="iotTabs" role="tablist">
                    <li class="nav-item" role="presentation">
                        <button class="nav-link active" id="all-iocs-tab" data-bs-toggle="tab" data-bs-target="#all-iocs" type="button" role="tab">
                            All IOCs
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="dns-queries-tab" data-bs-toggle="tab" data-bs-target="#dns-queries" type="button" role="tab">
                            DNS Queries
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="dropped-files-tab" data-bs-toggle="tab" data-bs-target="#dropped-files" type="button" role="tab">
                            Dropped Files
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="registry-mods-tab" data-bs-toggle="tab" data-bs-target="#registry-mods" type="button" role="tab">
                            Registry Modifications
                        </button>
                    </li>
                    <li class="nav-item" role="presentation">
                        <button class="nav-link" id="process-behavior-tab" data-bs-toggle="tab" data-bs-target="#process-behavior" type="button" role="tab">
                            Process Behavior
                        </button>
                    </li>
                </ul>

                <div class="tab-content" id="iocTabContent">
                    <!-- All IOCs -->
                    <div class="tab-pane fade show active" id="all-iocs" role="tabpanel">
                        <div class="table-responsive">
                            <table class="table table-sm ioc-table">
                                <thead>
                                    <tr>
                                        <th>Type</th>
                                        <th>Value</th>
                                        <th>Confidence</th>
                                        <th>Threat Level</th>
                                        <th>MISP Intelligence</th>
                                        <th>Sources</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ioc in iocs %}
                                    <tr>
                                        <td>
                                            <span class="ioc-type-badge" style="
                                                background-color: {% if ioc.ioc_type.value == 'ip' %}#b3e5fc{% elif ioc.ioc_type.value == 'domain' %}#c8e6c9{% elif ioc.ioc_type.value == 'url' %}#ffe0b2{% elif ioc.ioc_type.value == 'dns_query' %}#f0f4c3{% elif ioc.ioc_type.value == 'file_dropped' %}#ffccbc{% elif ioc.ioc_type.value == 'registry' %}#d0c4e9{% elif ioc.ioc_type.value == 'process_behavior' %}#bbdefb{% else %}#d1c4e9{% endif %};
                                                color: {% if ioc.ioc_type.value == 'ip' %}#01579b{% elif ioc.ioc_type.value == 'domain' %}#1b5e20{% elif ioc.ioc_type.value == 'url' %}#e65100{% elif ioc.ioc_type.value == 'dns_query' %}#33691e{% elif ioc.ioc_type.value == 'file_dropped' %}#bf360c{% elif ioc.ioc_type.value == 'registry' %}#4a148c{% elif ioc.ioc_type.value == 'process_behavior' %}#0d47a1{% else %}#311b92{% endif %};
                                            ">
                                                {{ ioc.ioc_type.value | upper }}
                                            </span>
                                        </td>
                                        <td><code style="font-size: 0.85rem;">{{ ioc.value }}</code></td>
                                        <td>{{ (ioc.confidence * 100) | int }}%</td>
                                        <td>
                                            {% if ioc.misp_threat_level %}
                                            <span class="badge bg-{% if ioc.misp_threat_level == 'critical' %}danger{% elif ioc.misp_threat_level == 'high' %}warning{% elif ioc.misp_threat_level == 'medium' %}info{% else %}secondary{% endif %}">
                                                {{ ioc.misp_threat_level | upper }}
                                            </span>
                                            {% else %}
                                            <span class="badge bg-light text-dark">-</span>
                                            {% endif %}
                                        </td>
                                        <td>
                                            {% if ioc.is_known_malicious %}
                                            <span class="badge bg-danger">🔴 Malicious</span>
                                            {% endif %}
                                            {% if ioc.misp_tags %}
                                            {% for tag in ioc.misp_tags[:3] %}
                                            <small class="badge bg-secondary">{{ tag }}</small>
                                            {% endfor %}
                                            {% if ioc.misp_tags | length > 3 %}
                                            <small class="badge bg-secondary">+{{ (ioc.misp_tags | length) - 3 }} more</small>
                                            {% endif %}
                                            {% else %}
                                            <small class="text-muted">No MISP data</small>
                                            {% endif %}
                                        </td>
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

                    <!-- DNS Queries -->
                    <div class="tab-pane fade" id="dns-queries" role="tabpanel">
                        {% set dns_iocs = iocs | selectattr('ioc_type.value', 'equalto', 'dns_query') | list %}
                        {% if dns_iocs %}
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Query</th>
                                        <th>Threat Level</th>
                                        <th>Known Bad</th>
                                        <th>Confidence</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ioc in dns_iocs %}
                                    <tr>
                                        <td><code>{{ ioc.value }}</code></td>
                                        <td>
                                            {% if ioc.misp_threat_level %}
                                            <span class="badge bg-{% if ioc.misp_threat_level == 'critical' %}danger{% elif ioc.misp_threat_level == 'high' %}warning{% else %}info{% endif %}">{{ ioc.misp_threat_level | upper }}</span>
                                            {% else %}
                                            <span class="badge bg-light text-dark">-</span>
                                            {% endif %}
                                        </td>
                                        <td>{% if ioc.is_known_malicious %}<span class="badge bg-danger">Yes</span>{% else %}<span class="badge bg-success">No</span>{% endif %}</td>
                                        <td>{{ (ioc.confidence * 100) | int }}%</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-muted">No DNS queries detected.</p>
                        {% endif %}
                    </div>

                    <!-- Dropped Files -->
                    <div class="tab-pane fade" id="dropped-files" role="tabpanel">
                        {% set file_iocs = iocs | selectattr('ioc_type.value', 'equalto', 'file_dropped') | list %}
                        {% if file_iocs %}
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>File Path</th>
                                        <th>Process</th>
                                        <th>Threat Level</th>
                                        <th>Confidence</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ioc in file_iocs %}
                                    <tr>
                                        <td><code style="font-size: 0.8rem;">{{ ioc.value }}</code></td>
                                        <td><small>{{ ioc.process_name or 'Unknown' }}</small></td>
                                        <td>
                                            {% if ioc.misp_threat_level %}
                                            <span class="badge bg-{% if ioc.misp_threat_level == 'critical' %}danger{% elif ioc.misp_threat_level == 'high' %}warning{% else %}info{% endif %}">{{ ioc.misp_threat_level | upper }}</span>
                                            {% else %}
                                            <span class="badge bg-light text-dark">-</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ (ioc.confidence * 100) | int }}%</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-muted">No dropped files detected.</p>
                        {% endif %}
                    </div>

                    <!-- Registry Modifications -->
                    <div class="tab-pane fade" id="registry-mods" role="tabpanel">
                        {% set registry_iocs = iocs | selectattr('ioc_type.value', 'equalto', 'registry') | list %}
                        {% if registry_iocs %}
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Registry Key / Value</th>
                                        <th>Context</th>
                                        <th>Threat Level</th>
                                        <th>Confidence</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ioc in registry_iocs %}
                                    <tr>
                                        <td><code style="font-size: 0.8rem;">{{ ioc.value }}</code></td>
                                        <td><small>{{ ioc.operation_context or 'Write/Create' }}</small></td>
                                        <td>
                                            {% if ioc.misp_threat_level %}
                                            <span class="badge bg-{% if ioc.misp_threat_level == 'critical' %}danger{% elif ioc.misp_threat_level == 'high' %}warning{% else %}info{% endif %}">{{ ioc.misp_threat_level | upper }}</span>
                                            {% else %}
                                            <span class="badge bg-light text-dark">-</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ (ioc.confidence * 100) | int }}%</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-muted">No registry modifications detected.</p>
                        {% endif %}
                    </div>

                    <!-- Process Behavior -->
                    <div class="tab-pane fade" id="process-behavior" role="tabpanel">
                        {% set process_iocs = iocs | selectattr('ioc_type.value', 'equalto', 'process_behavior') | list %}
                        {% if process_iocs %}
                        <div class="table-responsive">
                            <table class="table table-sm">
                                <thead>
                                    <tr>
                                        <th>Behavioral Pattern</th>
                                        <th>Category</th>
                                        <th>Threat Level</th>
                                        <th>Confidence</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for ioc in process_iocs %}
                                    <tr>
                                        <td><code style="font-size: 0.8rem;">{{ ioc.value }}</code></td>
                                        <td><small>{{ ioc.operation_context or 'Process Behavior' }}</small></td>
                                        <td>
                                            {% if ioc.misp_threat_level %}
                                            <span class="badge bg-{% if ioc.misp_threat_level == 'critical' %}danger{% elif ioc.misp_threat_level == 'high' %}warning{% else %}info{% endif %}">{{ ioc.misp_threat_level | upper }}</span>
                                            {% else %}
                                            <span class="badge bg-light text-dark">-</span>
                                            {% endif %}
                                        </td>
                                        <td>{{ (ioc.confidence * 100) | int }}%</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-muted">No suspicious process behavior detected.</p>
                        {% endif %}
                    </div>
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
