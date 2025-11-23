#!/usr/bin/env python3
"""
Multi-Format Report Generator
==============================

Generates surveillance detection reports in multiple formats:
- Markdown (human-readable text reports)
- HTML (interactive web reports)
- KML (Google Earth visualization)
"""

from enum import Enum
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import xml.etree.ElementTree as ET
from xml.dom import minidom

from .persistence_detector import DeviceScore, RiskLevel
from .location_tracker import LocationCluster, GPSLocation
from .probe_tracker import DeviceAppearance


class ReportFormat(Enum):
    """Report output format."""
    MARKDOWN = "markdown"
    HTML = "html"
    KML = "kml"


class ReportGenerator:
    """
    Multi-format surveillance report generator.
    """

    def __init__(
        self,
        output_dir: str = "./surveillance_reports",
        include_low_risk: bool = False
    ):
        """
        Initialize report generator.

        Args:
            output_dir: Directory for report output
            include_low_risk: Include normal/low risk devices in reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.include_low_risk = include_low_risk

    def generate_report(
        self,
        scores: List[DeviceScore],
        clusters: List[LocationCluster],
        devices: List[DeviceAppearance],
        format: ReportFormat = ReportFormat.MARKDOWN,
        title: Optional[str] = None
    ) -> Path:
        """
        Generate surveillance detection report.

        Args:
            scores: List of DeviceScore objects
            clusters: List of LocationCluster objects
            devices: List of DeviceAppearance objects
            format: Output format
            title: Report title

        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        title = title or f"Surveillance Detection Report - {timestamp}"

        # Filter scores if needed
        if not self.include_low_risk:
            scores = [s for s in scores if s.risk_level != RiskLevel.NORMAL]

        # Generate based on format
        if format == ReportFormat.MARKDOWN:
            return self._generate_markdown(scores, clusters, devices, title, timestamp)
        elif format == ReportFormat.HTML:
            return self._generate_html(scores, clusters, devices, title, timestamp)
        elif format == ReportFormat.KML:
            return self._generate_kml(scores, clusters, devices, title, timestamp)
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _generate_markdown(
        self,
        scores: List[DeviceScore],
        clusters: List[LocationCluster],
        devices: List[DeviceAppearance],
        title: str,
        timestamp: str
    ) -> Path:
        """Generate Markdown report."""
        output_file = self.output_dir / f"surveillance_report_{timestamp}.md"

        lines = [
            f"# {title}",
            "",
            f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "---",
            "",
        ]

        # Executive Summary
        lines.extend([
            "## Executive Summary",
            "",
            f"- **Total Devices Analyzed:** {len(devices)}",
            f"- **Suspicious Devices:** {len([s for s in scores if s.risk_level == RiskLevel.SUSPICIOUS])}",
            f"- **High Risk Devices:** {len([s for s in scores if s.risk_level == RiskLevel.HIGH])}",
            f"- **Critical Threats:** {len([s for s in scores if s.risk_level == RiskLevel.CRITICAL])}",
            f"- **Location Clusters:** {len(clusters)}",
            "",
            "---",
            "",
        ])

        # Threat Details
        if scores:
            lines.extend([
                "## Detected Threats",
                "",
            ])

            for i, score in enumerate(scores, 1):
                lines.extend([
                    f"### {i}. Device: `{score.mac_address}`",
                    "",
                    f"**Risk Level:** {score.risk_level.icon} {score.risk_level.value.upper()}",
                    f"**Persistence Score:** {score.total_score:.2f}/1.00",
                    "",
                    "**Metrics:**",
                    f"- Appearances: {score.total_appearances}",
                    f"- Time Span: {score.time_span_hours:.1f} hours",
                    f"- Appearance Rate: {score.appearance_rate:.2f} times/hour",
                    f"- Unique Locations: {score.unique_locations}",
                    "",
                ])

                if score.ssids_probed:
                    lines.extend([
                        "**SSIDs Probed:**",
                        "",
                    ])
                    for ssid in sorted(score.ssids_probed):
                        lines.append(f"- `{ssid}`")
                    lines.append("")

                if score.detection_reasons:
                    lines.extend([
                        "**Detection Reasons:**",
                        "",
                    ])
                    for reason in score.detection_reasons:
                        lines.append(f"- {reason}")
                    lines.append("")

                lines.append("---")
                lines.append("")

        # Location Clusters
        if clusters:
            lines.extend([
                "## Location Clusters",
                "",
                "Geographic hotspots where multiple devices were detected.",
                "",
            ])

            for cluster in clusters:
                lines.extend([
                    f"### Cluster {cluster.cluster_id}",
                    "",
                    f"- **Center:** ({cluster.center.latitude:.6f}, {cluster.center.longitude:.6f})",
                    f"- **Radius:** {cluster.radius_meters:.0f} meters",
                    f"- **Devices:** {cluster.device_count}",
                    f"- **Observations:** {cluster.location_count}",
                    "",
                    "**Devices in this cluster:**",
                    "",
                ])

                for mac in sorted(cluster.device_macs):
                    lines.append(f"- `{mac}`")

                lines.append("")
                lines.append("---")
                lines.append("")

        # Footer
        lines.extend([
            "## Recommendations",
            "",
            "1. Investigate high-risk and critical devices immediately",
            "2. Cross-reference detected devices with authorized personnel/equipment",
            "3. Consider changing locations if persistent surveillance is confirmed",
            "4. Document all findings and report to appropriate authorities if needed",
            "",
            "---",
            "",
            "*This report was generated by DavBest WiFi Surveillance Detection*",
            "*For authorized security testing and educational purposes only.*",
        ])

        # Write report
        output_file.write_text("\n".join(lines))
        return output_file

    def _generate_html(
        self,
        scores: List[DeviceScore],
        clusters: List[LocationCluster],
        devices: List[DeviceAppearance],
        title: str,
        timestamp: str
    ) -> Path:
        """Generate HTML report."""
        output_file = self.output_dir / f"surveillance_report_{timestamp}.html"

        # Build HTML
        html = [
            "<!DOCTYPE html>",
            "<html lang='en'>",
            "<head>",
            "  <meta charset='UTF-8'>",
            "  <meta name='viewport' content='width=device-width, initial-scale=1.0'>",
            f"  <title>{title}</title>",
            "  <style>",
            "    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }",
            "    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }",
            "    h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }",
            "    h2 { color: #007bff; margin-top: 30px; }",
            "    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }",
            "    .summary-card { background: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 4px solid #007bff; }",
            "    .summary-card h3 { margin: 0 0 5px 0; font-size: 14px; color: #666; }",
            "    .summary-card p { margin: 0; font-size: 24px; font-weight: bold; color: #333; }",
            "    .device { background: #fff; border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin: 15px 0; }",
            "    .device.critical { border-left: 4px solid #dc3545; }",
            "    .device.high { border-left: 4px solid #fd7e14; }",
            "    .device.suspicious { border-left: 4px solid #ffc107; }",
            "    .device.normal { border-left: 4px solid #28a745; }",
            "    .badge { display: inline-block; padding: 4px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }",
            "    .badge.critical { background: #dc3545; color: white; }",
            "    .badge.high { background: #fd7e14; color: white; }",
            "    .badge.suspicious { background: #ffc107; color: black; }",
            "    .badge.normal { background: #28a745; color: white; }",
            "    .metric { display: inline-block; margin: 5px 10px 5px 0; padding: 5px 10px; background: #e9ecef; border-radius: 3px; font-size: 14px; }",
            "    .cluster { background: #e7f3ff; border: 1px solid #007bff; border-radius: 5px; padding: 15px; margin: 15px 0; }",
            "    code { background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-family: monospace; }",
            "    ul { margin: 10px 0; }",
            "    .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 12px; }",
            "  </style>",
            "</head>",
            "<body>",
            "  <div class='container'>",
            f"    <h1>{title}</h1>",
            f"    <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
            "",
            "    <h2>Executive Summary</h2>",
            "    <div class='summary'>",
            f"      <div class='summary-card'><h3>Total Devices</h3><p>{len(devices)}</p></div>",
            f"      <div class='summary-card'><h3>Suspicious</h3><p>{len([s for s in scores if s.risk_level == RiskLevel.SUSPICIOUS])}</p></div>",
            f"      <div class='summary-card'><h3>High Risk</h3><p>{len([s for s in scores if s.risk_level == RiskLevel.HIGH])}</p></div>",
            f"      <div class='summary-card'><h3>Critical</h3><p>{len([s for s in scores if s.risk_level == RiskLevel.CRITICAL])}</p></div>",
            f"      <div class='summary-card'><h3>Clusters</h3><p>{len(clusters)}</p></div>",
            "    </div>",
        ]

        # Threats
        if scores:
            html.append("    <h2>Detected Threats</h2>")

            for score in scores:
                risk_class = score.risk_level.value
                html.extend([
                    f"    <div class='device {risk_class}'>",
                    f"      <h3>{score.risk_level.icon} Device: <code>{score.mac_address}</code></h3>",
                    f"      <span class='badge {risk_class}'>{score.risk_level.value.upper()}</span>",
                    f"      <span class='badge normal'>Score: {score.total_score:.2f}</span>",
                    "      <div style='margin-top: 10px;'>",
                    f"        <span class='metric'>Appearances: {score.total_appearances}</span>",
                    f"        <span class='metric'>Time Span: {score.time_span_hours:.1f}h</span>",
                    f"        <span class='metric'>Rate: {score.appearance_rate:.2f}/hr</span>",
                    f"        <span class='metric'>Locations: {score.unique_locations}</span>",
                    "      </div>",
                ])

                if score.ssids_probed:
                    html.append("      <p><strong>SSIDs Probed:</strong></p><ul>")
                    for ssid in sorted(score.ssids_probed):
                        html.append(f"        <li><code>{ssid}</code></li>")
                    html.append("      </ul>")

                if score.detection_reasons:
                    html.append("      <p><strong>Detection Reasons:</strong></p><ul>")
                    for reason in score.detection_reasons:
                        html.append(f"        <li>{reason}</li>")
                    html.append("      </ul>")

                html.append("    </div>")

        # Clusters
        if clusters:
            html.append("    <h2>Location Clusters</h2>")

            for cluster in clusters:
                html.extend([
                    "    <div class='cluster'>",
                    f"      <h3>Cluster {cluster.cluster_id}</h3>",
                    f"      <p><strong>Center:</strong> ({cluster.center.latitude:.6f}, {cluster.center.longitude:.6f})</p>",
                    f"      <p><strong>Radius:</strong> {cluster.radius_meters:.0f} meters</p>",
                    f"      <p><strong>Devices:</strong> {cluster.device_count}</p>",
                    "      <p><strong>Devices in cluster:</strong></p>",
                    "      <ul>",
                ])

                for mac in sorted(cluster.device_macs):
                    html.append(f"        <li><code>{mac}</code></li>")

                html.extend([
                    "      </ul>",
                    "    </div>",
                ])

        # Footer
        html.extend([
            "    <div class='footer'>",
            "      <p>This report was generated by DavBest WiFi Surveillance Detection</p>",
            "      <p>For authorized security testing and educational purposes only.</p>",
            "    </div>",
            "  </div>",
            "</body>",
            "</html>",
        ])

        # Write report
        output_file.write_text("\n".join(html))
        return output_file

    def _generate_kml(
        self,
        scores: List[DeviceScore],
        clusters: List[LocationCluster],
        devices: List[DeviceAppearance],
        title: str,
        timestamp: str
    ) -> Path:
        """Generate KML report for Google Earth."""
        output_file = self.output_dir / f"surveillance_report_{timestamp}.kml"

        # Create KML structure
        kml = ET.Element('kml', xmlns='http://www.opengis.net/kml/2.2')
        document = ET.SubElement(kml, 'Document')

        # Title
        name = ET.SubElement(document, 'name')
        name.text = title

        # Styles for different risk levels
        self._add_kml_styles(document)

        # Add device placemarks
        device_dict = {d.mac_address: d for d in devices}

        for score in scores:
            device = device_dict.get(score.mac_address)
            if not device:
                continue

            # Add placemark for each location
            for probe in device.appearances:
                if not probe.has_location:
                    continue

                placemark = ET.SubElement(document, 'Placemark')

                pm_name = ET.SubElement(placemark, 'name')
                pm_name.text = score.mac_address

                # Description
                desc = ET.SubElement(placemark, 'description')
                desc_text = [
                    f"Risk Level: {score.risk_level.value.upper()}",
                    f"Persistence Score: {score.total_score:.2f}",
                    f"Signal: {probe.signal_strength}dBm",
                    f"Time: {datetime.fromtimestamp(probe.timestamp).strftime('%Y-%m-%d %H:%M:%S')}",
                ]
                if probe.ssid:
                    desc_text.append(f"SSID: {probe.ssid}")
                desc.text = "\n".join(desc_text)

                # Style
                style_url = ET.SubElement(placemark, 'styleUrl')
                style_url.text = f"#{score.risk_level.value}_style"

                # Point
                point = ET.SubElement(placemark, 'Point')
                coordinates = ET.SubElement(point, 'coordinates')
                coordinates.text = f"{probe.longitude},{probe.latitude},0"

        # Add cluster placemarks
        for cluster in clusters:
            placemark = ET.SubElement(document, 'Placemark')

            pm_name = ET.SubElement(placemark, 'name')
            pm_name.text = f"Cluster {cluster.cluster_id}"

            desc = ET.SubElement(placemark, 'description')
            desc.text = (
                f"Devices: {cluster.device_count}\n"
                f"Radius: {cluster.radius_meters:.0f}m\n"
                f"MACs: {', '.join(sorted(cluster.device_macs))}"
            )

            style_url = ET.SubElement(placemark, 'styleUrl')
            style_url.text = "#cluster_style"

            # Point
            point = ET.SubElement(placemark, 'Point')
            coordinates = ET.SubElement(point, 'coordinates')
            coordinates.text = f"{cluster.center.longitude},{cluster.center.latitude},0"

        # Convert to string with formatting
        xml_str = minidom.parseString(ET.tostring(kml)).toprettyxml(indent="  ")

        # Write report
        output_file.write_text(xml_str)
        return output_file

    def _add_kml_styles(self, document):
        """Add KML styles for different risk levels."""
        styles = {
            'critical': '#FF0000',  # Red
            'high': '#FF6600',      # Orange
            'suspicious': '#FFCC00', # Yellow
            'normal': '#00FF00',    # Green
            'cluster': '#0000FF',   # Blue
        }

        for name, color in styles.items():
            style = ET.SubElement(document, 'Style', id=f'{name}_style')
            icon_style = ET.SubElement(style, 'IconStyle')

            color_elem = ET.SubElement(icon_style, 'color')
            # KML uses ABGR format
            color_elem.text = f'ff{color[5:7]}{color[3:5]}{color[1:3]}'

            scale = ET.SubElement(icon_style, 'scale')
            scale.text = '1.2' if name == 'cluster' else '1.0'


# Example usage
if __name__ == "__main__":
    from .persistence_detector import PersistenceDetector
    from .probe_tracker import ProbeRequest
    import time

    # Example: Generate test report
    devices = []
    device = DeviceAppearance(mac_address="AA:BB:CC:DD:EE:FF")

    for i in range(8):
        probe = ProbeRequest(
            mac_address="AA:BB:CC:DD:EE:FF",
            ssid=f"TestNetwork_{i % 2}",
            signal_strength=-65,
            latitude=37.7749 + (i * 0.001),
            longitude=-122.4194 + (i * 0.001),
            timestamp=time.time() - ((8 - i) * 1800)
        )
        device.add_appearance(probe)

    devices.append(device)

    # Analyze
    detector = PersistenceDetector()
    scores = detector.analyze_devices(devices)

    # Generate reports
    generator = ReportGenerator()

    md_file = generator.generate_report(scores, [], devices, ReportFormat.MARKDOWN)
    print(f"[+] Markdown report: {md_file}")

    html_file = generator.generate_report(scores, [], devices, ReportFormat.HTML)
    print(f"[+] HTML report: {html_file}")

    kml_file = generator.generate_report(scores, [], devices, ReportFormat.KML)
    print(f"[+] KML report: {kml_file}")
