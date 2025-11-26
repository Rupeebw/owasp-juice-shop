#!/usr/bin/env python3
"""
SARIF Parser - Converts CodeQL SARIF results to human-readable format
Generates a clean, structured report of security findings
"""

import json
import sys
import os
from pathlib import Path
from collections import defaultdict

def get_severity_symbol(level):
    """Get emoji/symbol for severity level"""
    symbols = {
        'error': '🔴',
        'warning': '🟡',
        'note': '🔵',
        'critical': '💀',
        'high': '🔴',
        'medium': '🟡',
        'low': '🔵'
    }
    return symbols.get(level.lower(), '⚪')

def get_cwe_from_tags(tags):
    """Extract CWE identifier from tags"""
    if not tags:
        return None
    for tag in tags:
        if tag.startswith('external/cwe/cwe-'):
            return tag.replace('external/cwe/cwe-', 'CWE-').upper()
    return None

def parse_sarif_file(sarif_path):
    """Parse a SARIF file and extract findings"""
    try:
        with open(sarif_path, 'r', encoding='utf-8') as f:
            sarif_data = json.load(f)
    except Exception as e:
        print(f"Error reading SARIF file {sarif_path}: {e}")
        return []

    findings = []

    for run in sarif_data.get('runs', []):
        # Get rules dictionary for reference
        rules = {}
        if 'tool' in run and 'driver' in run['tool']:
            driver = run['tool']['driver']
            for rule in driver.get('rules', []):
                rules[rule['id']] = rule

        # Process results
        for result in run.get('results', []):
            rule_id = result.get('ruleId', 'unknown')
            rule = rules.get(rule_id, {})

            # Get severity
            level = result.get('level', 'warning')

            # Get CWE from tags
            tags = rule.get('properties', {}).get('tags', [])
            cwe = get_cwe_from_tags(tags)

            # Get location
            locations = result.get('locations', [])
            location_str = "Unknown"
            if locations:
                physical_location = locations[0].get('physicalLocation', {})
                artifact_location = physical_location.get('artifactLocation', {})
                region = physical_location.get('region', {})

                file_path = artifact_location.get('uri', 'unknown')
                start_line = region.get('startLine', 0)
                location_str = f"{file_path}:{start_line}"

            # Get message
            message = result.get('message', {}).get('text', 'No description available')

            # Get rule name/title
            rule_name = rule.get('shortDescription', {}).get('text', rule_id)

            findings.append({
                'rule_id': rule_id,
                'rule_name': rule_name,
                'level': level,
                'cwe': cwe,
                'location': location_str,
                'message': message,
                'tags': tags
            })

    return findings

def generate_readable_report(findings, output_file):
    """Generate human-readable text report"""

    # Group findings by severity
    by_severity = defaultdict(list)
    for finding in findings:
        by_severity[finding['level']].append(finding)

    # Severity order
    severity_order = ['error', 'warning', 'note']

    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("=" * 80 + "\n")
        f.write("CodeQL Security Analysis Report\n")
        f.write("=" * 80 + "\n\n")

        # Summary
        f.write("TL;DR - Summary\n")
        f.write("=" * 80 + "\n")
        f.write(f"Total Findings: {len(findings)}\n\n")

        for severity in severity_order:
            count = len(by_severity.get(severity, []))
            symbol = get_severity_symbol(severity)
            f.write(f"{symbol} {severity.upper()}: {count} finding(s)\n")

        f.write("\n" + "=" * 80 + "\n\n")

        # Detailed findings by severity
        for severity in severity_order:
            severity_findings = by_severity.get(severity, [])
            if not severity_findings:
                continue

            symbol = get_severity_symbol(severity)
            f.write(f"\n{severity.upper()} Severity Findings\n")
            f.write("-" * 80 + "\n\n")

            # Group by CWE/rule type
            by_rule = defaultdict(list)
            for finding in severity_findings:
                key = finding['cwe'] or finding['rule_name']
                by_rule[key].append(finding)

            for rule_key, rule_findings in sorted(by_rule.items()):
                # Get CWE for first finding
                cwe_info = rule_findings[0]['cwe']
                rule_name = rule_findings[0]['rule_name']

                f.write(f"{symbol} {rule_name}")
                if cwe_info:
                    f.write(f" ({cwe_info})")
                f.write(f" → {severity.upper()} Severity\n")
                f.write(f"  Count: {len(rule_findings)} occurrence(s)\n\n")

                # Show first 5 occurrences
                for i, finding in enumerate(rule_findings[:5]):
                    f.write(f"  Location {i+1}: {finding['location']}\n")
                    # Truncate long messages
                    message = finding['message']
                    if len(message) > 150:
                        message = message[:150] + "..."
                    f.write(f"  Description: {message}\n\n")

                if len(rule_findings) > 5:
                    f.write(f"  ... and {len(rule_findings) - 5} more occurrence(s)\n\n")

                f.write("\n")

        # Footer
        f.write("=" * 80 + "\n")
        f.write("End of CodeQL Security Analysis Report\n")
        f.write("=" * 80 + "\n\n")

        f.write("Note: This is an intentionally vulnerable application (OWASP Juice Shop).\n")
        f.write("Security findings are expected and serve as training material.\n")
        f.write("\nFor full details, refer to the SARIF file or GitHub Security tab.\n")

def main():
    if len(sys.argv) < 3:
        print("Usage: parse-sarif.py <sarif-directory> <output-file>")
        sys.exit(1)

    sarif_dir = Path(sys.argv[1])
    output_file = sys.argv[2]

    if not sarif_dir.exists():
        print(f"Error: Directory {sarif_dir} does not exist")
        sys.exit(1)

    # Find all SARIF files
    sarif_files = list(sarif_dir.glob("**/*.sarif"))

    if not sarif_files:
        print(f"Warning: No SARIF files found in {sarif_dir}")
        # Create empty report
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CodeQL Security Analysis Report\n")
            f.write("=" * 80 + "\n\n")
            f.write("No SARIF results found. Analysis may not have completed.\n")
        sys.exit(0)

    print(f"Found {len(sarif_files)} SARIF file(s):")
    for sarif_file in sarif_files:
        print(f"  - {sarif_file}")

    # Parse all SARIF files
    all_findings = []
    for sarif_file in sarif_files:
        print(f"\nParsing {sarif_file}...")
        findings = parse_sarif_file(sarif_file)
        all_findings.extend(findings)
        print(f"  Found {len(findings)} finding(s)")

    print(f"\nTotal findings across all files: {len(all_findings)}")

    # Generate readable report
    print(f"\nGenerating readable report: {output_file}")
    generate_readable_report(all_findings, output_file)

    print(f"\n✅ Report generated successfully!")
    print(f"📄 Output: {output_file}")

if __name__ == "__main__":
    main()
