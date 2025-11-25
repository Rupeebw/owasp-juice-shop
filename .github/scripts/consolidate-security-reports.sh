#!/bin/bash
################################################################################
# Security Report Consolidation Script
# Aggregates findings from all security scans into HTML and Markdown reports
################################################################################

set -e

REPORTS_DIR="${1:-./security-reports}"
OUTPUT_DIR="${2:-./consolidated-reports}"

echo "📊 Consolidating Security Reports..."
echo "Reports directory: $REPORTS_DIR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize counters
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_FINDINGS=0

# Report timestamp
TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S UTC')
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
GIT_BRANCH=$(git branch --show-current 2>/dev/null || echo "unknown")

################################################################################
# Parse npm audit results
################################################################################
parse_npm_audit() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  npm audit report not found"
        return
    fi

    echo "  📦 Parsing npm audit results..."

    # Count vulnerabilities by severity
    local critical=$(grep -c "critical" "$file" 2>/dev/null || echo "0")
    local high=$(grep -c "high" "$file" 2>/dev/null || echo "0")
    local moderate=$(grep -c "moderate" "$file" 2>/dev/null || echo "0")
    local low=$(grep -c "low" "$file" 2>/dev/null || echo "0")

    TOTAL_CRITICAL=$((TOTAL_CRITICAL + critical))
    TOTAL_HIGH=$((TOTAL_HIGH + high))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + moderate))
    TOTAL_LOW=$((TOTAL_LOW + low))

    echo "npm-audit|$critical|$high|$moderate|$low" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse Trivy results
################################################################################
parse_trivy() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  Trivy report not found"
        return
    fi

    echo "  🐳 Parsing Trivy results..."

    # Count vulnerabilities
    local critical=$(grep -c "CRITICAL" "$file" 2>/dev/null || echo "0")
    local high=$(grep -c "HIGH" "$file" 2>/dev/null || echo "0")
    local medium=$(grep -c "MEDIUM" "$file" 2>/dev/null || echo "0")
    local low=$(grep -c "LOW" "$file" 2>/dev/null || echo "0")

    TOTAL_CRITICAL=$((TOTAL_CRITICAL + critical))
    TOTAL_HIGH=$((TOTAL_HIGH + high))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
    TOTAL_LOW=$((TOTAL_LOW + low))

    echo "trivy|$critical|$high|$medium|$low" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse Gitleaks results
################################################################################
parse_gitleaks() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ✅ Gitleaks report not found (no secrets detected)"
        echo "gitleaks|0|0|0|0" >> "$OUTPUT_DIR/summary.txt"
        return
    fi

    echo "  🔐 Parsing Gitleaks results..."

    # Count secrets found (all treated as HIGH severity)
    local secrets=$(grep -c "Secret" "$file" 2>/dev/null || echo "0")

    TOTAL_HIGH=$((TOTAL_HIGH + secrets))

    echo "gitleaks|0|$secrets|0|0" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse RetireJS results
################################################################################
parse_retirejs() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  RetireJS report not found"
        return
    fi

    echo "  📚 Parsing RetireJS results..."

    # Count vulnerable libraries (treat as MEDIUM)
    local vulns=$(grep -c "vulnerability" "$file" 2>/dev/null || echo "0")

    TOTAL_MEDIUM=$((TOTAL_MEDIUM + vulns))

    echo "retirejs|0|0|$vulns|0" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse Dockerfile Policy results
################################################################################
parse_dockerfile_policy() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  Dockerfile policy report not found"
        return
    fi

    echo "  📋 Parsing Dockerfile policy results..."

    # Count failures and warnings
    local failures=$(grep -c "FAIL" "$file" 2>/dev/null || echo "0")
    local warnings=$(grep -c "WARN" "$file" 2>/dev/null || echo "0")

    TOTAL_HIGH=$((TOTAL_HIGH + failures))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + warnings))

    echo "dockerfile-policy|0|$failures|$warnings|0" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse OWASP ZAP results
################################################################################
parse_zap() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  ZAP report not found"
        return
    fi

    echo "  🔍 Parsing OWASP ZAP results..."

    # Parse HTML report for alert counts
    local high=$(grep -c 'riskcode="3"' "$file" 2>/dev/null || echo "0")
    local medium=$(grep -c 'riskcode="2"' "$file" 2>/dev/null || echo "0")
    local low=$(grep -c 'riskcode="1"' "$file" 2>/dev/null || echo "0")
    local info=$(grep -c 'riskcode="0"' "$file" 2>/dev/null || echo "0")

    TOTAL_HIGH=$((TOTAL_HIGH + high))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
    TOTAL_LOW=$((TOTAL_LOW + low))

    echo "owasp-zap|0|$high|$medium|$low" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse K8s Manifest Security Scan results
################################################################################
parse_k8s_manifest() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  K8s manifest scan report not found"
        return
    fi

    echo "  🔐 Parsing K8s manifest scan results..."

    # Count policy violations and warnings
    local failures=$(grep -c "FAIL" "$file" 2>/dev/null || echo "0")
    local warnings=$(grep -c "WARN" "$file" 2>/dev/null || echo "0")

    TOTAL_HIGH=$((TOTAL_HIGH + failures))
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + warnings))

    echo "k8s-manifest|0|$failures|$warnings|0" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Parse Security Headers Analysis results
################################################################################
parse_security_headers() {
    local file="$1"
    if [ ! -f "$file" ]; then
        echo "  ⚠️  Security headers scan report not found"
        return
    fi

    echo "  🔒 Parsing security headers results..."

    # Count missing headers (marked with ✗)
    local missing=$(grep -c "✗" "$file" 2>/dev/null || echo "0")

    # Missing security headers are medium severity
    TOTAL_MEDIUM=$((TOTAL_MEDIUM + missing))

    echo "security-headers|0|0|$missing|0" >> "$OUTPUT_DIR/summary.txt"
}

################################################################################
# Generate HTML Dashboard
################################################################################
generate_html_report() {
    echo "🎨 Generating HTML dashboard..."

    local html_file="$OUTPUT_DIR/security-dashboard.html"

    cat > "$html_file" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - OWASP Juice Shop</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: #f5f7fa;
            color: #2c3e50;
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { opacity: 0.9; font-size: 1.1em; }
        .meta-info {
            background: white;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .meta-info div {
            display: inline-block;
            margin-right: 30px;
            font-size: 0.95em;
        }
        .meta-info strong { color: #667eea; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid;
        }
        .summary-card.critical { border-left-color: #e74c3c; }
        .summary-card.high { border-left-color: #e67e22; }
        .summary-card.medium { border-left-color: #f39c12; }
        .summary-card.low { border-left-color: #3498db; }
        .summary-card.total { border-left-color: #9b59b6; }
        .summary-card h3 {
            font-size: 0.9em;
            text-transform: uppercase;
            color: #7f8c8d;
            margin-bottom: 10px;
        }
        .summary-card .count {
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }
        .summary-card.critical .count { color: #e74c3c; }
        .summary-card.high .count { color: #e67e22; }
        .summary-card.medium .count { color: #f39c12; }
        .summary-card.low .count { color: #3498db; }
        .summary-card.total .count { color: #9b59b6; }
        .tool-section {
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .tool-section h2 {
            color: #2c3e50;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #ecf0f1;
        }
        .tool-section .tool-icon {
            display: inline-block;
            margin-right: 10px;
            font-size: 1.2em;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ecf0f1;
        }
        th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2c3e50;
        }
        tr:hover { background: #f8f9fa; }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge.critical { background: #fee; color: #e74c3c; }
        .badge.high { background: #fef0e6; color: #e67e22; }
        .badge.medium { background: #fef5e6; color: #f39c12; }
        .badge.low { background: #e8f4f8; color: #3498db; }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 20px;
            margin: 30px 0;
        }
        .warning-box strong { color: #856404; }
        footer {
            text-align: center;
            padding: 30px;
            color: #7f8c8d;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛡️ Security Scan Report</h1>
            <p>OWASP Juice Shop - DevSecOps Pipeline</p>
        </header>

        <div class="meta-info">
EOF

    # Add metadata
    echo "            <div><strong>Timestamp:</strong> $TIMESTAMP</div>" >> "$html_file"
    echo "            <div><strong>Branch:</strong> $GIT_BRANCH</div>" >> "$html_file"
    echo "            <div><strong>Commit:</strong> $GIT_SHA</div>" >> "$html_file"

    cat >> "$html_file" <<EOF
        </div>

        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical</h3>
                <div class="count">$TOTAL_CRITICAL</div>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <div class="count">$TOTAL_HIGH</div>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <div class="count">$TOTAL_MEDIUM</div>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <div class="count">$TOTAL_LOW</div>
            </div>
            <div class="summary-card total">
                <h3>Total Findings</h3>
                <div class="count">$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))</div>
            </div>
        </div>

        <div class="warning-box">
            <strong>⚠️ Note:</strong> OWASP Juice Shop is an intentionally vulnerable application for security training.
            The findings reported here are expected and are part of the learning experience.
        </div>

        <div class="tool-section">
            <h2><span class="tool-icon">🔧</span>Scan Tool Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Low</th>
                        <th>Total</th>
                    </tr>
                </thead>
                <tbody>
EOF

    # Add tool results from summary.txt
    if [ -f "$OUTPUT_DIR/summary.txt" ]; then
        while IFS='|' read -r tool crit high med low; do
            total=$((crit + high + med + low))
            cat >> "$html_file" <<EOF
                    <tr>
                        <td><strong>$tool</strong></td>
                        <td>$([ "$crit" -gt 0 ] && echo "<span class='badge critical'>$crit</span>" || echo "$crit")</td>
                        <td>$([ "$high" -gt 0 ] && echo "<span class='badge high'>$high</span>" || echo "$high")</td>
                        <td>$([ "$med" -gt 0 ] && echo "<span class='badge medium'>$med</span>" || echo "$med")</td>
                        <td>$([ "$low" -gt 0 ] && echo "<span class='badge low'>$low</span>" || echo "$low")</td>
                        <td><strong>$total</strong></td>
                    </tr>
EOF
        done < "$OUTPUT_DIR/summary.txt"
    fi

    cat >> "$html_file" <<EOF
                </tbody>
            </table>
        </div>

        <footer>
            <p>Generated by DevSecOps Pipeline | OWASP Juice Shop Security Training</p>
            <p>For detailed findings, review individual scan reports in the artifacts.</p>
        </footer>
    </div>
</body>
</html>
EOF

    echo "  ✅ HTML report generated: $html_file"
}

################################################################################
# Generate Markdown Report
################################################################################
generate_markdown_report() {
    echo "📝 Generating Markdown report..."

    local md_file="$OUTPUT_DIR/security-report.md"

    cat > "$md_file" <<EOF
# 🛡️ Security Scan Report - OWASP Juice Shop

**Generated:** $TIMESTAMP
**Branch:** $GIT_BRANCH
**Commit:** \`$GIT_SHA\`

---

## 📊 Executive Summary

| Severity | Count |
|----------|-------|
| 🔴 **Critical** | $TOTAL_CRITICAL |
| 🟠 **High** | $TOTAL_HIGH |
| 🟡 **Medium** | $TOTAL_MEDIUM |
| 🔵 **Low** | $TOTAL_LOW |
| **Total** | **$((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))** |

---

## 🔧 Tool-by-Tool Breakdown

| Tool | Critical | High | Medium | Low | Total |
|------|----------|------|--------|-----|-------|
EOF

    # Add tool results from summary.txt
    if [ -f "$OUTPUT_DIR/summary.txt" ]; then
        while IFS='|' read -r tool crit high med low; do
            total=$((crit + high + med + low))
            echo "| **$tool** | $crit | $high | $med | $low | **$total** |" >> "$md_file"
        done < "$OUTPUT_DIR/summary.txt"
    fi

    cat >> "$md_file" <<'EOF'

---

## 📋 Scan Coverage

This security assessment includes:

- **SAST (Static Application Security Testing)**
  - npm audit - Dependency vulnerability scanning
  - CodeQL (future) - Static code analysis

- **SCA (Software Composition Analysis)**
  - Trivy - Container image vulnerability scanning
  - RetireJS - JavaScript library vulnerability detection

- **Secret Detection**
  - Gitleaks - Secret scanning in git history
  - TruffleHog (future) - Entropy-based secret detection

- **Policy Validation**
  - OPA/Conftest - Dockerfile security policy enforcement
  - Kubernetes manifest security validation

- **DAST (Dynamic Application Security Testing)**
  - OWASP ZAP - Web application security scanning
  - Security headers analysis

---

## ⚠️ Important Note

**OWASP Juice Shop** is an **intentionally vulnerable** application designed for security training, awareness demos, CTFs, and testing security tools.

The vulnerabilities and security findings reported here are **expected and by design**. They serve as learning opportunities for:
- Understanding common web application vulnerabilities
- Practicing security testing methodologies
- Evaluating security scanning tools
- Training in secure coding practices

**Do not attempt to "fix" these vulnerabilities** unless explicitly requested for a specific training scenario.

---

## 📦 Detailed Reports

For detailed findings from each tool, please review the individual scan artifacts:
- npm-audit.txt
- trivy-scan.txt
- gitleaks-report.txt
- retirejs-scan.txt
- dockerfile-policy.txt
- zap-report.html
- k8s-manifest-scan.txt

---

## 📚 References

- [OWASP Juice Shop Documentation](https://pwning.owasp-juice.shop)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DevSecOps Best Practices](https://www.devsecops.org/)

---

*Generated by DevSecOps Pipeline - Security Training Environment*
EOF

    echo "  ✅ Markdown report generated: $md_file"
}

################################################################################
# Main Execution
################################################################################
main() {
    echo ""
    echo "================================================================"
    echo "  Security Report Consolidation"
    echo "================================================================"
    echo ""

    # Initialize summary file
    > "$OUTPUT_DIR/summary.txt"

    # Parse each scan type
    parse_npm_audit "$REPORTS_DIR/npm-audit.txt"
    parse_trivy "$REPORTS_DIR/trivy-scan.txt"
    parse_gitleaks "$REPORTS_DIR/gitleaks-report.txt"
    parse_retirejs "$REPORTS_DIR/retirejs-scan.txt"
    parse_dockerfile_policy "$REPORTS_DIR/dockerfile-policy.txt"
    parse_k8s_manifest "$REPORTS_DIR/k8s-manifest-scan.txt"
    parse_security_headers "$REPORTS_DIR/security-headers-scan.txt"
    parse_zap "$REPORTS_DIR/zap-report.html"

    echo ""
    echo "📊 Summary Statistics:"
    echo "   Critical: $TOTAL_CRITICAL"
    echo "   High: $TOTAL_HIGH"
    echo "   Medium: $TOTAL_MEDIUM"
    echo "   Low: $TOTAL_LOW"
    echo "   Total: $((TOTAL_CRITICAL + TOTAL_HIGH + TOTAL_MEDIUM + TOTAL_LOW))"
    echo ""

    # Generate reports
    generate_html_report
    generate_markdown_report

    echo ""
    echo "================================================================"
    echo "✅ Consolidation Complete!"
    echo "================================================================"
    echo ""
    echo "Generated reports:"
    echo "  📊 HTML Dashboard: $OUTPUT_DIR/security-dashboard.html"
    echo "  📝 Markdown Report: $OUTPUT_DIR/security-report.md"
    echo "  📋 Summary Data: $OUTPUT_DIR/summary.txt"
    echo ""
}

# Run main function
main
