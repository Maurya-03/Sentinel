// src/lib/mock-data.ts — Rich mock scan report for UI development

import { ScanReport } from "@/types/scan";

export const MOCK_REPORT: ScanReport = {
  sentinel_version: "1.0.0",
  scan_timestamp:   "2025-01-15T10:30:00.000Z",
  target:           "http://testphp.vulnweb.com",
  summary: {
    total_vulnerabilities: 8,
    severity_breakdown: { CRITICAL: 2, HIGH: 1, MEDIUM: 3, LOW: 2, INFO: 0 },
    overall_risk_score: 8.4,
    risk_rating: "HIGH",
  },
  vulnerabilities: [
    {
      type: "SQL Injection", url: "http://testphp.vulnweb.com/login.php",
      method: "POST", param: "uname", payload: "' OR '1'='1",
      severity: "CRITICAL", numeric_score: 9.5,
      cwe: "CWE-89", owasp: "A03:2021 – Injection",
      evidence: "Warning: mysql_fetch_array() expects parameter 1 to be resource, boolean given",
      ai_analysis: {
        explanation: "The login form passes the uname parameter directly into a MySQL query without parameterization. The payload ' OR '1'='1 manipulates the WHERE clause logic to always evaluate as true, bypassing authentication.",
        impact: "Complete authentication bypass enabling access to any user account. Database contents extractable via UNION or error-based techniques.",
        mitigation: [
          "Use PDO with prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE username = ?')",
          "Never concatenate user input into SQL query strings",
          "Apply allowlist input validation on all form fields",
          "Run database with minimum required privileges (SELECT only where applicable)",
        ],
        confidence: "92%", source: "rule_based",
      },
    },
    {
      type: "SQL Injection", url: "http://testphp.vulnweb.com/search.php",
      method: "GET", param: "test", payload: "1' ORDER BY 3--",
      severity: "CRITICAL", numeric_score: 9.2,
      cwe: "CWE-89", owasp: "A03:2021 – Injection",
      evidence: "You have an error in your SQL syntax near '1' ORDER BY 3--'",
      ai_analysis: {
        explanation: "The search parameter is interpolated directly into an ORDER BY clause. Attackers can enumerate columns and perform UNION-based extraction of the full database.",
        impact: "Full database enumeration. Attackers can extract schema, table names, all user credentials and PII.",
        mitigation: [
          "Whitelist allowable column names for ORDER BY — never pass raw user input",
          "Implement parameterized queries throughout the codebase",
          "Deploy a WAF with SQL injection signatures enabled",
        ],
        confidence: "92%", source: "rule_based",
      },
    },
    {
      type: "Cross-Site Scripting (XSS)", subtype: "Reflected",
      url: "http://testphp.vulnweb.com/search.php", method: "GET",
      param: "searchFor", payload: "<script>alert('XSS')</script>",
      severity: "HIGH", numeric_score: 7.5,
      cwe: "CWE-79", owasp: "A03:2021 – Injection",
      evidence: "<script>alert('XSS')</script> reflected unescaped in response",
      ai_analysis: {
        explanation: "The searchFor parameter value is reflected into the HTML page without HTML entity encoding, allowing arbitrary script injection via crafted URLs.",
        impact: "Session cookie theft, credential harvesting via fake login overlays, full account takeover for any user clicking a malicious link.",
        mitigation: [
          "Apply htmlspecialchars($output, ENT_QUOTES, 'UTF-8') on all reflected data",
          "Implement Content-Security-Policy: default-src 'self'; script-src 'self'",
          "Set HttpOnly and Secure flags on all session cookies",
          "Use a modern framework that auto-escapes template variables",
        ],
        confidence: "95%", source: "rule_based",
      },
    },
    {
      type: "Open Port", host: "testphp.vulnweb.com",
      url: "http://testphp.vulnweb.com", port: 3306, service: "MySQL",
      severity: "MEDIUM", numeric_score: 6.8,
      cwe: "CWE-200", owasp: "A05:2021 – Security Misconfiguration",
      evidence: "TCP port 3306 (MySQL) open and accepting connections from public internet",
      ai_analysis: {
        explanation: "MySQL is directly accessible from the public internet on port 3306. This exposes the database to direct brute-force attacks against credentials without requiring application-layer access.",
        impact: "Direct database compromise if credentials are weak, default, or guessable. Complete data exfiltration possible.",
        mitigation: [
          "Restrict port 3306 via firewall — allow only application server IP",
          "Never expose database ports to the public internet",
          "Use SSH tunneling or VPN for remote database administration",
        ],
        confidence: "99%", source: "rule_based",
      },
    },
    {
      type: "Missing Security Header", header: "Content-Security-Policy",
      url: "http://testphp.vulnweb.com", severity: "MEDIUM", numeric_score: 5.4,
      cwe: "CWE-693", owasp: "A05:2021 – Security Misconfiguration",
      evidence: "Content-Security-Policy header absent from all responses",
      ai_analysis: {
        explanation: "No CSP header directs the browser on permitted script sources. Any injected or third-party script executes without restriction.",
        impact: "Amplifies XSS impact. Data exfiltration to attacker-controlled domains unrestricted.",
        mitigation: [
          "Add: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{token}'",
          "Use report-only mode initially to audit without breaking functionality",
        ],
        confidence: "99%", source: "rule_based",
      },
    },
    {
      type: "Missing Security Header", header: "Strict-Transport-Security",
      url: "http://testphp.vulnweb.com", severity: "MEDIUM", numeric_score: 5.9,
      cwe: "CWE-319", owasp: "A05:2021 – Security Misconfiguration",
      evidence: "Strict-Transport-Security header absent",
      ai_analysis: {
        explanation: "Without HSTS, browsers allow HTTP connections. An attacker on the network path can strip TLS and intercept all traffic in plaintext.",
        impact: "Credential and session token theft via SSL stripping on untrusted networks.",
        mitigation: [
          "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          "Permanently redirect all HTTP to HTTPS (301)",
        ],
        confidence: "99%", source: "rule_based",
      },
    },
    {
      type: "Missing Security Header", header: "X-Frame-Options",
      url: "http://testphp.vulnweb.com", severity: "LOW", numeric_score: 3.2,
      cwe: "CWE-1021", owasp: "A05:2021 – Security Misconfiguration",
      evidence: "X-Frame-Options absent — page embeddable in cross-origin iframes",
      ai_analysis: {
        explanation: "The absence of X-Frame-Options allows the application to be framed by any external site, enabling UI redressing and clickjacking.",
        impact: "Users tricked into performing unintended actions via invisible overlay attacks.",
        mitigation: [
          "Add: X-Frame-Options: DENY",
          "Or use CSP: frame-ancestors 'none' for modern browsers",
        ],
        confidence: "99%", source: "rule_based",
      },
    },
    {
      type: "Information Disclosure", header: "Server",
      url: "http://testphp.vulnweb.com", severity: "LOW", numeric_score: 2.1,
      cwe: "CWE-200", owasp: "A05:2021 – Security Misconfiguration",
      evidence: "Server: Apache/2.4.7 (Ubuntu) — exact version disclosed",
      ai_analysis: {
        explanation: "The Server response header exposes the web server name and version, enabling targeted exploitation of known CVEs for that specific version.",
        impact: "Reconnaissance advantage for attackers — reduces time to identify applicable exploits.",
        mitigation: [
          "Apache: set ServerTokens Prod in httpd.conf",
          "Nginx: set server_tokens off in nginx.conf",
          "Consider a reverse proxy that strips or replaces the header",
        ],
        confidence: "99%", source: "rule_based",
      },
    },
  ],
};
