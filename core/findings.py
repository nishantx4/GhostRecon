"""
FindingsDB — central store for all vulnerabilities discovered during a scan
"""
from datetime import datetime


class FindingsDB:
    def __init__(self):
        self.findings = []
        self._seen = set()

    def add(self, title, severity, url, module, description='', remediation='',
            cvss=None, evidence=None, references=None, confidence='medium'):
        """Add a finding. Deduplicates on (title, url) pair."""
        key = (title.lower().strip(), url.lower().strip())
        if key in self._seen:
            return False
        self._seen.add(key)

        sev = severity.lower()
        if sev not in ('critical', 'high', 'medium', 'low', 'info'):
            sev = 'info'

        self.findings.append({
            'id':          len(self.findings) + 1,
            'title':       title,
            'severity':    sev,
            'url':         url,
            'module':      module,
            'description': description,
            'remediation': remediation,
            'cvss':        cvss,
            'evidence':    evidence or [],
            'references':  references or [],
            'confidence':  confidence,
            'timestamp':   datetime.now().isoformat(),
        })
        return True

    def by_severity(self, sev):
        return [f for f in self.findings if f['severity'] == sev]

    def severity_counts(self):
        counts = {}
        for f in self.findings:
            counts[f['severity']] = counts.get(f['severity'], 0) + 1
        return counts

    def to_summary_list(self):
        return [
            f"[{f['severity'].upper()}] {f['title']} — {f['url']}"
            for f in self.findings
        ]

    def to_detail_list(self):
        lines = []
        for f in self.findings:
            lines.append(
                f"[{f['severity'].upper()}] {f['title']}\n"
                f"URL: {f['url']}\n"
                f"CVSS: {f.get('cvss','N/A')}\n"
                f"Description: {f['description']}\n"
                f"Remediation: {f['remediation']}"
            )
        return lines
