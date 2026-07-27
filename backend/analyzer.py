"""
CVE Enricher — uses only GitHub-native / free external data sources.

No paid API needed:
- CISA KEV (Known Exploited Vulnerabilities): exploit info
- NVD (National Vulnerability Database): CVSS, CWE details
- GitHub Advisory Database: exploit Predictions, git references
- cve.cve.org: official record
"""

import os
import json
import time
import requests
from typing import Dict, Any, Optional
from backend.utils.logger import Logger

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


class CVEAnalyzer:
    def __init__(self):
        self.logger = Logger("CVEAnalyzer")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "CVE-Monitor/1.0 (contact: github.com/anonymous99-Rise)",
        })
        if os.getenv("GITHUB_TOKEN"):
            self.session.headers["Authorization"] = f"Bearer {os.getenv('GITHUB_TOKEN')}"

        self._cisa_kev: Optional[Dict[str, Any]] = None
        self._cisa_kev_loaded = False

    # ── CISA KEV ──────────────────────────────────────────────────────────────

    def _load_cisa_kev(self) -> None:
        """Fetch and cache CISA KEV catalog (loaded once per instance)."""
        if self._cisa_kev_loaded:
            return
        try:
            r = self.session.get(CISA_KEV_URL, timeout=15)
            r.raise_for_status()
            self._cisa_kev = r.json()
            self._cisa_kev_loaded = True
            entries = len(self._cisa_kev.get("vulnerabilities", []))
            self.logger.info(f"CISA KEV loaded: {entries} known exploited vulnerabilities")
        except Exception as e:
            self.logger.warning(f"Failed to load CISA KEV: {e}")
            self._cisa_kev = {"vulnerabilities": []}
            self._cisa_kev_loaded = True

    def is_in_cisa_kev(self, cve_id: str) -> bool:
        self._load_cisa_kev()
        return any(
            v.get("cveID", "").upper() == cve_id.upper()
            for v in self._cisa_kev.get("vulnerabilities", [])
        )

    def get_kev_info(self, cve_id: str) -> Dict[str, Any]:
        """Return CISA KEV record for a CVE, or empty dict."""
        self._load_cisa_kev()
        for v in self._cisa_kev.get("vulnerabilities", []):
            if v.get("cveID", "").upper() == cve_id.upper():
                return v
        return {}

    # ── NVD CVSS / CWE ────────────────────────────────────────────────────────

    def _nvd_request(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch from NVD with retry + backoff.
        Returns parsed JSON dict or None on failure.
        """
        params = {"cveId": cve_id}
        for attempt in range(3):
            try:
                r = self.session.get(NVD_API, params=params, timeout=15)
                if r.status_code == 403:
                    # Rate limited — wait and retry
                    wait = (attempt + 1) * 5
                    self.logger.warning(f"NVD 403, attempt {attempt+1}/3, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code == 200:
                    return r.json()
                self.logger.warning(f"NVD returned {r.status_code} for {cve_id}")
                return None
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"NVD request error (attempt {attempt+1}/3): {e}")
                time.sleep(2 * (attempt + 1))
        return None

    def enrich_from_nvd(self, cve_id: str, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Look up CVSS 3.1 score + vector + CWE description from NVD API.
        Updates cve_data in place and returns it.
        """
        nvd = self._nvd_request(cve_id)
        if not nvd:
            # Fallback: try to get severity directly from cve.org page
            self._enrich_from_cve_org(cve_id, cve_data)
            return cve_data

        items = nvd.get("vulnerabilities", [])
        if not items:
            self._enrich_from_cve_org(cve_id, cve_data)
            return cve_data

        cve_item = items[0]

        # CVSS — check all versions, prefer highest
        metrics = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            cvss_list = metrics.get(metric_key, [])
            if cvss_list:
                cvss = cvss_list[0].get("cvssData", {})
                base_score = cvss.get("baseScore")
                base_severity = cvss.get("baseSeverity", "")
                vector = cvss.get("vectorString", "")

                # Only update if we have a better score than current
                current = cve_data.get("severity", "N/A")
                if base_score is not None:
                    needs_update = (
                        current in ("N/A", "", None) or
                        (current != "N/A" and float(base_score) > float(current))
                    )
                    if needs_update:
                        cve_data["severity"] = str(base_score)
                        self.logger.debug(f"NVD updated {cve_id} severity to {base_score}")

                if vector:
                    cve_data["cvss_vector"] = vector
                if base_severity:
                    cve_data["cvss_severity"] = base_severity
                break  # use first (best) available

        # CWE descriptions
        weaknesses = cve_item.get("weaknesses", [])
        for w in weaknesses:
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids = cve_data.setdefault("cwe_ids", [])
                    if val not in cwe_ids:
                        cwe_ids.append(val)
                    if not cve_data.get("cwe_description"):
                        cve_data["cwe_description"] = self._cwe_human_readable(val)

        # Also grab descriptions from NVD
        if not cve_data.get("description"):
            for desc_obj in cve_item.get("descriptions", []):
                if desc_obj.get("lang") == "en":
                    cve_data["description"] = desc_obj.get("value", "")
                    break

        self.logger.info(f"NVD enriched {cve_id}: score={cve_data.get('severity')}")
        return cve_data

    def _enrich_from_cve_org(self, cve_id: str, cve_data: Dict[str, Any]) -> None:
        """
        Fallback: scrape cve.org for CVSS severity if NVD unavailable.
        """
        try:
            url = f"https://www.cve.org/CVERecord?id={cve_id}"
            r = self.session.get(url, timeout=10)
            if r.status_code == 200:
                import re
                # Look for CVSS pattern in page
                cvss_match = re.search(r'CVSS[:\s]+(?:v?3(?:\.\d)?(?:\.\d)?)?\s*[:\s]*([0-9](?:\.\d)?)', r.text, re.IGNORECASE)
                if cvss_match:
                    score = cvss_match.group(1)
                    current = cve_data.get("severity", "N/A")
                    if current in ("N/A", "", None) or (current != "N/A" and float(score) > float(current)):
                        cve_data["severity"] = score
                        self.logger.info(f"cve.org fallback set {cve_id} severity to {score}")
        except Exception as e:
            self.logger.debug(f"cve.org fallback failed for {cve_id}: {e}")

    # ── GitHub Advisory Database ───────────────────────────────────────────────

    def enrich_from_github_advisory(self, cve_id: str, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check GitHub Advisory Database for exploit/PoC info.
        """
        try:
            r = self.session.get(
                GITHUB_ADVISORY_URL,
                params={"cve_id": cve_id, "type": "reviewed"},
                timeout=10,
            )
            if r.status_code == 200:
                advisories = r.json()
                if advisories:
                    adv = advisories[0]
                    cve_data["ghsa_id"] = adv.get("ghsa_id", "")
                    # Look for exploit_available in extensions
                    for ext in adv.get("extensions", []):
                        if ext.get("type") == "exploit":
                            cve_data["exploit_available"] = ext.get("exploit_available", False)
                            cve_data["exploit_last_patched"] = ext.get("exploit_last_patched")
        except Exception as e:
            self.logger.debug(f"GitHub advisory enrich failed for {cve_id}: {e}")
        return cve_data

    # ── Main enrich ─────────────────────────────────────────────────────────────

    def enrich(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full enrichment pipeline:
        1. CISA KEV — known exploited / ransomware flags
        2. NVD — CVSS + CWE (with retry/backoff)
        3. GitHub Advisory — exploitability
        4. Derive fix_suggestion
        """
        cve_id = cve_data.get("id", "")

        # CISA KEV
        kev = self.get_kev_info(cve_id)
        if kev:
            cve_data["cisa_kev"] = True
            cve_data["cisa_kev_vendor"] = kev.get("vendorProject", "")
            cve_data["cisa_kev_product"] = kev.get("product", "")
            cve_data["cisa_kev_date_added"] = kev.get("dateAdded", "")
            cve_data["short_description"] = kev.get("shortDescription", "")

        # NVD
        cve_data = self.enrich_from_nvd(cve_id, cve_data)

        # GitHub Advisory
        cve_data = self.enrich_from_github_advisory(cve_id, cve_data)

        # Derive fix suggestion if not set
        if not cve_data.get("fix_suggestion"):
            cve_data["fix_suggestion"] = self._derive_fix_suggestion(cve_data)

        return cve_data

    # ── Helpers ────────────────────────────────────────────────────────────────

    CWE_MAP = {
        "CWE-79":  "Cross-site Scripting (XSS)",
        "CWE-89":  "SQL Injection",
        "CWE-22":  "Path Traversal",
        "CWE-78":  "OS Command Injection",
        "CWE-287": "Improper Authentication",
        "CWE-269": "Improper Privilege Management",
        "CWE-862": "Missing Authorization",
        "CWE-918": "Server-Side Request Forgery (SSRF)",
        "CWE-306": "Missing Authentication for Critical Function",
        "CWE-863": "Incorrect Authorization",
        "CWE-502": "Deserialization of Untrusted Data",
        "CWE-400": "Uncontrolled Resource Consumption",
        "CWE-200": "Exposure of Sensitive Information",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-190": "Integer Overflow or Wraparound",
        "CWE-119": "Memory Buffer Overflow",
        "CWE-835": "Infinite Loop / Unreachable Exit",
        "CWE-755": "Improper Handling of Exceptional Conditions",
        "CWE-352": "Cross-Site Request Forgery (CSRF)",
        "CWE-434": "Unrestricted Upload of Dangerous File Type",
        "CWE-94":  "Code Injection",
        "CWE-77":  "Command Injection",
        "CWE-611": "XML External Entity (XXE)",
        "CWE-918": "Server-Side Request Forgery",
        "CWE-自信": "Use of Obsolete Function",
        "CWE-323": "Reusing Nonce / Key in Role",
        "CWE-用到": "Key Management Errors",
        "CWE-590": "Free of Memory Not on Heap",
        "CWE-416": "Use After Free",
    }

    @staticmethod
    def _cwe_human_readable(cwe: str) -> str:
        return CVEAnalyzer.CWE_MAP.get(cwe, cwe)

    def _derive_fix_suggestion(self, cve: Dict[str, Any]) -> str:
        """Generate a fix suggestion from enriched data — no LLM needed."""
        parts = []

        vendor = cve.get("cisa_kev_vendor") or (
            (cve.get("affected") or [{}])[0].get("vendor", "") if cve.get("affected") else ""
        )
        product = cve.get("cisa_kev_product") or (
            (cve.get("affected") or [{}])[0].get("product", "") if cve.get("affected") else ""
        )
        if vendor or product:
            parts.append(f"📦 受影响组件：{vendor} {product}".strip())

        cwe_ids = cve.get("cwe_ids", [])
        if cwe_ids:
            names = [self._cwe_human_readable(c) for c in cwe_ids]
            parts.append(f"🔓 漏洞类型：{', '.join(names)} ({', '.join(cwe_ids)})")

        if cve.get("cisa_kev"):
            parts.append(
                "⚠️ **已在 CISA KEV 中标记为已知被利用 — 请立即修复！**"
            )

        if cve.get("cvss_severity"):
            parts.append(f"📊 官方评级：{cve['cvss_severity']} (CVSS {cve.get('severity', '?')})")

        if cve.get("short_description"):
            parts.append(f"📝 {cve['short_description']}")

        parts.append("""
🛠️ 修复建议：
1. 确认受影响的版本范围（见上方 Affected Products）
2. 升级到厂商官方发布的最稳定安全版本
3. 检查官方安全公告获取补丁链接
4. 如无法立即升级，实施临时缓解措施：
   - 网络层：WAF 规则 / IPS 签名 / 零信任策略
   - 主机层：最小化暴露面 / 禁用危险功能 / 输入过滤
5. 修复后使用 NVD / 厂商 PoC 验证修复有效性""")

        return "\n".join(parts)
