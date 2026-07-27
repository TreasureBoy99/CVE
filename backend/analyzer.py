"""
CVE Enricher — uses only GitHub-native / free external data sources.

No paid API needed:
- CISA KEV (Known Exploited Vulnerabilities): exploit info
- NVD (National Vulnerability Database): CVSS, CWE details
- GitHub Advisory Database: exploit Predictions, git references
- CVE.org: official record
"""

import os
import json
import time
import requests
from typing import Dict, Any, Optional, List
from backend.utils.logger import Logger

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"


class CVEAnalyzer:
    def __init__(self):
        self.logger = Logger("CVEAnalyzer")
        self.session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "CVE-Monitor/1.0",
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
            self.logger.info(f"CISA KEV loaded: {len(self._cisa_kev.get('vulnerabilities', []))} entries")
        except Exception as e:
            self.logger.warning(f"Failed to load CISA KEV: {e}")
            self._cisa_kev = {"vulnerabilities": []}
            self._cisa_kev_loaded = True

    def is_in_cisa_kev(self, cve_id: str) -> bool:
        self._load_cisa_kev()
        if not self._cisa_kev:
            return False
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

    def enrich_from_nvd(self, cve_id: str, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Look up CVSS 3.1 score + vector + CWE description from NVD API.
        Updates cve_data in place and returns it.
        """
        try:
            # NVD requires 2-digit year; CVE IDs look like CVE-YYYY-NNNNN
            parts = cve_id.split("-")
            if len(parts) >= 3:
                year = parts[1]
                params = {"cveId": cve_id}
                r = self.session.get(NVD_API, params=params, timeout=10)
                if r.status_code == 200:
                    nvd = r.json()
                    items = nvd.get("vulnerabilities", [])
                    if items:
                        cve_item = items[0]
                        # CVSS
                        metrics = cve_item.get("metrics", {})
                        cvss31 = (
                            metrics.get("cvssMetricV31")
                            or metrics.get("cvssMetricV30")
                            or metrics.get("cvssMetricV2")
                        )
                        if cvss31:
                            cvss = cvss31[0].get("cvssData", {})
                            base_score = cvss.get("baseScore", "")
                            base_severity = cvss.get("baseSeverity", "")
                            vector = cvss.get("vectorString", "")
                            if base_score and not cve_data.get("severity") or cve_data.get("severity") == "N/A":
                                cve_data["severity"] = str(base_score)
                            if not cve_data.get("cvss_vector"):
                                cve_data["cvss_vector"] = vector
                            if not cve_data.get("cvss_severity"):
                                cve_data["cvss_severity"] = base_severity

                        # CWE descriptions
                        weaknesses = cve_item.get("weaknesses", [])
                        for w in weaknesses:
                            for desc in w.get("description", []):
                                val = desc.get("value", "")
                                if val.startswith("CWE-"):
                                    cve_data.setdefault("cwe_ids", []).append(val)
                                    if not cve_data.get("cwe_description"):
                                        cve_data["cwe_description"] = self._cwe_human_readable(val)

                        self.logger.debug(f"NVD enriched {cve_id}: score={cve_data.get('severity')}")
        except Exception as e:
            self.logger.warning(f"NVD enrich failed for {cve_id}: {e}")

        return cve_data

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
                    if adv.get("identifiers"):
                        cve_data["ghsa_id"] = adv.get("ghsa_id", "")
                    # GitHub marks predicates like 'Exploit Available'
                    for ext in adv.get("extensions", []):
                        if ext.get("type") == "exploit":
                            cve_data["exploit_available"] = ext.get("exploit_available", False)
                            cve_data["exploit_last_patched"] = ext.get("exploit_last_patched")
        except Exception as e:
            self.logger.warning(f"GitHub advisory enrich failed for {cve_id}: {e}")
        return cve_data

    # ── Main enrich ─────────────────────────────────────────────────────────────

    def enrich(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full enrichment pipeline:
        1. CISA KEV — isKnownRansomwareCampaignUsed / isKnownToBeUsedInRansomware
        2. NVD — CVSS + CWE
        3. GitHub Advisory — exploitability
        4. Derive fix_suggestion from CWE
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

    @staticmethod
    def _cwe_human_readable(cwe: str) -> str:
        CWE_MAP = {
            "CWE-79": "Cross-site Scripting (XSS)",
            "CWE-89": "SQL Injection",
            "CWE-22": "Path Traversal",
            "CWE-78": "OS Command Injection",
            "CWE-287": "Improper Authentication",
            "Cwe-269": "Improper Privilege Management",
            "CWE-862": "Missing Authorization",
            "CWE-918": "Server-Side Request Forgery (SSRF)",
            "CWE-306": "Missing Authentication for Critical Function",
            "CWE-863": "Incorrect Authorization",
            "CWE-502": "Deserialization of Untrusted Data",
            "CWE-400": "Uncontrolled Resource Consumption",
            "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
            "CWE-476": "NULL Pointer Dereference",
            "CWE-190": "Integer Overflow or Wraparound",
            "CWE-119": "Memory Buffer Overflow",
            "CWE-835": "Loop with Unreachable Exit Condition",
            "CWE-755": "Improper Handling of Exceptional Conditions",
        }
        return CWE_MAP.get(cwe, cwe)

    def _derive_fix_suggestion(self, cve: Dict[str, Any]) -> str:
        """Generate a fix suggestion from enriched data — no LLM needed."""
        parts = []

        # Vendor/product from CISA KEV or affected field
        vendor = cve.get("cisa_kev_vendor") or (
            cve.get("affected") or [{}])[0].get("vendor", ""
        )
        product = cve.get("cisa_kev_product") or (
            cve.get("affected") or [{}])[0].get("product", ""
        )
        if vendor or product:
            parts.append(f"受影响组件：{vendor} {product}".strip())

        # CWE
        cwe_ids = cve.get("cwe_ids", [])
        if cwe_ids:
            cwe_name = self._cwe_human_readable(cwe_ids[0])
            parts.append(f"漏洞类型：{cwe_name} ({cwe_ids[0]})")

        # CISA KEV
        if cve.get("cisa_kev"):
            parts.append("⚠️ 此漏洞已在 CISA KEV 中标记为已知被利用，请优先修复")

        # CISA KEV description
        if cve.get("short_description"):
            parts.append(f"CISA 描述：{cve['short_description']}")

        # General guidance
        parts.append("修复建议：")
        parts.append("1. 确认受影响的版本范围")
        parts.append("2. 升级到最新稳定版本")
        parts.append("3. 检查官方安全公告获取补丁信息")
        parts.append("4. 如无法立即升级，实施临时缓解措施（如网络隔离、WAF规则）")

        return "\n".join(parts)
