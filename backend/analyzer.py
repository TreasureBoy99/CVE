"""
CVE Enricher — uses only GitHub-native / free external data sources.

No paid API needed (but NVD_API_KEY is recommended for higher rate limits):
- CISA KEV (Known Exploited Vulnerabilities): exploit info
- NVD (National Vulnerability Database): CVSS, CWE details
- GitHub Advisory Database: exploit Predictions, git references

Uses SQLite caching so already-enriched CVEs are not re-fetched.
Cache is stored at ~/.cve-monitor/cve.db
"""

import os
import json
import time
import sqlite3
import requests
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from backend.utils.logger import Logger

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ORG_URL = "https://www.cve.org/CVERecord?id="
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GITHUB_ADVISORY_URL = "https://api.github.com/advisories"

# Cache staleness: re-fetch CVE from NVD if older than this
CACHE_STALE_HOURS = 24


class CVEAnalyzer:
    def __init__(self, cache_hours: int = CACHE_STALE_HOURS):
        self.logger = Logger("CVEAnalyzer")
        self.cache_hours = cache_hours
        self.session = requests.Session()
        self._nvd_api_key = os.getenv("NVD_API_KEY", "") or os.getenv("GITHUB_TOKEN", "")
        self._github_token = os.getenv("GITHUB_TOKEN", "")
        # Rate limits: with NVD API key = 50 req/10s, without = 10 req/10s
        self._nvd_rate_limit = 0.2 if self._nvd_api_key else 2.0

        self.session.headers.update({
            "Accept": "application/json",
            "User-Agent": "CVE-Monitor/1.0 (contact: github.com/anonymous99-Rise)",
        })
        if self._github_token:
            self.session.headers["Authorization"] = f"Bearer {self._github_token}"

        self._cisa_kev: Optional[Dict[str, Any]] = None
        self._cisa_kev_loaded = False

        # SQLite cache
        self._db_path = Path.home() / ".cve-monitor" / "cve.db"
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ── SQLite Cache ────────────────────────────────────────────────────────────

    def _get_db(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        conn = self._get_db()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_enrichment (
                    cve_id          TEXT PRIMARY KEY,
                    severity        REAL    DEFAULT 0,
                    cvss_vector     TEXT,
                    cvss_severity  TEXT,
                    cwe_ids         TEXT,
                    cwe_description TEXT,
                    description     TEXT,
                    cisa_kev       INTEGER DEFAULT 0,
                    ghsa_id         TEXT,
                    exploit_avail   INTEGER DEFAULT 0,
                    enriched_at     TEXT,
                    source          TEXT    DEFAULT 'nvd'
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS cve_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def get_cached(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Get cached enrichment for a CVE.
        Returns None if stale or missing.
        """
        conn = self._get_db()
        try:
            row = conn.execute(
                "SELECT * FROM cve_enrichment WHERE cve_id = ?", (cve_id,)
            ).fetchone()
            if not row:
                return None

            # Check staleness
            enriched_at = datetime.fromisoformat(row["enriched_at"])
            if datetime.now(timezone.utc) - enriched_at > timedelta(hours=self.cache_hours):
                return None  # stale

            return {
                "severity":          str(row["severity"]) if row["severity"] else "N/A",
                "cvss_vector":       row["cvss_vector"],
                "cvss_severity":     row["cvss_severity"],
                "cwe_ids":            json.loads(row["cwe_ids"]) if row["cwe_ids"] else [],
                "cwe_description":    row["cwe_description"],
                "description":        row["description"],
                "cisa_kev":          bool(row["cisa_kev"]),
                "ghsa_id":           row["ghsa_id"],
                "exploit_available":  bool(row["exploit_avail"]),
            }
        finally:
            conn.close()

    def save_enrichment(self, cve_id: str, data: Dict[str, Any]) -> None:
        """Save enriched CVE data to cache."""
        conn = self._get_db()
        try:
            conn.execute("""
                INSERT OR REPLACE INTO cve_enrichment (
                    cve_id, severity, cvss_vector, cvss_severity,
                    cwe_ids, cwe_description, description,
                    cisa_kev, ghsa_id, exploit_avail, enriched_at, source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve_id,
                float(data.get("severity", 0) or 0),
                data.get("cvss_vector"),
                data.get("cvss_severity"),
                json.dumps(data.get("cwe_ids", []), ensure_ascii=False),
                data.get("cwe_description"),
                data.get("description"),
                int(data.get("cisa_kev", False)),
                data.get("ghsa_id"),
                int(data.get("exploit_available", False)),
                datetime.now(timezone.utc).isoformat(),
                "nvd",
            ))
            conn.commit()
        finally:
            conn.close()

    def cache_stats(self) -> Dict[str, int]:
        """Return cache statistics."""
        conn = self._get_db()
        try:
            total = conn.execute("SELECT COUNT(*) FROM cve_enrichment").fetchone()[0]
            stale = 0
            cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.cache_hours)).isoformat()
            stale = conn.execute(
                "SELECT COUNT(*) FROM cve_enrichment WHERE enriched_at < ?", (cutoff,)
            ).fetchone()[0]
            return {"total": total, "stale": stale}
        finally:
            conn.close()

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
        Fetch from NVD with retry + exponential backoff.
        Uses NVD_API_KEY if available for higher rate limits.
        """
        params = {"cveId": cve_id}
        headers = dict(self.session.headers)
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        for attempt in range(4):
            try:
                r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
                if r.status_code in (403, 429):
                    wait = (2 ** attempt) * 3
                    retry_after = r.headers.get("Retry-After")
                    if retry_after:
                        wait = max(wait, int(retry_after))
                    self.logger.warning(f"NVD {r.status_code}, attempt {attempt+1}/4, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code == 200:
                    return r.json()
                self.logger.warning(f"NVD returned {r.status_code} for {cve_id}")
                return None
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"NVD request error (attempt {attempt+1}/4): {e}")
                time.sleep(2 * (attempt + 1))
        return None

    def _parse_nvd_response(self, nvd: Dict, cve_data: Dict[str, Any]) -> None:
        """Parse NVD JSON into cve_data dict, in-place."""
        items = nvd.get("vulnerabilities", [])
        if not items:
            return

        cve_item = items[0]

        # CVSS — prefer v3.1, then v3.0, then v2
        metrics = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            cvss_list = metrics.get(metric_key, [])
            if cvss_list:
                cvss = cvss_list[0].get("cvssData", {})
                base_score = cvss.get("baseScore")
                base_severity = cvss.get("baseSeverity", "")
                vector = cvss.get("vectorString", "")

                current = cve_data.get("severity", "N/A")
                if base_score is not None:
                    needs_update = (
                        current in ("N/A", "", None) or
                        (current != "N/A" and float(base_score) > float(current))
                    )
                    if needs_update:
                        cve_data["severity"] = str(base_score)

                if vector and not cve_data.get("cvss_vector"):
                    cve_data["cvss_vector"] = vector
                if base_severity and not cve_data.get("cvss_severity"):
                    cve_data["cvss_severity"] = base_severity
                break

        # CWE
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

        # Description fallback
        if not cve_data.get("description"):
            for desc_obj in cve_item.get("descriptions", []):
                if desc_obj.get("lang") == "en":
                    cve_data["description"] = desc_obj.get("value", "")
                    break

    def _enrich_from_cve_org(self, cve_id: str, cve_data: Dict[str, Any]) -> None:
        """Fallback: scrape cve.org for CVSS severity."""
        try:
            url = f"https://www.cve.org/CVERecord?id={cve_id}"
            r = self.session.get(url, timeout=10)
            if r.status_code == 200:
                import re
                cvss_match = re.search(
                    r'CVSS[:\s]+(?:v?3(?:\.\d)?(?:\.\d)?)?\s*[:\s]*([0-9](?:\.\d)?)',
                    r.text, re.IGNORECASE
                )
                if cvss_match:
                    score = cvss_match.group(1)
                    current = cve_data.get("severity", "N/A")
                    if current in ("N/A", "", None) or (current != "N/A" and float(score) > float(current)):
                        cve_data["severity"] = score
                        self.logger.info(f"cve.org fallback set {cve_id} severity to {score}")
        except Exception as e:
            self.logger.debug(f"cve.org fallback failed for {cve_id}: {e}")

    # ── GitHub Advisory ───────────────────────────────────────────────────────

    def _enrich_github_advisory(self, cve_id: str, cve_data: Dict[str, Any]) -> None:
        """Check GitHub Advisory Database for exploit signals."""
        for attempt in range(3):
            try:
                time.sleep(self._nvd_rate_limit)
                r = self.session.get(
                    GITHUB_ADVISORY_URL,
                    params={"cve_id": cve_id, "type": "reviewed"},
                    timeout=10,
                )
                if r.status_code == 403:
                    wait = (attempt + 1) * 5
                    self.logger.warning(f"GitHub Advisory 403, attempt {attempt+1}/3, waiting {wait}s")
                    time.sleep(wait)
                    continue
                if r.status_code == 200:
                    advisories = r.json()
                    if advisories:
                        adv = advisories[0]
                        cve_data["ghsa_id"] = adv.get("ghsa_id", "")
                        for ext in adv.get("extensions", []):
                            if ext.get("type") == "exploit":
                                cve_data["exploit_available"] = ext.get("exploit_available", False)
                                cve_data["exploit_last_patched"] = ext.get("exploit_last_patched")
                    return
                return
            except Exception as e:
                self.logger.debug(f"GitHub advisory error (attempt {attempt+1}/3): {e}")
                time.sleep(2 * (attempt + 1))

    # ── Main enrich ────────────────────────────────────────────────────────────

    def enrich(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full enrichment pipeline with SQLite caching.

        1. Check cache — return if fresh
        2. CISA KEV — always check (small payload, no rate limit concern)
        3. NVD — only fetch if cache miss or stale
        4. GitHub Advisory — only fetch if cache miss
        5. Derive fix_suggestion
        6. Save to cache
        """
        cve_id = cve_data.get("id", "")
        if not cve_id:
            return cve_data

        # Check cache first
        cached = self.get_cached(cve_id)
        if cached:
            self.logger.debug(f"Cache hit for {cve_id}")
            cve_data.update(cached)
            # Always check CISA KEV for freshest KEV flag
            kev = self.get_kev_info(cve_id)
            if kev:
                cve_data["cisa_kev"] = True
                cve_data["cisa_kev_vendor"] = kev.get("vendorProject", "")
                cve_data["cisa_kev_product"] = kev.get("product", "")
                cve_data["cisa_kev_date_added"] = kev.get("dateAdded", "")
                cve_data["short_description"] = kev.get("shortDescription", "")
            if not cve_data.get("fix_suggestion"):
                cve_data["fix_suggestion"] = self._derive_fix_suggestion(cve_data)
            return cve_data

        # Cache miss — fetch from NVD
        nvd = self._nvd_request(cve_id)
        if nvd:
            self._parse_nvd_response(nvd, cve_data)
        else:
            self._enrich_from_cve_org(cve_id, cve_data)

        # GitHub Advisory (only on cache miss)
        self._enrich_github_advisory(cve_id, cve_data)

        # CISA KEV
        kev = self.get_kev_info(cve_id)
        if kev:
            cve_data["cisa_kev"] = True
            cve_data["cisa_kev_vendor"] = kev.get("vendorProject", "")
            cve_data["cisa_kev_product"] = kev.get("product", "")
            cve_data["cisa_kev_date_added"] = kev.get("dateAdded", "")
            cve_data["short_description"] = kev.get("shortDescription", "")

        # Derive fix suggestion
        if not cve_data.get("fix_suggestion"):
            cve_data["fix_suggestion"] = self._derive_fix_suggestion(cve_data)

        # Save to cache
        self.save_enrichment(cve_id, cve_data)
        self.logger.info(f"Enriched {cve_id}: CVSS={cve_data.get('severity')}")

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
        "CWE-416": "Use After Free",
        "CWE-843": "Type Confusion",
        "CWE-88":  "Argument Injection",
    }

    @staticmethod
    def _cwe_human_readable(cwe: str) -> str:
        return CVEAnalyzer.CWE_MAP.get(cwe, cwe)

    def _derive_fix_suggestion(self, cve: Dict[str, Any]) -> str:
        """Generate fix suggestion from enriched data — no LLM needed."""
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

        parts.append("""\
🛠️ 修复建议：
1. 确认受影响的版本范围（见上方 Affected Products）
2. 升级到厂商官方发布的最稳定安全版本
3. 检查官方安全公告获取补丁链接
4. 如无法立即升级，实施临时缓解措施：
   - 网络层：WAF 规则 / IPS 签名 / 零信任策略
   - 主机层：最小化暴露面 / 禁用危险功能 / 输入过滤
5. 修复后使用 NVD / 厂商 PoC 验证修复有效性""")

        return "\n".join(parts)
