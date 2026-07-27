#!/usr/bin/env python3
"""
CVE Monitor — Unified CLI

Modes:
  daily     — 默认模式，获取最近 N 天的所有 CVE（7天）
  weekly    — 周报：获取本周所有 CVE，支持 --keyword 过滤
  poc       — 只获取有 PoC/已知被利用的 CVE（结合 CISA KEV）
  scan      — 扫描特定年份/关键词，默认 CVE-2026
  diff      — 只输出 delta（新增/变化），不保存全量
  github    — 导出 GitHub Security Advisories 格式

Examples:
  # 周一/日常：获取近 7 天全量 CVE
  python scripts/update_cves.py daily --days 7

  # 周三：扫描本年漏洞
  python scripts/update_cves.py scan --year 2026 --keyword "remote code execution"

  # 周五：只获取有 PoC 的 CVE
  python scripts/update_cves.py poc --days 30

  # 手动：指定关键词
  python scripts/update_cves.py daily --keyword "apache log4j" --days 30
"""

import os
import sys
import json
import time
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT_DIR = Path(__file__).parent.parent.absolute()
sys.path.insert(0, str(ROOT_DIR))

from backend.cve_crawler import CVECrawler
from backend.analyzer import CVEAnalyzer


# ── Formatters ────────────────────────────────────────────────────────────────

def format_delta(cves, mode="all") -> str:
    """Format CVEs for GitHub Issue body."""
    if not cves:
        return "✅ 暂无新增 CVE 记录"

    lines = [
        f"## 📋 CVE 情报汇总",
        f"",
        f"_生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_",
        f"",
    ]

    severity_order = ["critical", "high", "medium", "low", "none"]
    by_sev = {s: [] for s in severity_order}

    for cve in cves:
        sev = _severity_level(cve.get("severity", "N/A"))
        by_sev[sev].append(cve)

    for sev in severity_order:
        group = by_sev[sev]
        if not group:
            continue
        label_map = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium",
                     "low": "🟢 Low", "none": "⚪ N/A"}
        lines.append(f"### {label_map.get(sev, sev)} ({len(group)})")
        lines.append("")
        for cve in group:
            lines.append(_format_cve_bullet(cve))
        lines.append("")

    return "\n".join(lines)


def _format_cve_bullet(cve) -> str:
    sev = cve.get("severity", "N/A")
    sev_icon = "🔴" if float(sev or 0) >= 9 else "🟠" if float(sev or 0) >= 7 else "🟡"
    cve_id = cve.get("id", "N/A")
    desc = cve.get("description", "无描述")[:120]
    if len(cve.get("description", "")) > 120:
        desc += "..."

    has_poc = cve.get("cisa_kev") or cve.get("exploit_available")
    poc_tag = " ⚠️ **PoC**" if has_poc else ""

    lines = [
        f"- **{cve_id}** {sev_icon} `CVSS {sev}`{poc_tag}",
        f"  - {desc}",
    ]

    # CWE
    cwe_ids = cve.get("cwe_ids", [])
    if cwe_ids:
        lines.append(f"  - 类型：`{', '.join(cwe_ids)}`")

    # CISA KEV
    if cve.get("cisa_kev"):
        vendor = cve.get("cisa_kev_vendor", "")
        product = cve.get("cisa_kev_product", "")
        lines.append(f"  - ⚠️ **CISA KEV** | {vendor} {product}")

    # Fix
    fix = cve.get("fix_suggestion", "")
    if fix and fix != "无法生成修复建议":
        lines.append(f"  - 📋 修复建议：{fix.split(chr(10))[0][:80]}")

    # Reference
    refs = cve.get("references", [])
    if refs:
        ref_url = refs[0].get("url", "")
        if ref_url:
            lines.append(f"  - 🔗 {ref_url}")

    return "\n".join(lines)


def _severity_level(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "none"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "none"


# ── Mode handlers ─────────────────────────────────────────────────────────────

def run_daily(crawler, analyzer, args):
    """daily: fetch recent CVEs, apply optional keyword filter."""
    days = getattr(args, "days", 7)
    keywords = getattr(args, "keyword", None)
    min_sev = getattr(args, "min_severity", 0.0)

    cves = crawler.fetch_latest_cves(days_back=days)
    cves = _apply_filters(cves, min_sev=min_sev, keywords=keywords)
    cves = _enrich_all(cves, analyzer)

    crawler._save_cves(cves, enrich=False)  # already enriched
    print(f"[daily] Fetched and saved {len(cves)} CVEs (days={days})")
    return cves


def run_weekly(crawler, analyzer, args):
    """weekly: Monday report — this week's CVEs, optionally filtered by keyword."""
    # Get start of current week (Monday = weekday 0)
    today = datetime.now(timezone.utc)
    days_since_monday = today.weekday() + 1  # Mon=1, Sun=7

    keywords = getattr(args, "keyword", None)
    min_sev = getattr(args, "min_severity", 0.0)

    cves = crawler.fetch_latest_cves(days_back=days_since_monday)
    cves = _apply_filters(cves, min_sev=min_sev, keywords=keywords)
    cves = _enrich_all(cves, analyzer)

    body = format_delta(cves)
    print(body)
    crawler._save_cves(cves, enrich=False)
    _append_delta(len(cves))
    return cves


def run_poc(crawler, analyzer, args):
    """poc: Only CVEs with known exploit / PoC (CISA KEV + GitHub Advisory)."""
    days = getattr(args, "days", 30)
    cves = crawler.fetch_latest_cves(days_back=days)
    cves = _enrich_all(cves, analyzer)

    # Filter to only those with exploit signals
    poc_cves = [c for c in cves if c.get("cisa_kev") or c.get("exploit_available")]

    body = format_delta(poc_cves, mode="poc")
    print(body)
    crawler._save_cves(poc_cves, enrich=False)
    _append_delta(len(poc_cves))
    return poc_cves


def run_scan(crawler, analyzer, args):
    """scan: scan by year and/or keyword, no date restriction."""
    year = getattr(args, "year", 2026)
    keywords = getattr(args, "keyword", None)
    min_sev = getattr(args, "min_severity", 0.0)

    # Fetch broader range then filter by year
    cves = crawler.fetch_latest_cves(days_back=365)
    cves = [c for c in cves if str(year) in c.get("id", "")]
    cves = _apply_filters(cves, min_sev=min_sev, keywords=keywords)
    cves = _enrich_all(cves, analyzer)

    body = format_delta(cves)
    print(body)
    crawler._save_cves(cves, enrich=False)
    _append_delta(len(cves))
    return cves


def run_diff(crawler, analyzer, args):
    """diff: only show what changed since last run."""
    delta_file = ROOT_DIR / "data" / "deltaLog.json"
    if delta_file.exists():
        with open(delta_file) as f:
            log = json.load(f)
        last = log[0] if log else {}
        last_fetch = last.get("fetchTime", "")
        print(f"[diff] Last fetch: {last_fetch}")
    else:
        print("[diff] No delta log found")

    days = getattr(args, "days", 1)
    cves = crawler.fetch_latest_cves(days_back=days)
    cves = _enrich_all(cves, analyzer)

    # Print concise diff
    print(f"[diff] {len(cves)} CVEs in last {days} day(s)")
    for cve in cves[:20]:
        sev = cve.get("severity", "?")
        print(f"  {cve['id']} CVSS={sev}")
    if len(cves) > 20:
        print(f"  ... and {len(cves) - 20} more")

    _append_delta(len(cves))
    return cves


# ── Helpers ────────────────────────────────────────────────────────────────────

def _apply_filters(cves, min_sev=0.0, keywords=None, has_poc=None):
    result = []
    for cve in cves:
        sev = float(cve.get("severity", 0) if cve.get("severity") not in ("N/A", "") else 0)
        if sev < min_sev:
            continue
        if has_poc and not (cve.get("cisa_kev") or cve.get("exploit_available")):
            continue
        if keywords:
            q = " ".join(keywords).lower()
            in_desc = q in cve.get("description", "").lower()
            in_id = q in cve.get("id", "").lower()
            if not (in_desc or in_id):
                continue
        result.append(cve)
    return result


def _enrich_all(cves, analyzer):
    """Enrich a list of CVEs, rate-limited."""
    enriched = []
    for cve in cves:
        try:
            enriched.append(analyzer.enrich(cve))
            time.sleep(0.15)  # be nice to public APIs
        except Exception as e:
            print(f"[enrich] Error enriching {cve.get('id')}: {e}")
            enriched.append(cve)
    return enriched


# ── CLI ───────────────────────────────────────────────────────────────────────

MODES = {
    "daily":   ("获取近 N 天全量 CVE（默认）", run_daily),
    "weekly":  ("本周 CVE 摘要（周一报告）", run_weekly),
    "poc":     ("只获取有 PoC / CISA KEV 的 CVE（周五报告）", run_poc),
    "scan":    ("按年份/关键词扫描 CVE", run_scan),
    "diff":    ("增量对比：最近一次与当前差异", run_diff),
}


def main():
    parser = argparse.ArgumentParser(
        description="CVE Monitor — 漏洞情报采集与 enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Modes:\n"
            + "  daily   " + MODES["daily"][0] + "\n"
            + "  weekly  " + MODES["weekly"][0] + "\n"
            + "  poc     " + MODES["poc"][0] + "\n"
            + "  scan    " + MODES["scan"][0] + "\n"
            + "  diff    " + MODES["diff"][0] + "\n"
        )
    )

    parser.add_argument(
        "mode", nargs="?", default="daily",
        choices=list(MODES.keys()),
        help="运行模式"
    )
    parser.add_argument("--days", type=int, default=7,
                        help="获取最近 N 天的 CVE（默认 7）")
    parser.add_argument("--year", type=int, default=2026,
                        help="CVE 年份（scan 模式，默认 2026）")
    parser.add_argument("--keyword", type=str, nargs="+",
                        help="关键词过滤（可多个）")
    parser.add_argument("--min-severity", type=float, default=0.0,
                        help="最低 CVSS 分数（默认 0）")
    parser.add_argument("--has-poc", action="store_true",
                        help="只返回有 PoC 的 CVE")
    parser.add_argument("--dry-run", action="store_true",
                        help="只打印，不保存")
    parser.add_argument("--no-enrich", action="store_true",
                        help="跳过 NVD/CISA enrichment（加速）")

    args = parser.parse_args()

    crawler = CVECrawler()
    analyzer = None if args.no_enrich else CVEAnalyzer()

    handler = MODES.get(args.mode, MODES["daily"])[1]
    cves = handler(crawler, analyzer, args)

    if not args.dry_run and cves:
        # Update delta log
        _append_delta(len(cves))

    print(f"\n✅ Done — mode={args.mode}, fetched={len(cves) if cves else 0}")


def _append_delta(count: int):
    """Append a record to deltaLog.json."""
    log_file = ROOT_DIR / "data" / "deltaLog.json"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "fetchTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "count": count,
    }

    try:
        if log_file.exists():
            with open(log_file) as f:
                log = json.load(f)
        else:
            log = []

        log.insert(0, entry)
        log = log[:30]  # keep last 30

        with open(log_file, "w") as f:
            json.dump(log, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[delta] Failed to update deltaLog: {e}")


if __name__ == "__main__":
    main()
