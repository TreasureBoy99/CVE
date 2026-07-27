# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `backend/analyzer.py` — `CVEAnalyzer` replacing `DeepSeekAnalyzer`:
  - CISA KEV integration (known exploited vulnerabilities flag)
  - NVD API 2.0 with retry/backoff for CVSS 3.1 + CWE enrichment
  - cve.org fallback when NVD rate-limited
  - GitHub Advisory Database for exploit/PoC signals
  - `_derive_fix_suggestion()` generates fix advice from structured data (no LLM needed)
- `scripts/update_cves.py` — complete CLI rewrite with 5 modes:
  - `daily` — fetch recent CVEs
  - `weekly` — Monday report (this week's CVEs)
  - `poc` — Friday report (CVEs with known PoC / CISA KEV only)
  - `scan` — year + keyword scan
  - `diff` — incremental comparison
- `.github/workflows/schedule.yml` — time-based GitHub Actions scheduler:
  - Every 5 min: `daily --no-enrich`
  - Monday 09:00 UTC: `weekly`
  - Wednesday 09:00 UTC: `scan --year 2026`
  - Friday 09:00 UTC: `poc`
  - Manual `workflow_dispatch` with mode/days/keyword inputs
- `.github/workflows/release.yml` — auto-release on data milestone

### Changed
- `backend/cve_crawler.py`:
  - Replace `DeepSeekAnalyzer` import with `CVEAnalyzer`
  - `_save_cves()` now calls `analyzer.enrich()` instead of `generate_fix_suggestion()`
  - Saves dual output: `data/cves.json` (repo data) + `frontend/public/cve_cache.json` (static site)
  - Add `fix_suggestion` default field in `_parse_cve_data()`
- `.github/workflows/deploy-frontend.yml`:
  - Remove redundant `Fix Build Output` step
  - Remove duplicate Deploy step
  - Add `single-commit: true`
  - Add Python setup + crawler step before frontend build
  - Fix `next.config.js` to remove `distDir` (conflicts with export)
- `frontend/next.config.js`:
  - Add `basePath: '/CVE'` and `assetPrefix: '/CVE/'` for GitHub Pages subdirectory
  - Remove `distDir` (conflicts with `output: 'export'`)

### Fixed
- **Tailwind/CSS configs missing** — `tailwind.config.js`, `postcss.config.js`, `styles/globals.css` were not present despite `package.json` declaring tailwindcss as dependency. All class names were no-ops.
- **API route broken** — `output: 'export'` disables API routes; replaced with direct static JSON fetch from `/cve_cache.json`
- **Field name mismatch** — backend saves `fix_suggestion` (snake_case) but frontend typed `fixSuggestion` (camelCase). Fixed frontend interface.
- **N/A severity** — NVD enrichment condition had wrong operator precedence (`and` binding tighter than `or`), causing severity to not update. Added retry/backoff for NVD 403 errors and cve.org fallback.
- **GitHub Pages subdirectory** — `basePath` was missing, causing assets to 404 at `anonymous99-rise.github.io/CVE/`

### Removed
- `backend/deepseek_analyzer.py` — replaced by `backend/analyzer.py`
- `frontend/pages/api/cves.ts` — replaced by direct static JSON fetch
- `.nojekyll` / manual `_next` mv step — deprecated, JamesIves action handles this

---

## [0.1.0] — 2026-07-27

### Added
- Initial project structure
- `backend/cve_crawler.py` — CVEProject delta.json crawler with threading
- `backend/deepseek_analyzer.py` — DeepSeek API for fix suggestions
- `frontend/pages/index.tsx` — basic CVE table display
- `frontend/components/ui/table.tsx` — shadcn/ui table component
- `.github/workflows/update-cves.yml` — every-5-minute CVE update
- `.github/workflows/deploy-frontend.yml` — build + GitHub Pages deploy
- `data/cves.json` — initial CVE dataset
- `data/deltaLog.json` — update history log
